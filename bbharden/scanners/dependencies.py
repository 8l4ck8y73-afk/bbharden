"""Dependency hygiene checks.

By default this is fully offline and flags structural risks: unpinned
requirements, mutable version ranges, and install-time lifecycle scripts.

With `--osv` it additionally matches exact pinned versions against OSV.dev for
known CVEs (only package names and versions are sent). Version ranges are never
guessed at — they are reported as unpinned instead.
"""

from __future__ import annotations

import json
import re
from typing import Iterator

from ..findings import Finding, Severity

# name[extras] <spec> [; marker]
_REQ_LINE = re.compile(
    r"^(?P<name>[A-Za-z0-9][A-Za-z0-9_.\-]*)\s*(?:\[[^\]]*\])?\s*(?P<spec>[^;]*?)\s*(?:;.*)?$")
# A single exact pin: `==1.2.3` / `===1.2.3`. `==1.*` (wildcard) is NOT exact.
_EXACT_SPEC = re.compile(r"^===?\s*(?P<ver>[A-Za-z0-9_.+!\-]+)$")
_NPM_EXACT = re.compile(r"^=?v?\d+\.\d+\.\d+([\-+][0-9A-Za-z.\-+]+)?$")
# Specs that are not registry versions at all (handled elsewhere / intentionally).
_NPM_NON_REGISTRY = re.compile(
    r"^(file:|link:|git\+|git:|github:|https?:|workspace:|npm:|portal:|patch:)"
    r"|^[\w.\-]+/[\w.\-]+(#.*)?$")


def _pep503(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _parse_requirement(raw: str):
    """Return (name, exact_version_or_None) for one requirements.txt line.

    None for blank/comment/option lines and for direct URL references.
    """
    line = raw.split(" #", 1)[0].split("\t#", 1)[0].strip().rstrip("\\").strip()
    if not line or line.startswith(("#", "-")) or "@" in line or "://" in line:
        return None
    m = _REQ_LINE.match(line)
    if not m:
        return None
    spec = m.group("spec").strip()
    em = _EXACT_SPEC.match(spec)
    return m.group("name"), (em.group("ver") if em else None)


def _requirement_files(ctx):
    seen, out = set(), []
    for pat in ("**/requirements*.txt", "**/requirements/*.txt"):
        for p in ctx.glob(pat):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


def _scan_requirements(ctx, path) -> Iterator[Finding]:
    name = ctx.rel(path)
    text = ctx.read_text(path)
    if not text:
        return
    for i, raw in enumerate(text.splitlines(), start=1):
        parsed = _parse_requirement(raw)
        if not parsed:
            continue
        pkg, exact = parsed
        if exact is None:
            yield Finding(
                rule_id="DEP_UNPINNED_PY",
                title="Unpinned Python dependency",
                severity=Severity.LOW,
                file=name, line=i,
                message=f"`{pkg}` is not pinned to an exact version, so builds are "
                        "not reproducible and a bad upstream release lands "
                        "automatically.",
                remediation="Pin to an exact version (==) and manage upgrades with a "
                            "lockfile or Dependabot/Renovate.",
                evidence=raw.strip()[:120], cwe="CWE-1104",
            )


def _load_json(ctx, path):
    text = ctx.read_text(path)
    if not text:
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError, RecursionError):
        return None
    return data if isinstance(data, dict) else None


_NPM_LOCKFILES = ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
                  "pnpm-lock.yaml", "bun.lockb", "bun.lock")


def _has_npm_lockfile(path) -> bool:
    return any((path.parent / n).is_file() for n in _NPM_LOCKFILES)


def _npm_is_unpinned(spec: str) -> bool:
    s = spec.strip()
    if not s or _NPM_NON_REGISTRY.match(s):
        return False
    return not _NPM_EXACT.match(s)


def _scan_package_json(ctx, path) -> Iterator[Finding]:
    name = ctx.rel(path)
    data = _load_json(ctx, path)
    if data is None:
        return
    locked = _has_npm_lockfile(path)
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for dep, spec in deps.items():
            if isinstance(spec, str) and _npm_is_unpinned(spec):
                yield Finding(
                    rule_id="DEP_UNPINNED_NPM",
                    title=("npm range (resolved by the committed lockfile)" if locked
                           else "Unpinned npm dependency"),
                    # With a lockfile the range is only a declaration of intent: the
                    # installed version is fixed. Report it, but as information.
                    severity=Severity.INFO if locked else Severity.LOW,
                    file=name, line=1,
                    message=f"`{dep}` uses the range `{spec}` in {section}"
                            + (" (a committed lockfile fixes the installed version)."
                               if locked else "."),
                    remediation="Pin exact versions and commit a lockfile "
                                "(package-lock.json / pnpm-lock.yaml); enable "
                                "Dependabot for controlled upgrades.",
                    evidence=f"{dep}: {spec}", cwe="CWE-1104",
                )
    # Lifecycle scripts that run on install are a supply-chain foothold.
    scripts = data.get("scripts") or {}
    if isinstance(scripts, dict):
        for hook in ("preinstall", "postinstall", "install"):
            if hook in scripts:
                yield Finding(
                    rule_id="DEP_NPM_INSTALL_SCRIPT",
                    title=f"npm '{hook}' lifecycle script present",
                    severity=Severity.INFO,
                    file=name, line=1,
                    message=f"`{hook}` runs automatically on `npm install`; review it "
                            "and consider `--ignore-scripts` in CI.",
                    remediation="Audit the script; in CI, install with "
                                "`npm ci --ignore-scripts` where feasible.",
                    evidence=f"{hook}: {scripts[hook]}"[:120],
                )


def _collect_packages(ctx):
    """Exact-version packages we can match against OSV.

    Returns {(ecosystem, name, version): (file, line)} using the first location.
    Ranges (>=, ^, ~, ==1.*) are skipped on purpose: OSV needs a concrete
    version, and guessing one would produce wrong CVE claims.

    Sources: requirements*.txt and package.json (direct pins), plus lockfiles —
    package-lock.json, Pipfile.lock, poetry.lock — which expose the TRANSITIVE
    dependencies that actually ship.
    """
    found = {}
    for p in _requirement_files(ctx):
        text = ctx.read_text(p) or ""
        for i, raw in enumerate(text.splitlines(), start=1):
            parsed = _parse_requirement(raw)
            if parsed and parsed[1] and not parsed[1].endswith("."):
                found.setdefault(("PyPI", _pep503(parsed[0]), parsed[1]),
                                 (ctx.rel(p), i))

    for p in ctx.glob("**/package.json"):
        data = _load_json(ctx, p)
        if not data:
            continue
        for section in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for dep, spec in deps.items():
                if isinstance(spec, str) and _NPM_EXACT.match(spec.strip()):
                    found.setdefault(("npm", dep, spec.strip().lstrip("=v")),
                                     (ctx.rel(p), 1))

    for p in ctx.glob("**/package-lock.json"):
        data = _load_json(ctx, p)
        pk = (data or {}).get("packages")
        if isinstance(pk, dict):                       # lockfileVersion 2/3
            for key, meta in pk.items():
                if not key or not isinstance(meta, dict) or meta.get("link"):
                    continue
                name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
                ver = meta.get("version")
                if isinstance(ver, str) and _NPM_EXACT.match(ver):
                    found.setdefault(("npm", name, ver), (ctx.rel(p), 1))
        elif isinstance((data or {}).get("dependencies"), dict):   # v1
            stack = [(data["dependencies"])]
            while stack:
                for name, meta in stack.pop().items():
                    if not isinstance(meta, dict):
                        continue
                    ver = meta.get("version")
                    if isinstance(ver, str) and _NPM_EXACT.match(ver):
                        found.setdefault(("npm", name, ver), (ctx.rel(p), 1))
                    if isinstance(meta.get("dependencies"), dict):
                        stack.append(meta["dependencies"])

    for p in ctx.glob("**/Pipfile.lock"):
        data = _load_json(ctx, p) or {}
        for section in ("default", "develop"):
            sec = data.get(section)
            if not isinstance(sec, dict):
                continue
            for name, meta in sec.items():
                ver = meta.get("version", "") if isinstance(meta, dict) else ""
                if isinstance(ver, str) and ver.startswith("=="):
                    found.setdefault(("PyPI", _pep503(name), ver[2:]),
                                     (ctx.rel(p), 1))

    for p in ctx.glob("**/poetry.lock"):
        text = ctx.read_text(p) or ""
        for block in text.split("[[package]]")[1:]:
            nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
            vr = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
            if nm and vr:
                found.setdefault(("PyPI", _pep503(nm.group(1)), vr.group(1)),
                                 (ctx.rel(p), 1))
    _collect_other_ecosystems(ctx, found)
    return found


# ---- Go, Rust, Maven, Ruby, PHP: exact versions only (text parsing, no execution)
_GO_REQ = re.compile(r"^\s*(?:require\s+)?(?P<mod>[A-Za-z0-9._~/\-]+\.[A-Za-z0-9._~/\-]+)"
                     r"\s+v(?P<ver>\d[0-9A-Za-z.+\-]*)\s*(?://.*)?$")


def _mvn_blocks(text: str):
    """<dependency>…</dependency> bodies in linear time (a lazy regex is
    quadratic on an unterminated-tag bomb)."""
    pos = 0
    while True:
        a = text.find("<dependency>", pos)
        if a < 0:
            return
        b = text.find("</dependency>", a)
        if b < 0:
            return
        yield text[a + 12:b]
        pos = b + 13


_MVN_TAG = lambda tag: re.compile(rf"<{tag}>\s*([^<>\s]+)\s*</{tag}>")  # noqa: E731
_MVN_G, _MVN_A, _MVN_V = _MVN_TAG("groupId"), _MVN_TAG("artifactId"), _MVN_TAG("version")
_GEM_SPEC = re.compile(r"^    (?P<n>[A-Za-z0-9_.\-]+) \((?P<v>\d[0-9A-Za-z.\-]*)\)\s*$")


def _collect_other_ecosystems(ctx, found) -> None:
    for p in ctx.glob("**/go.mod"):
        in_block = False
        for i, raw in enumerate((ctx.read_text(p) or "").splitlines(), start=1):
            s = raw.strip()
            if s.startswith("require ("):
                in_block = True
                continue
            if in_block and s == ")":
                in_block = False
                continue
            if not (in_block or s.startswith("require ")):
                continue
            m = _GO_REQ.match(raw)
            if m:
                found.setdefault(("Go", m.group("mod"), m.group("ver")), (ctx.rel(p), i))

    for p in ctx.glob("**/Cargo.lock"):
        for block in (ctx.read_text(p) or "").split("[[package]]")[1:]:
            nm = re.search(r'^name\s*=\s*"([^"]+)"', block, re.M)
            vr = re.search(r'^version\s*=\s*"([^"]+)"', block, re.M)
            src = re.search(r'^source\s*=\s*"([^"]+)"', block, re.M)
            # Only registry crates; path/git dependencies have no registry identity.
            if nm and vr and src and src.group(1).startswith("registry+"):
                found.setdefault(("crates.io", nm.group(1), vr.group(1)), (ctx.rel(p), 1))

    for p in ctx.glob("**/pom.xml"):
        text = re.sub(r"<!--.*?-->", "", ctx.read_text(p) or "", flags=re.S)
        for d in _mvn_blocks(text):
            g, a, v = _MVN_G.search(d), _MVN_A.search(d), _MVN_V.search(d)
            # Property references (${x}) and ranges ([1,2)) are not concrete versions.
            if g and a and v and re.fullmatch(r"\d[0-9A-Za-z._\-]*", v.group(1)):
                found.setdefault(("Maven", f"{g.group(1)}:{a.group(1)}", v.group(1)),
                                 (ctx.rel(p), 1))

    for p in ctx.glob("**/Gemfile.lock"):
        specs = False
        for i, raw in enumerate((ctx.read_text(p) or "").splitlines(), start=1):
            if raw.strip() == "specs:":
                specs = True
                continue
            if specs and raw and not raw.startswith(" "):
                specs = False
            m = _GEM_SPEC.match(raw) if specs else None
            if m:
                found.setdefault(("RubyGems", m.group("n"), m.group("v")), (ctx.rel(p), i))

    for p in ctx.glob("**/composer.lock"):
        data = _load_json(ctx, p) or {}
        for section in ("packages", "packages-dev"):
            for pkg in data.get(section) or []:
                if not isinstance(pkg, dict):
                    continue
                n, v = pkg.get("name"), pkg.get("version")
                if isinstance(n, str) and isinstance(v, str):
                    v = v[1:] if v.startswith("v") else v
                    if re.fullmatch(r"\d[0-9A-Za-z.\-+]*", v):
                        found.setdefault(("Packagist", n, v), (ctx.rel(p), 1))


def _scan_osv(ctx) -> Iterator[Finding]:
    from .. import osv as osv_mod  # local import: keeps offline runs dependency-free

    packages = _collect_packages(ctx)
    if not packages:
        return
    lookup = ctx.osv_query or osv_mod.query
    try:
        results = lookup(list(packages))
    except osv_mod.OSVUnavailable as exc:
        ctx.osv_failed = True
        ctx.notes.append(
            f"OSV lookup skipped (could not reach api.osv.dev: {exc}). "
            "Known-CVE matching did not run."
        )
        return

    for pkg, vulns in results.items():
        if not vulns:
            continue
        eco, name, version = pkg
        file, line = packages[pkg]
        if len(vulns) == 1 or getattr(ctx, "osv_detail", False):
            yield from _per_advisory(eco, name, version, file, line, vulns)
        else:
            yield _grouped(eco, name, version, file, line, vulns)


def _best_fix(vulns):
    from .. import osv as osv_mod
    keyed = [(osv_mod._vkey(v.fixed_in), v.fixed_in) for v in vulns
             if v.fixed_in and osv_mod._vkey(v.fixed_in) is not None]
    return max(keyed)[1] if keyed else None


def _per_advisory(eco, name, version, file, line, vulns):
    best = _best_fix(vulns)
    n_fixed = sum(1 for v in vulns if v.fixed_in)
    for v in vulns:
        ident = v.cve or v.id
        fix = (f"Upgrade `{name}` to {v.fixed_in} or later."
               if v.fixed_in else
               f"Upgrade `{name}` to a release that fixes {ident}, or remove it.")
        if best and len(vulns) > 1:
            fix += (f" Upgrading to {best} or later resolves all {n_fixed} "
                    f"advisories for this package that list a fix.")
        yield Finding(
            rule_id="DEP_KNOWN_VULN",
            title=f"Known vulnerability in {name} {version} ({ident})",
            severity=v.severity, file=file, line=line,
            message=(v.summary or f"{name} {version} is affected by {ident}.")
                    + f" [{eco}] {v.id}",
            remediation=fix, evidence=f"{name}=={version}", cwe="CWE-1395",
        )


def _grouped(eco, name, version, file, line, vulns):
    """One finding per vulnerable package: what a reader acts on is the upgrade."""
    order = sorted(vulns, key=lambda v: (-v.severity.rank, v.cve or v.id))
    counts = {}
    for v in order:
        counts[v.severity.value] = counts.get(v.severity.value, 0) + 1
    breakdown = ", ".join(f"{n} {s}" for s, n in counts.items())
    best = _best_fix(vulns)
    unfixed = sum(1 for v in vulns if not v.fixed_in)
    top = "; ".join(f"{v.cve or v.id} ({v.severity.value})" for v in order[:8])
    more = f"; +{len(order) - 8} more" if len(order) > 8 else ""
    if best:
        fix = f"Upgrade `{name}` to {best} or later: that resolves every advisory that lists a fix."
        if unfixed:
            fix += f" {unfixed} advisory(ies) list no fix yet — review them individually."
    else:
        fix = f"No fixed release is listed; review the advisories and consider replacing `{name}`."
    return Finding(
        rule_id="DEP_KNOWN_VULN",
        title=f"{name} {version}: {len(vulns)} known vulnerabilities ({breakdown})",
        severity=order[0].severity, file=file, line=line,
        message=f"[{eco}] Most severe: {top}{more}. Use --osv-detail for one finding per advisory.",
        remediation=fix, evidence=f"{name}=={version}", cwe="CWE-1395",
        details=[{"id": v.id, "cve": v.cve, "severity": v.severity.value,
                  "summary": v.summary, "fixed_in": v.fixed_in,
                  "url": f"https://osv.dev/vulnerability/{v.id}"} for v in order],
    )


def scan(ctx) -> Iterator[Finding]:
    for p in _requirement_files(ctx):
        yield from _scan_requirements(ctx, p)
    for p in ctx.glob("**/package.json"):
        yield from _scan_package_json(ctx, p)
    if ctx.use_osv:
        yield from _scan_osv(ctx)
