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

_REQ_PINNED = re.compile(r"^[A-Za-z0-9_.\-]+\s*==\s*\S+")
_REQ_UNPINNED = re.compile(r"^[A-Za-z0-9_.\-]+\s*(>=|<=|~=|>|<|\*|$)")
_REQ_NAME = re.compile(r"^[A-Za-z0-9_.\-]+")


def _scan_requirements(ctx, path) -> Iterator[Finding]:
    name = ctx.rel(path)
    text = ctx.read_text(path)
    if not text:
        return
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        if "==" in line or "@" in line:
            continue
        if _REQ_UNPINNED.match(line):
            yield Finding(
                rule_id="DEP_UNPINNED_PY",
                title="Unpinned Python dependency",
                severity=Severity.LOW,
                file=name, line=i,
                message=f"`{_REQ_NAME.match(line).group(0)}` is not pinned to an "
                        "exact version, so builds are not reproducible and a bad "
                        "upstream release lands automatically.",
                remediation="Pin to an exact version (==) and manage upgrades with a "
                            "lockfile or Dependabot/Renovate.",
                evidence=line[:120], cwe="CWE-1104",
            )


def _scan_package_json(ctx, path) -> Iterator[Finding]:
    name = ctx.rel(path)
    text = ctx.read_text(path)
    if not text:
        return
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return
    for section in ("dependencies", "devDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for dep, spec in deps.items():
            if not isinstance(spec, str):
                continue
            s = spec.strip()
            if s.startswith(("^", "~", "*", ">", "<")) or s in ("latest", "*"):
                yield Finding(
                    rule_id="DEP_UNPINNED_NPM",
                    title="Unpinned npm dependency",
                    severity=Severity.LOW,
                    file=name, line=1,
                    message=f"`{dep}` uses the mutable range `{spec}` in {section}.",
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


_PIN_EXACT = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9_.\-+!]+)")
_NPM_EXACT = re.compile(r"^\d+\.\d+\.\d+([\-+][0-9A-Za-z.\-+]+)?$")


def _collect_packages(ctx):
    """Exact-version packages we can match against OSV.

    Returns {(ecosystem, name, version): (file, line)} using the first location.
    Ranges (>=, ^, ~) are skipped on purpose: OSV needs a concrete version, and
    guessing one would produce wrong CVE claims.
    """
    found = {}
    for p in ctx.glob("**/requirements*.txt"):
        text = ctx.read_text(p) or ""
        for i, raw in enumerate(text.splitlines(), start=1):
            line = raw.split("#", 1)[0].strip()
            m = _PIN_EXACT.match(line)
            if m:
                found.setdefault(("PyPI", m.group(1), m.group(2)), (ctx.rel(p), i))
    for p in ctx.glob("**/package.json"):
        text = ctx.read_text(p)
        try:
            data = json.loads(text) if text else {}
        except ValueError:
            continue
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section) or {}
            if not isinstance(deps, dict):
                continue
            for dep, spec in deps.items():
                if isinstance(spec, str) and _NPM_EXACT.match(spec.strip()):
                    found.setdefault(("npm", dep, spec.strip()), (ctx.rel(p), 1))
    return found


def _scan_osv(ctx) -> Iterator[Finding]:
    from .. import osv as osv_mod  # local import: keeps offline runs dependency-free

    packages = _collect_packages(ctx)
    if not packages:
        return
    lookup = ctx.osv_query or osv_mod.query
    try:
        results = lookup(list(packages))
    except osv_mod.OSVUnavailable as exc:
        ctx.notes.append(
            f"OSV lookup skipped (could not reach api.osv.dev: {exc}). "
            "Known-CVE matching did not run."
        )
        return

    for pkg, vulns in results.items():
        eco, name, version = pkg
        file, line = packages[pkg]
        for v in vulns:
            ident = v.cve or v.id
            fix = (f"Upgrade `{name}` to {v.fixed_in} or later."
                   if v.fixed_in else
                   f"Upgrade `{name}` to a release that fixes {ident}, or remove it.")
            yield Finding(
                rule_id="DEP_KNOWN_VULN",
                title=f"Known vulnerability in {name} {version} ({ident})",
                severity=v.severity,
                file=file, line=line,
                message=(v.summary or f"{name} {version} is affected by {ident}.")
                        + f" [{eco}] {v.id}",
                remediation=fix,
                evidence=f"{name}=={version}",
                cwe="CWE-1395",
            )


def scan(ctx) -> Iterator[Finding]:
    for p in ctx.glob("**/requirements*.txt"):
        yield from _scan_requirements(ctx, p)
    for p in ctx.glob("**/package.json"):
        yield from _scan_package_json(ctx, p)
    if ctx.use_osv:
        yield from _scan_osv(ctx)
