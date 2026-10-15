"""Dependency hygiene checks.

Stdlib-only, so this does NOT query a live advisory database. It flags
structural risks that need no network: unpinned requirements, use of mutable
ranges, and known-dangerous install patterns. For live CVE matching, wire in
`pip-audit` / `osv-scanner` via the optional `--osv` hook (see README).
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


def scan(ctx) -> Iterator[Finding]:
    for p in ctx.glob("**/requirements*.txt"):
        yield from _scan_requirements(ctx, p)
    for p in ctx.glob("**/package.json"):
        yield from _scan_package_json(ctx, p)
