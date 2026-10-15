"""Software Bill of Materials in CycloneDX 1.5 (JSON).

Components come from exact-version sources only: requirements*.txt pins,
package.json pins, and lockfiles (package-lock.json, Pipfile.lock, poetry.lock),
which carry the transitive dependencies that actually ship. Version *ranges* are
never guessed at, so a repository without lockfiles yields an honest but partial
SBOM — the document says so in `metadata.properties`.

Output is reproducible: the serial number is derived from the content, and the
timestamp honours SOURCE_DATE_EPOCH.
"""

from __future__ import annotations

import datetime as _dt
import json
import os
import uuid
from typing import Dict, List, Optional
from urllib.parse import quote

from . import __version__
from .scanners.dependencies import _collect_packages

_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium",
             "low": "low", "info": "info"}


def purl(ecosystem: str, name: str, version: str) -> str:
    """Package URL (https://github.com/package-url/purl-spec)."""
    v = quote(version, safe="")
    if ecosystem == "PyPI":
        return f"pkg:pypi/{quote(name.lower().replace('_', '-'), safe='')}@{v}"
    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:
            scope, pkg = name.split("/", 1)
            return f"pkg:npm/{quote(scope, safe='')}/{quote(pkg, safe='')}@{v}"
        return f"pkg:npm/{quote(name, safe='')}@{v}"
    return f"pkg:generic/{quote(name, safe='')}@{v}"


def _timestamp() -> str:
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    try:
        when = _dt.datetime.fromtimestamp(int(epoch), _dt.timezone.utc) if epoch \
            else _dt.datetime.now(_dt.timezone.utc)
    except (ValueError, OverflowError, OSError):
        when = _dt.datetime.now(_dt.timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%SZ")


def build(ctx, vulns: Optional[Dict[tuple, list]] = None, name: Optional[str] = None) -> dict:
    """CycloneDX document for the repository in `ctx`.

    `vulns` is the result of `osv.query` ({(eco, name, version): [Vuln]}), if any.
    """
    root_name = name or ctx.root.name or "repository"
    packages = _collect_packages(ctx)

    components: List[dict] = []
    for (eco, pname, ver), (file, _line) in sorted(packages.items()):
        ref = purl(eco, pname, ver)
        components.append({
            "type": "library",
            "bom-ref": ref,
            "name": pname,
            "version": ver,
            "purl": ref,
            "properties": [
                {"name": "bbharden:ecosystem", "value": eco},
                {"name": "bbharden:found-in", "value": file},
            ],
        })
    # De-duplicate (two ecosystems/files can yield the same purl).
    uniq = {c["bom-ref"]: c for c in components}
    components = [uniq[k] for k in sorted(uniq)]

    root_ref = f"root:{root_name}"
    doc: dict = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(uuid.uuid5(
            uuid.NAMESPACE_URL,
            "bbharden:" + root_name + ":" + ",".join(c["bom-ref"] for c in components))),
        "version": 1,
        "metadata": {
            "timestamp": _timestamp(),
            "tools": {"components": [{
                "type": "application", "name": "bbharden", "version": __version__,
                "group": "BlackByte",
            }]},
            "component": {"type": "application", "bom-ref": root_ref, "name": root_name},
            "properties": [{
                "name": "bbharden:completeness",
                "value": "exact pins and lockfiles only; version ranges without a "
                         "lockfile are not listed",
            }],
        },
        "components": components,
        "dependencies": [{"ref": root_ref, "dependsOn": [c["bom-ref"] for c in components]}],
    }

    if vulns is not None:
        entries = []
        for (eco, pname, ver), found in sorted(vulns.items()):
            ref = purl(eco, pname, ver)
            if ref not in uniq:
                continue
            for v in found:
                entry = {
                    "id": v.cve or v.id,
                    "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{v.id}"},
                    "ratings": [{"source": {"name": "OSV"},
                                 "severity": _SEVERITY.get(v.severity.value, "unknown")}],
                    "affects": [{"ref": ref}],
                }
                if v.summary:
                    entry["description"] = v.summary
                if v.fixed_in:
                    entry["recommendation"] = f"Upgrade to {v.fixed_in} or later."
                if v.cve and v.cve != v.id:
                    entry["references"] = [{"id": v.id, "source": {"name": "OSV"}}]
                entries.append(entry)
        doc["vulnerabilities"] = entries
    return doc


def render(doc: dict) -> str:
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"
