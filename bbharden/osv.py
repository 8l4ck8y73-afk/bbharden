"""Minimal OSV.dev client (stdlib only) for known-vulnerability matching.

Only package *names and versions* are sent to the OSV API — never source code,
file paths, or repository names. The lookup is opt-in (`--osv`) because it
needs network access, and it degrades gracefully: if OSV is unreachable the
scan continues and reports that live CVE matching was skipped.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

from .findings import Severity

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN = "https://api.osv.dev/v1/vulns/{id}"
_TIMEOUT = 15
_BATCH = 100  # OSV accepts large batches; keep requests modest.


class OSVUnavailable(RuntimeError):
    """Raised when the OSV API cannot be reached or returns garbage."""


@dataclass
class Vuln:
    id: str
    summary: str = ""
    aliases: List[str] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    fixed_in: Optional[str] = None

    @property
    def cve(self) -> Optional[str]:
        for a in [self.id, *self.aliases]:
            if a.startswith("CVE-"):
                return a
        return None


# (ecosystem, name, version)
Package = Tuple[str, str, str]


def _post(url: str, payload: dict) -> dict:
    req = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "User-Agent": "bbharden"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise OSVUnavailable(str(exc)) from exc


def _get(url: str) -> dict:
    req = urllib.request.Request(url, headers={"User-Agent": "bbharden"})
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))
    except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
        raise OSVUnavailable(str(exc)) from exc


def severity_from_osv(vuln: dict) -> Severity:
    """Map an OSV record to our Severity.

    Prefers the GitHub-advisory `database_specific.severity` label (present for
    most ecosystems); falls back to a CVSS numeric score if one is present,
    else MEDIUM so an unclassified known-vuln is never silently ignored.
    """
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        mapped = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MODERATE": Severity.MEDIUM,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW,
        }.get(label.upper())
        if mapped:
            return mapped
    for sev in vuln.get("severity") or []:
        score = _cvss_numeric(sev.get("score", ""))
        if score is not None:
            if score >= 9.0:
                return Severity.CRITICAL
            if score >= 7.0:
                return Severity.HIGH
            if score >= 4.0:
                return Severity.MEDIUM
            return Severity.LOW
    return Severity.MEDIUM


def _cvss_numeric(score: str) -> Optional[float]:
    # OSV often carries a CVSS *vector* string, not a number; only a bare number
    # is trusted here (computing a score from a vector is out of scope).
    try:
        return float(score)
    except (TypeError, ValueError):
        return None


def fixed_version(vuln: dict, ecosystem: str, name: str) -> Optional[str]:
    """Return the lowest fixed version for this package, if the record has one."""
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or pkg.get("name", "").lower() != name.lower():
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if "fixed" in ev:
                    return ev["fixed"]
    return None


def parse_vuln(record: dict, ecosystem: str, name: str) -> Vuln:
    return Vuln(
        id=record.get("id", "UNKNOWN"),
        summary=(record.get("summary") or record.get("details") or "").strip()[:200],
        aliases=list(record.get("aliases") or []),
        severity=severity_from_osv(record),
        fixed_in=fixed_version(record, ecosystem, name),
    )


def query(packages: Iterable[Package],
          post=_post, get=_get) -> Dict[Package, List[Vuln]]:
    """Look up known vulnerabilities for exact (ecosystem, name, version) tuples.

    `post`/`get` are injectable so tests can run fully offline.
    Raises OSVUnavailable if the API cannot be reached.
    """
    pkgs = list(dict.fromkeys(packages))  # de-dup, keep order
    results: Dict[Package, List[Vuln]] = {p: [] for p in pkgs}
    cache: Dict[str, dict] = {}

    for start in range(0, len(pkgs), _BATCH):
        chunk = pkgs[start:start + _BATCH]
        body = {"queries": [
            {"package": {"ecosystem": eco, "name": name}, "version": ver}
            for eco, name, ver in chunk
        ]}
        resp = post(OSV_QUERYBATCH, body)
        for pkg, item in zip(chunk, resp.get("results", [])):
            eco, name, _ver = pkg
            for stub in (item or {}).get("vulns", []) or []:
                vid = stub.get("id")
                if not vid:
                    continue
                if vid not in cache:
                    cache[vid] = get(OSV_VULN.format(id=vid))
                results[pkg].append(parse_vuln(cache[vid], eco, name))
    return results
