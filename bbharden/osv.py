"""Minimal OSV.dev client (stdlib only) for known-vulnerability matching.

Only package *names and versions* are sent to the OSV API — never source code,
file paths, or repository names. The lookup is opt-in (`--osv`) because it
needs network access, and it degrades gracefully: if OSV is unreachable the
scan continues and reports that live CVE matching was skipped.
"""

from __future__ import annotations

import json
import re
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


_CVSS3_W = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _roundup(x: float) -> float:
    i = int(round(x * 100000))
    return i / 100000.0 if i % 10000 == 0 else (i // 10000 + 1) / 10.0


def cvss3_score(vector: str) -> Optional[float]:
    """CVSS v3.x base score from a vector string, or None if not parseable."""
    if not isinstance(vector, str) or not vector.startswith("CVSS:3"):
        return None
    try:
        m = dict(part.split(":", 1) for part in vector.split("/")[1:])
        scope_changed = m["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if scope_changed else 0.62,
              "H": 0.5 if scope_changed else 0.27}[m["PR"]]
        iss = 1 - ((1 - _CVSS3_W["CIA"][m["C"]]) * (1 - _CVSS3_W["CIA"][m["I"]])
                   * (1 - _CVSS3_W["CIA"][m["A"]]))
        impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
                  if scope_changed else 6.42 * iss)
        expl = 8.22 * _CVSS3_W["AV"][m["AV"]] * _CVSS3_W["AC"][m["AC"]] * pr \
            * _CVSS3_W["UI"][m["UI"]]
        if impact <= 0:
            return 0.0
        raw = min(1.08 * (impact + expl), 10) if scope_changed else min(impact + expl, 10)
        return _roundup(raw)
    except (KeyError, ValueError):
        return None


def _cvss_numeric(score: str) -> Optional[float]:
    """A bare number, or a CVSS v3 vector evaluated to its base score."""
    try:
        return float(score)
    except (TypeError, ValueError):
        return cvss3_score(score)


def _vkey(v: str):
    """Best-effort comparable key for dotted numeric versions; None otherwise."""
    parts = v.split("+", 1)[0].split("-", 1)[0].split(".")
    try:
        return tuple(int(p) for p in parts)
    except ValueError:
        return None


def fixed_version(vuln: dict, ecosystem: str, name: str,
                  current: Optional[str] = None) -> Optional[str]:
    """Lowest fixed version for this package that is newer than `current`.

    A record often lists several fixes (one per maintained branch, e.g. 1.2.5
    and 2.0.3). Recommending 1.2.5 to someone on 2.0.1 would be a downgrade, so
    when `current` is known and comparable only fixes above it are considered.
    """
    fixes = []
    for aff in vuln.get("affected") or []:
        pkg = aff.get("package") or {}
        if pkg.get("ecosystem") != ecosystem or \
                _norm(pkg.get("name", ""), ecosystem) != _norm(name, ecosystem):
            continue
        for rng in aff.get("ranges") or []:
            for ev in rng.get("events") or []:
                if isinstance(ev.get("fixed"), str):
                    fixes.append(ev["fixed"])
    if not fixes:
        return None
    cur = _vkey(current) if current else None
    if cur is not None:
        newer = [f for f in fixes if _vkey(f) is not None and _vkey(f) > cur]
        if newer:
            return min(newer, key=_vkey)
        return None          # every listed fix is not above us: don't guess
    keyed = [f for f in fixes if _vkey(f) is not None]
    return min(keyed, key=_vkey) if keyed else fixes[0]


def _norm(name: str, ecosystem: str) -> str:
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    return name.lower()


def parse_vuln(record: dict, ecosystem: str, name: str,
               current: Optional[str] = None) -> Vuln:
    return Vuln(
        id=record.get("id", "UNKNOWN"),
        summary=(record.get("summary") or record.get("details") or "").strip()[:200],
        aliases=list(record.get("aliases") or []),
        severity=severity_from_osv(record),
        fixed_in=fixed_version(record, ecosystem, name, current),
    )


def query(packages: Iterable[Package],
          post=_post, get=_get) -> Dict[Package, List[Vuln]]:
    """Look up known vulnerabilities for exact (ecosystem, name, version) tuples.

    `post`/`get` are injectable so tests can run fully offline.
    Raises OSVUnavailable if the API cannot be reached or answers inconsistently
    (a truncated reply must never be read as "no vulnerabilities").
    """
    pkgs = list(dict.fromkeys(packages))  # de-dup, keep order
    results: Dict[Package, List[Vuln]] = {p: [] for p in pkgs}
    cache: Dict[str, dict] = {}

    def record(vid: str) -> dict:
        if vid not in cache:
            try:
                cache[vid] = get(OSV_VULN.format(id=vid))
            except OSVUnavailable:
                # One unreachable advisory must not hide the others: keep the
                # match (the vulnerability exists) with the details we lack.
                cache[vid] = {"id": vid, "summary": "(details unavailable)"}
        return cache[vid]

    for start in range(0, len(pkgs), _BATCH):
        chunk = pkgs[start:start + _BATCH]
        pending = {i: None for i in range(len(chunk))}   # index -> page_token
        while pending:
            idxs = list(pending)
            body = {"queries": []}
            for i in idxs:
                eco, name, ver = chunk[i]
                q = {"package": {"ecosystem": eco, "name": name}, "version": ver}
                if pending[i]:
                    q["page_token"] = pending[i]
                body["queries"].append(q)
            resp = post(OSV_QUERYBATCH, body)
            items = resp.get("results") if isinstance(resp, dict) else None
            if not isinstance(items, list) or len(items) != len(idxs):
                raise OSVUnavailable("OSV returned a malformed or truncated reply")
            nxt = {}
            for i, item in zip(idxs, items):
                eco, name, ver = chunk[i]
                item = item or {}
                for stub in item.get("vulns") or []:
                    vid = stub.get("id") if isinstance(stub, dict) else None
                    if not vid:
                        continue
                    rec = record(vid)
                    if rec.get("withdrawn"):
                        continue
                    results[chunk[i]].append(parse_vuln(rec, eco, name, ver))
                if item.get("next_page_token"):
                    nxt[i] = item["next_page_token"]
            pending = nxt
    return results
