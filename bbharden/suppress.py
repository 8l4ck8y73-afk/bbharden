"""Suppressions: inline `bbharden:ignore` comments and a baseline file.

Both exist so a team can adopt the scanner on an existing codebase without
drowning in day-one noise, while still failing the build on anything NEW.

Inline (works inside any comment style: `#`, `//`, `<!-- -->`, `--`):

    password = "hunter2-prod"   # bbharden:ignore SECRET_GENERIC_ASSIGN
    # bbharden:ignore-next-line DOCKER_RUNS_AS_ROOT
    FROM python:3.12

No rule ids after the marker means "ignore every rule on that line".

Baseline: `scan --write-baseline FILE` records the findings that exist today;
`--baseline FILE` then hides exactly those. Fingerprints exclude the line
number, so unrelated edits above a finding don't resurrect it.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from collections import Counter
from typing import Dict, Iterable, List, Tuple

from .findings import Finding

BASELINE_VERSION = 1
_MARK = re.compile(r"bbharden:ignore(-next-line)?((?:[ \t]+[A-Z][A-Z0-9_]+)*)")


def fingerprint(f: Finding) -> str:
    """Stable, line-independent identity of a finding."""
    raw = "\x1f".join([f.rule_id, f.file, (f.evidence or "").strip()])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]


def load_baseline(path: str) -> Counter:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"error: baseline file not found: {path}")
    except (OSError, ValueError) as exc:
        raise SystemExit(f"error: unreadable baseline {path}: {exc}")
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise SystemExit(f"error: {path} is not a v{BASELINE_VERSION} bbharden baseline")
    fps = data.get("fingerprints") or []
    if not isinstance(fps, list) or not all(isinstance(x, str) for x in fps):
        raise SystemExit(f"error: {path} has a malformed fingerprints list")
    # A Counter, not a set: if the same secret is baselined once and a *second*
    # copy later appears in the same file, the second copy is still new.
    return Counter(fps)


def write_baseline(path: str, findings: Iterable[Finding]) -> int:
    fps = sorted(fingerprint(f) for f in findings)
    Path(path).write_text(
        json.dumps({"version": BASELINE_VERSION, "fingerprints": fps}, indent=2) + "\n",
        encoding="utf-8",
    )
    return len(fps)


def _inline_ignored(lines: List[str], lineno: int, rule_id: str) -> bool:
    """True if the finding's line (or the line above, via -next-line) opts out."""
    def hits(text: str, want_next: bool) -> bool:
        for m in _MARK.finditer(text):
            if bool(m.group(1)) != want_next:
                continue
            rules = m.group(2).split()
            if not rules or rule_id in rules:
                return True
        return False

    idx = lineno - 1
    if 0 <= idx < len(lines) and hits(lines[idx], False):
        return True
    if 1 <= idx <= len(lines) and hits(lines[idx - 1], True):
        return True
    return False


def apply(ctx, findings: List[Finding], baseline: Counter | None = None
          ) -> Tuple[List[Finding], Dict[str, int]]:
    """Drop suppressed findings. Returns (kept, {"inline": n, "baseline": n})."""
    kept: List[Finding] = []
    counts = {"inline": 0, "baseline": 0}
    cache: Dict[str, List[str]] = {}
    remaining = Counter(baseline) if baseline else Counter()
    for f in findings:
        fp = fingerprint(f)
        if remaining[fp] > 0:
            remaining[fp] -= 1
            counts["baseline"] += 1
            continue
        if f.file not in cache:
            text = ctx.read_text(ctx.root / f.file)
            cache[f.file] = text.splitlines() if text else []
        if _inline_ignored(cache[f.file], f.line, f.rule_id):
            counts["inline"] += 1
            continue
        kept.append(f)
    return kept, counts
