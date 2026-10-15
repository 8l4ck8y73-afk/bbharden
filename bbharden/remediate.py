"""Apply machine-applicable fixes from findings that carry fix_content."""

from __future__ import annotations

from pathlib import Path
from typing import List, Tuple

from .findings import Finding


def applicable(findings: List[Finding]) -> List[Finding]:
    # De-duplicate by fix_path; first finding per path wins.
    seen = set()
    out = []
    for f in findings:
        if not f.has_autofix:
            continue
        key = f.fix_path or f.file
        if key in seen:
            continue
        seen.add(key)
        out.append(f)
    return out


def apply(root: Path, findings: List[Finding], dry_run: bool = False
          ) -> List[Tuple[str, str]]:
    """Write fix_content to disk. Returns list of (path, action)."""
    actions = []
    for f in applicable(findings):
        target = root / (f.fix_path or f.file)
        existed = target.exists()
        action = "would update" if existed else "would create"
        if not dry_run:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(f.fix_content, encoding="utf-8")
            action = "updated" if existed else "created"
        actions.append((str(target.relative_to(root)), action))
    return actions
