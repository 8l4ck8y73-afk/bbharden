"""Apply machine-applicable fixes from findings that carry fix_content.

Writes are defensive because `fix` may run on a repository you do not control:
  * the target must stay inside the repo root (no `..`, no absolute paths);
  * neither the file nor any parent directory may be a symlink;
  * content is written to a temp file and atomically renamed, so a crash can
    never leave a half-written SECURITY.md or workflow file.
"""

from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import List, Optional, Tuple

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


def unsafe_reason(root: Path, rel: str) -> Optional[str]:
    """Why writing `rel` under `root` would be unsafe, or None if it is fine."""
    root = Path(root).resolve()
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts or not p.parts:
        return "path escapes the repository"
    cur = root
    for part in p.parts:
        cur = cur / part
        if cur.is_symlink():
            return f"{cur.relative_to(root).as_posix()} is a symlink"
        if not cur.exists():
            break
    try:
        cur.resolve().relative_to(root)
    except ValueError:
        return "path resolves outside the repository"
    return None


def safe_write(root: Path, rel: str, content: str) -> str:
    """Atomically write `content` to root/rel. Returns 'created' or 'updated'.

    Newlines are written exactly as given (no translation), so a CRLF file stays
    CRLF. Raises OSError if the path is unsafe.
    """
    why = unsafe_reason(root, rel)
    if why:
        raise OSError(why)
    target = Path(root).resolve() / rel
    existed = target.exists()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".bbharden-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
            fh.write(content)
        if existed:
            shutil.copymode(target, tmp)
        else:
            os.chmod(tmp, 0o644)
        os.replace(tmp, target)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return "updated" if existed else "created"


def apply(root: Path, findings: List[Finding], dry_run: bool = False
          ) -> List[Tuple[str, str]]:
    """Write fix_content to disk. Returns a list of (path, action).

    Actions starting with "skipped" mean the fix was refused for safety and
    nothing was written.
    """
    root = Path(root).resolve()
    actions = []
    for f in applicable(findings):
        rel = f.fix_path or f.file
        why = unsafe_reason(root, rel)
        if why:
            actions.append((rel, f"skipped ({why})"))
            continue
        if dry_run:
            actions.append((rel, "would update" if (root / rel).exists()
                            else "would create"))
            continue
        try:
            actions.append((rel, safe_write(root, rel, f.fix_content)))
        except OSError as exc:
            actions.append((rel, f"skipped ({exc})"))
    return actions
