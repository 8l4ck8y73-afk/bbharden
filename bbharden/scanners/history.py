"""Opt-in scan of git HISTORY for secrets that were committed and later removed.

Deleting a leaked key from the current tree does not un-leak it: it stays in
every clone. This scanner reads the added lines of past commits and applies the
same rules as the working-tree secrets scanner.

Safety: it runs the system `git` binary read-only against a repository that may
be hostile. Hooks, external diff drivers, textconv, fsmonitor, pagers and
user/system config are all disabled; output is streamed with hard caps on
commits, bytes and wall-clock time. If any cap is hit the user is told that
the result is partial (never presented as a clean bill of health).
"""

from __future__ import annotations

import os
import re
import subprocess
import time
from typing import Dict, Iterator, Optional, Tuple

from ..findings import Finding
from . import secrets

MAX_COMMITS = 10000
MAX_BYTES = 256 * 1024 * 1024
MAX_SECONDS = 300
_MAX_LINE = 4000

_HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_COMMIT = "@@BBH-COMMIT@@"


def _git_env() -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items()
           if k in ("PATH", "HOME", "SYSTEMROOT", "TMPDIR", "LANG")}
    env.update({
        "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0",
        "GIT_PAGER": "cat", "GIT_EXTERNAL_DIFF": "", "LC_ALL": "C",
    })
    return env


def _git_args(root, max_commits: int):
    return [
        "git", "-C", str(root),
        "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull,
        "-c", "core.pager=cat", "-c", "core.quotepath=false",
        "-c", "protocol.ext.allow=never", "-c", "diff.external=",
        "log", "--all", "--no-color", "--no-ext-diff", "--no-textconv",
        "--no-renames", "-U0", "--diff-filter=AM", f"--max-count={max_commits}",
        f"--format={_COMMIT} %H %aI", "-p",
    ]


def _has_git_dir(root) -> bool:
    g = root / ".git"
    return not g.is_symlink() and (g.is_dir() or g.is_file())


def iter_added_lines(root, max_commits=MAX_COMMITS, max_bytes=MAX_BYTES,
                     max_seconds=MAX_SECONDS, notes=None
                     ) -> Iterator[Tuple[str, str, str, int, str]]:
    """Yield (commit, date, path, new_line_number, text) for every added line."""
    notes = notes if notes is not None else []
    proc = subprocess.Popen(_git_args(root, max_commits), stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, env=_git_env(), cwd=str(root))
    start, total = time.monotonic(), 0
    commit = date = ""
    path: Optional[str] = None
    lineno = remaining = 0
    ncommits = 0
    truncated = False
    try:
        for raw in proc.stdout:  # bytes, line by line
            total += len(raw)
            if total > max_bytes or time.monotonic() - start > max_seconds:
                truncated = True
                proc.kill()
                break
            line = raw.decode("utf-8", "replace").rstrip("\n")
            if remaining == 0:
                if line.startswith(_COMMIT):
                    parts = line.split(" ")
                    commit, date = parts[1][:12], parts[2][:10]
                    ncommits += 1
                    path = None
                elif line.startswith("+++ "):
                    p = line[4:].split("\t")[0]
                    path = p[2:] if p.startswith("b/") else None
                else:
                    m = _HUNK.match(line)
                    if m:
                        lineno = int(m.group(1))
                        remaining = int(m.group(2)) if m.group(2) is not None else 1
                continue
            # Inside a hunk: with -U0 every line is "+..." (or "\ No newline").
            if line.startswith("+"):
                remaining -= 1
                if path is not None:
                    yield commit, date, path, lineno, line[1:_MAX_LINE]
                lineno += 1
    finally:
        if proc.poll() is None:
            proc.kill()
        err = proc.stderr.read().decode("utf-8", "replace").strip()
        proc.stdout.close()
        proc.stderr.close()
        rc = proc.wait()
    if truncated:
        notes.append("history scan stopped at its safety limit; results are PARTIAL")
    elif rc != 0:
        raise RuntimeError(f"git log failed ({rc}): {err[:200]}")
    if ncommits >= max_commits:
        notes.append(f"history scan limited to the newest {max_commits} commits; "
                     "older history was NOT scanned")


def scan(ctx) -> Iterator[Finding]:
    if not getattr(ctx, "history", False):
        return
    if not _has_git_dir(ctx.root):
        ctx.notes.append("history scan skipped: not a git repository")
        return
    if (ctx.root / ".git" / "shallow").exists():
        ctx.notes.append("repository is a shallow clone: older history is not "
                         "present and was NOT scanned")
    # Secrets still in the working tree are already reported by the secrets
    # scanner; don't double-report them here.
    current = {(f.file, f.evidence) for f in secrets.scan(ctx)}
    seen: Dict[Tuple[str, str, str], tuple] = {}
    for commit, date, path, lineno, text in iter_added_lines(
            ctx.root, getattr(ctx, "history_max_commits", MAX_COMMITS), notes=ctx.notes):
        if ctx.is_excluded(ctx.root / path) or secrets._is_ignored(
                path, getattr(ctx, "scan_tests", False)):
            continue
        for rule_id, title, sev, ev, _msg in secrets.match_line(text):
            if (path, ev) in current:
                continue
            # git log is newest-first: overwriting keeps the OLDEST introduction.
            seen[(rule_id, path, ev)] = (title, sev, commit, date, lineno)
    for (rule_id, path, ev), (title, sev, commit, date, lineno) in seen.items():
        yield Finding(
            rule_id="SECRET_IN_HISTORY",
            title=f"{title} found in git history",
            severity=sev, file=path, line=lineno,
            message=f"A {title.lower()} was committed in {commit} ({date}) and is no "
                    "longer in the current tree, but remains retrievable from any clone.",
            remediation="ROTATE the credential at the provider now — removing it from "
                        "the latest commit does not revoke it. Then purge it from "
                        "history (`git filter-repo`) and force-push if the repo is shared.",
            evidence=ev, cwe="CWE-798",
        )
