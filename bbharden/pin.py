"""Pin GitHub Actions to immutable commit SHAs.

Most scanners *report* `uses: owner/action@v4`. This one rewrites it:

    uses: actions/checkout@v4
 -> uses: actions/checkout@<40-char-sha>  # v4

Why: a tag is a movable pointer. If an action's repo is compromised and the tag
is re-pointed, every workflow that references the tag runs the attacker's code
with your GITHUB_TOKEN. A full commit SHA cannot be re-pointed.

The SHA is resolved with `git ls-remote` against the action's PUBLIC repo — it
is read-only, needs no token, and is never guessed. If a ref can't be resolved
the line is left untouched and reported; a wrong SHA would break your CI.
"""

from __future__ import annotations

import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple

_SHA = re.compile(r"^[0-9a-f]{40}$")
# `uses: owner/repo[/subpath]@ref  [# comment]`
_USES = re.compile(
    r"^(?P<prefix>\s*-?\s*uses:\s*)(?P<q>[\"']?)"
    r"(?P<action>[A-Za-z0-9_.\-]+/[A-Za-z0-9_.\-]+)(?P<sub>/[^@\s\"']+)?"
    r"@(?P<ref>[^\s#\"']+)(?P=q)(?P<rest>.*)$"
)
# Only plain git ref names are looked up; anything templated (`${{ ... }}`) or
# glob-like is reported instead of being sent to `git ls-remote` as a pattern.
_SAFE_REF = re.compile(r"^[A-Za-z0-9._/\-]+$")

# (url, patterns) -> list of "sha<TAB>refname" lines
LsRemote = Callable[[str, List[str]], List[str]]


def git_ls_remote(url: str, patterns: List[str]) -> List[str]:
    """Read-only lookup of refs on a public repo. Raises OSError on failure."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    try:
        out = subprocess.run(
            ["git", "ls-remote", url, *patterns],
            capture_output=True, text=True, timeout=45, env=env, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise OSError(str(exc)) from exc
    if out.returncode != 0:
        raise OSError((out.stderr or "git ls-remote failed").strip().splitlines()[-1])
    return [ln for ln in out.stdout.splitlines() if ln.strip()]


def resolve_sha(owner_repo: str, ref: str,
                ls_remote: LsRemote = git_ls_remote) -> Optional[str]:
    """Resolve a tag/branch to a commit SHA, or None if it can't be determined.

    Annotated tags list both the tag object and the peeled commit (`^{}`); the
    peeled commit is the one a workflow actually checks out, so it wins.
    """
    if _SHA.match(ref):
        return ref
    url = f"https://github.com/{owner_repo}.git"
    lines = ls_remote(url, [f"refs/tags/{ref}", f"refs/tags/{ref}^{{}}",
                            f"refs/heads/{ref}"])
    found: Dict[str, str] = {}
    for ln in lines:
        parts = ln.split()
        if len(parts) == 2 and _SHA.match(parts[0]):
            found[parts[1]] = parts[0]
    for key in (f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"):
        if key in found:
            return found[key]
    return None


@dataclass
class PinResult:
    path: str                                   # file, relative to repo root
    pinned: List[Tuple[str, str, str]]          # (action, ref, sha)
    skipped: List[Tuple[str, str, str]]         # (action, ref, reason)

    @property
    def changed(self) -> bool:
        return bool(self.pinned)


def pin_text(text: str, resolve: Callable[[str, str], Optional[str]]
             ) -> Tuple[str, List[Tuple[str, str, str]], List[Tuple[str, str, str]]]:
    """Rewrite every unpinned `uses:` line. Returns (new_text, pinned, skipped)."""
    pinned: List[Tuple[str, str, str]] = []
    skipped: List[Tuple[str, str, str]] = []
    cache: Dict[Tuple[str, str], Optional[str]] = {}
    out: List[str] = []
    for full in text.split("\n"):
        # Keep the line ending out of the regex so CRLF files stay CRLF.
        cr = "\r" if full.endswith("\r") else ""
        raw = full[:-1] if cr else full
        m = _USES.match(raw)
        if not m or raw.lstrip().startswith("#"):
            out.append(full)
            continue
        action = m.group("action") + (m.group("sub") or "")
        repo, ref, rest = m.group("action"), m.group("ref"), m.group("rest")
        if _SHA.match(ref):
            out.append(full)            # already pinned
            continue
        if not _SAFE_REF.match(ref):
            skipped.append((action, ref, "templated or unsupported ref"))
            out.append(full)
            continue
        key = (repo, ref)
        if key not in cache:
            try:
                cache[key] = resolve(repo, ref)
            except OSError as exc:
                cache[key] = None
                skipped.append((action, ref, f"lookup failed: {exc}"))
                out.append(full)
                continue
        sha = cache[key]
        if not sha:
            skipped.append((action, ref, "ref not found on the remote"))
            out.append(full)
            continue
        comment = rest if rest.strip() else f"  # {ref}"
        q = m.group("q")
        out.append(f"{m.group('prefix')}{q}{action}@{sha}{q}{comment}{cr}")
        pinned.append((action, ref, sha))
    return "\n".join(out), pinned, skipped


def pin_workflows(ctx, dry_run: bool = False,
                  resolve: Callable[[str, str], Optional[str]] = resolve_sha
                  ) -> List[PinResult]:
    """Pin every workflow under .github/workflows (honouring --exclude)."""
    from .remediate import safe_write, unsafe_reason

    results: List[PinResult] = []
    wf_dir = ctx.root / ".github" / "workflows"
    if not wf_dir.is_dir() or wf_dir.is_symlink():
        return results
    for path in sorted(wf_dir.iterdir()):
        if path.suffix.lower() not in (".yml", ".yaml") or ctx.is_excluded(path):
            continue
        if not ctx.is_regular(path):          # symlink / FIFO: never touch
            continue
        rel = ctx.rel(path)
        # newline="" keeps CRLF exactly as found.
        with open(path, encoding="utf-8", newline="") as fh:
            text = fh.read()
        new, pinned, skipped = pin_text(text, resolve)
        if pinned and not dry_run:
            why = unsafe_reason(ctx.root, rel)
            if why:
                skipped.append((rel, "-", f"not written: {why}"))
                pinned = []
            else:
                safe_write(ctx.root, rel, new)
        if pinned or skipped:
            results.append(PinResult(rel, pinned, skipped))
    return results
