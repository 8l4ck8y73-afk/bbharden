"""Repository context: file discovery + cheap helpers shared by scanners.

Security notes (this tool is routinely pointed at repositories you do not trust):
  * symlinks are never followed or yielded — a link inside the repo must not make
    the scanner read (or `fix` write) a file outside it;
  * only regular files are opened — a FIFO/device in a hostile tree must not hang
    the scan;
  * file contents are cached up to a bounded budget, so a huge tree cannot exhaust
    memory.
"""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# Directories we never descend into.
_IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", ".tox", ".idea", ".next", "vendor",
    "site-packages", ".terraform", ".terragrunt-cache",
}

# Extensions treated as binary / not worth reading as text.
_BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".7z",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav",
    ".so", ".dylib", ".dll", ".pyc", ".class", ".jar", ".bin", ".wasm",
}

_MAX_BYTES = 2_000_000          # skip files larger than ~2MB for text scanning
_CACHE_BUDGET = 64_000_000      # total characters kept in the read cache


def _is_regular(path: Path) -> bool:
    """True for a regular file that is not a symlink (never follows links)."""
    try:
        return stat.S_ISREG(os.lstat(path).st_mode)
    except OSError:
        return False


def _suffix_match(rel: str, pattern: str) -> bool:
    """Match `pattern` against rel or any trailing sub-path of it.

    `**/requirements*.txt` therefore matches both `requirements.txt` and
    `a/b/requirements-dev.txt`.
    """
    pat = pattern[3:] if pattern.startswith("**/") else pattern
    parts = rel.split("/")
    for i in range(len(parts)):
        if fnmatch.fnmatch("/".join(parts[i:]), pat):
            return True
    return False


@dataclass
class RepoContext:
    root: Path
    max_bytes: int = _MAX_BYTES
    # Opt-in: query OSV.dev for known CVEs (sends package names+versions only).
    use_osv: bool = False
    # Injectable lookup (tests); None means "use bbharden.osv.query".
    osv_query: object = None
    # Non-fatal notes surfaced to the user (e.g. "OSV unreachable").
    notes: list = field(default_factory=list)
    # Scanner crashes. A security gate must never fail OPEN, so the CLI turns a
    # non-empty list into a non-zero exit code.
    errors: list = field(default_factory=list)
    # True if --osv was requested but the lookup could not complete.
    osv_failed: bool = False
    # Glob patterns (relative to root, '/'-separated) to leave out of every scan.
    # A bare directory name such as "examples" excludes everything beneath it.
    exclude: list = field(default_factory=list)
    # Real contact address for a generated SECURITY.md (never invented).
    security_email: object = None
    # [[custom_rule]] entries from .bbharden.toml (see bbharden.config).
    custom_rules: list = field(default_factory=list)
    # By default the secrets scanner skips test/fixture/example paths (they hold
    # fake credentials); set True to scan them too.
    scan_tests: bool = False
    # Opt-in: scan git history for secrets (see scanners/history.py).
    history: bool = False
    # One DEP_KNOWN_VULN per advisory instead of one per package.
    osv_detail: bool = False
    history_max_commits: int = 10000
    _text_cache: dict = field(default_factory=dict)
    _cache_used: int = 0

    def __post_init__(self) -> None:
        self.root = Path(self.root).resolve()

    # ------------------------------------------------------------------ paths
    def rel(self, path: Path) -> str:
        try:
            return Path(path).relative_to(self.root).as_posix()
        except ValueError:
            return Path(path).as_posix()

    def is_excluded(self, path: Path) -> bool:
        if not self.exclude:
            return False
        rel = self.rel(path)
        for pat in self.exclude:
            pat = pat.strip().replace("\\", "/")
            while pat.startswith("./"):          # NOT lstrip("./"): that would
                pat = pat[2:]                    # also eat the dot of ".github"
            pat = pat.lstrip("/")
            if not pat:
                continue
            if fnmatch.fnmatch(rel, pat) or rel.startswith(pat.rstrip("/") + "/"):
                return True
        return False

    def is_regular(self, path: Path) -> bool:
        return _is_regular(path)

    # ------------------------------------------------------------- discovery
    def walk(self) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root, followlinks=False):
            dirnames[:] = sorted(d for d in dirnames if d not in _IGNORE_DIRS)
            for fn in sorted(filenames):
                p = Path(dirpath) / fn
                if _is_regular(p) and not self.is_excluded(p):
                    yield p

    def text_files(self) -> Iterator[Path]:
        for p in self.walk():
            if p.suffix.lower() in _BINARY_EXT:
                continue
            try:
                if p.stat().st_size > self.max_bytes:
                    continue
            except OSError:
                continue
            yield p

    def read_text(self, path: Path) -> str | None:
        path = Path(path)
        key = str(path)
        if key in self._text_cache:
            return self._text_cache[key]
        data: str | None
        if not _is_regular(path):
            data = None                      # symlink, FIFO, device, missing
        else:
            try:
                data = path.read_text(encoding="utf-8", errors="replace")
            except (OSError, UnicodeError):
                data = None
        if data is not None and self._cache_used + len(data) <= _CACHE_BUDGET:
            self._text_cache[key] = data
            self._cache_used += len(data)
        return data

    def find(self, *names: str) -> list[Path]:
        """Return existing files matching any of the given relative names."""
        out = []
        for name in names:
            candidate = self.root / name
            if candidate.exists():
                out.append(candidate)
        return out

    def glob(self, pattern: str) -> list[Path]:
        """Regular files whose root-relative path matches `pattern`.

        Matching is done on the path *relative to the root*: a repository that
        happens to live under a directory called `build/` or `vendor/` must not
        have its own files filtered out.
        """
        return [p for p in self.walk() if _suffix_match(self.rel(p), pattern)]
