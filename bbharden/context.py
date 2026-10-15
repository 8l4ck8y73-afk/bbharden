"""Repository context: file discovery + cheap helpers shared by scanners."""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator

# Directories we never descend into.
_IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", "dist", "build", ".tox", ".idea", ".next", "vendor",
    "site-packages",
}

# Extensions treated as binary / not worth reading as text.
_BINARY_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".pdf", ".zip", ".gz", ".tar", ".7z",
    ".ico", ".woff", ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".wav",
    ".so", ".dylib", ".dll", ".pyc", ".class", ".jar", ".bin", ".wasm",
}

_MAX_BYTES = 2_000_000  # skip files larger than ~2MB for text scanning


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
    # Glob patterns (relative to root, '/'-separated) to leave out of every scan.
    # A bare directory name such as "examples" excludes everything beneath it.
    exclude: list = field(default_factory=list)
    # Real contact address for a generated SECURITY.md (never invented).
    security_email: object = None
    # By default the secrets scanner skips test/fixture/example paths (they hold
    # fake credentials); set True to scan them too.
    scan_tests: bool = False
    _text_cache: dict = field(default_factory=dict)

    def rel(self, path: Path) -> str:
        try:
            return str(path.relative_to(self.root))
        except ValueError:
            return str(path)

    def is_excluded(self, path: Path) -> bool:
        if not self.exclude:
            return False
        rel = self.rel(path).replace(os.sep, "/")
        for pat in self.exclude:
            pat = pat.strip().replace(os.sep, "/").lstrip("./")
            if not pat:
                continue
            if fnmatch.fnmatch(rel, pat) or rel.startswith(pat.rstrip("/") + "/"):
                return True
        return False

    def walk(self) -> Iterator[Path]:
        for dirpath, dirnames, filenames in os.walk(self.root):
            dirnames[:] = [d for d in dirnames if d not in _IGNORE_DIRS]
            for fn in filenames:
                p = Path(dirpath) / fn
                if not self.is_excluded(p):
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
        key = str(path)
        if key in self._text_cache:
            return self._text_cache[key]
        try:
            data = path.read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            data = None
        self._text_cache[key] = data
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
        return [
            p for p in self.root.glob(pattern)
            if not any(part in _IGNORE_DIRS for part in p.parts)
            and not self.is_excluded(p)
        ]
