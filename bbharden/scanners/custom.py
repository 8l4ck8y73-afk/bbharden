"""User-defined regex rules from `.bbharden.toml` ([[custom_rule]])."""

from __future__ import annotations

import fnmatch
from typing import Iterator

from ..findings import Finding


def _matches(rel: str, globs) -> bool:
    """True if `rel` matches any glob. Globs without '/' match the file name
    anywhere (`*.py`); globs with '/' match the whole relative path (`src/**`)."""
    name = rel.rsplit("/", 1)[-1]
    for g in globs:
        g = g.replace("\\", "/")
        if g.startswith("./"):                 # not lstrip("./"): keeps ".github"
            g = g[2:]
        if fnmatch.fnmatch(rel, g) or ("/" not in g and fnmatch.fnmatch(name, g)):
            return True
    return False


def scan(ctx) -> Iterator[Finding]:
    rules = getattr(ctx, "custom_rules", None) or []
    if not rules:
        return
    from ..config import _MAX_LINE
    for path in ctx.text_files():
        rel = ctx.rel(path)
        applicable = [r for r in rules if not r.files or _matches(rel, r.files)]
        if not applicable:
            continue
        text = ctx.read_text(path)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > _MAX_LINE:
                continue
            for r in applicable:
                m = r.pattern.search(line)
                if not m:
                    continue
                shown = m.group(0)
                if r.redact:
                    shown = shown[:2] + "…" + f" ({len(shown)} chars)"
                yield Finding(
                    rule_id=r.id, title=r.title, severity=r.severity,
                    file=rel, line=lineno,
                    message=r.message or f"Matched custom rule {r.id}.",
                    remediation=r.remediation or "See your team's policy for this rule.",
                    evidence=shown[:120],
                )
