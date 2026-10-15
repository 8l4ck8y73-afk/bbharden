"""Scanner registry.

Each scanner is a callable that receives a RepoContext and yields Findings.
"""

from __future__ import annotations

from typing import Callable, Iterable, List

from ..findings import Finding
from . import custom, dependencies, dockerfile, history, iac, secrets, security_files, workflows

# A scanner is: (ctx) -> Iterable[Finding]
Scanner = Callable[["object"], Iterable[Finding]]

ALL_SCANNERS: List[tuple[str, Scanner]] = [
    ("secrets", secrets.scan),
    ("dockerfile", dockerfile.scan),
    ("dependencies", dependencies.scan),
    ("workflows", workflows.scan),
    ("iac", iac.scan),
    ("security-files", security_files.scan),
    ("custom", custom.scan),
    ("history", history.scan),
]


def enabled_scanners(only: list[str] | None, skip: list[str] | None):
    only = set(only) if only else None
    skip = set(skip) if skip else set()
    for name, fn in ALL_SCANNERS:
        if only is not None and name not in only:
            continue
        if name in skip:
            continue
        yield name, fn
