"""Finding model shared by every scanner."""

from __future__ import annotations

import dataclasses
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        order = {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }
        return order[self]

    @property
    def sarif_level(self) -> str:
        # SARIF only defines error/warning/note/none.
        if self in (Severity.CRITICAL, Severity.HIGH):
            return "error"
        if self is Severity.MEDIUM:
            return "warning"
        return "note"


@dataclasses.dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    file: str
    line: int
    message: str
    remediation: str
    # Optional machine-applicable fix. If `fix_content` is set, the file at
    # `fix_path` (defaults to `file`) can be created/replaced with it.
    fix_path: Optional[str] = None
    fix_content: Optional[str] = None
    # A short excerpt of the offending line, already redacted when sensitive.
    evidence: str = ""
    cwe: Optional[str] = None
    # Optional structured sub-items (e.g. every advisory behind a grouped
    # DEP_KNOWN_VULN finding). Rendered by JSON/HTML; omitted when None.
    details: Optional[list] = None

    @property
    def has_autofix(self) -> bool:
        return self.fix_content is not None

    def to_dict(self) -> dict:
        d = dataclasses.asdict(self)
        d["severity"] = self.severity.value
        d["has_autofix"] = self.has_autofix
        # fix_content can be large; omit from the compact dict form.
        d.pop("fix_content", None)
        if d.get("details") is None:
            d.pop("details", None)
        return d
