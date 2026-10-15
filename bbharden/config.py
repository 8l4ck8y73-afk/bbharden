"""Policy file: `.bbharden.toml`.

    [scan]
    fail_on    = "high"                 # CLI --fail-on wins
    exclude    = ["examples", "docs/*.md"]
    scan_tests = false
    only       = ["secrets", "iac"]     # or: skip = ["dependencies"]

    [rules.CI_ACTION_UNPINNED]
    severity = "low"                    # critical|high|medium|low|info|off

    [[custom_rule]]
    id          = "ACME_INTERNAL_HOST"  # UPPER_SNAKE so `bbharden:ignore` works
    title       = "Internal hostname in code"
    pattern     = 'corp\\.internal'
    severity    = "medium"
    files       = ["*.py", "src/**"]    # optional globs
    message     = "Internal hostnames must not ship in source."
    remediation = "Read it from configuration."

The file is data only — nothing in it is executed. Unknown keys are an error: a
typo in a policy file must never silently switch a check off.

Trust note: a policy file inside a repository you are *auditing* is controlled
by that repository's owner (it could hide findings from you). The CLI therefore
announces the file it loads, and `--no-config` ignores it.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from .findings import Finding, Severity

CONFIG_NAME = ".bbharden.toml"
_SEVERITIES = {s.value for s in Severity}
_ID = re.compile(r"^[A-Z][A-Z0-9_]{2,63}$")
_MAX_CONFIG_BYTES = 256_000
_MAX_LINE = 2000        # custom rules never run on longer lines (bounds regex cost)


class ConfigError(Exception):
    pass


@dataclass
class CustomRule:
    id: str
    title: str
    pattern: "re.Pattern[str]"
    severity: Severity
    files: List[str] = field(default_factory=list)
    message: str = ""
    remediation: str = ""
    redact: bool = False


@dataclass
class Config:
    path: Optional[Path] = None
    fail_on: Optional[str] = None
    exclude: List[str] = field(default_factory=list)
    scan_tests: Optional[bool] = None
    only: Optional[List[str]] = None
    skip: Optional[List[str]] = None
    # rule id -> new Severity, or None meaning "off"
    overrides: Dict[str, Optional[Severity]] = field(default_factory=dict)
    custom_rules: List[CustomRule] = field(default_factory=list)


def _check_keys(where: str, table: dict, allowed: set) -> None:
    unknown = set(table) - allowed
    if unknown:
        raise ConfigError(f"{where}: unknown key(s): {', '.join(sorted(unknown))} "
                          f"(allowed: {', '.join(sorted(allowed))})")


def _str_list(where: str, value) -> List[str]:
    if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
        raise ConfigError(f"{where} must be a list of strings")
    return value


def _severity(where: str, value) -> str:
    if not isinstance(value, str) or value.lower() not in _SEVERITIES:
        raise ConfigError(f"{where} must be one of: {', '.join(sorted(_SEVERITIES))}")
    return value.lower()


def parse(data: dict, known_rules=None, known_scanners=None) -> Config:
    """Validate an already-parsed TOML document into a Config."""
    _check_keys("config", data, {"scan", "rules", "custom_rule"})
    cfg = Config()

    scan = data.get("scan", {})
    if not isinstance(scan, dict):
        raise ConfigError("[scan] must be a table")
    _check_keys("[scan]", scan, {"fail_on", "exclude", "scan_tests", "only", "skip"})
    if "fail_on" in scan:
        cfg.fail_on = _severity("[scan] fail_on", scan["fail_on"])
    if "exclude" in scan:
        cfg.exclude = _str_list("[scan] exclude", scan["exclude"])
    if "scan_tests" in scan:
        if not isinstance(scan["scan_tests"], bool):
            raise ConfigError("[scan] scan_tests must be true or false")
        cfg.scan_tests = scan["scan_tests"]
    for key in ("only", "skip"):
        if key in scan:
            names = _str_list(f"[scan] {key}", scan[key])
            if known_scanners is not None:
                bad = [n for n in names if n not in known_scanners]
                if bad:
                    raise ConfigError(f"[scan] {key}: unknown scanner(s): {', '.join(bad)}")
            setattr(cfg, key, names)

    rules = data.get("rules", {})
    if not isinstance(rules, dict):
        raise ConfigError("[rules] must be a table")
    for rid, body in rules.items():
        if not isinstance(body, dict):
            raise ConfigError(f"[rules.{rid}] must be a table")
        _check_keys(f"[rules.{rid}]", body, {"severity"})
        if "severity" not in body:
            raise ConfigError(f"[rules.{rid}] needs a severity")
        value = body["severity"]
        if isinstance(value, str) and value.lower() == "off":
            cfg.overrides[rid] = None
        else:
            cfg.overrides[rid] = Severity(_severity(f"[rules.{rid}] severity", value))

    customs = data.get("custom_rule", [])
    if not isinstance(customs, list):
        raise ConfigError("[[custom_rule]] must be an array of tables")
    seen = set()
    for i, body in enumerate(customs, start=1):
        where = f"[[custom_rule]] #{i}"
        if not isinstance(body, dict):
            raise ConfigError(f"{where} must be a table")
        _check_keys(where, body, {"id", "title", "pattern", "severity", "files",
                                  "message", "remediation", "redact"})
        for req in ("id", "title", "pattern", "severity"):
            if req not in body:
                raise ConfigError(f"{where} is missing '{req}'")
        rid = body["id"]
        if not isinstance(rid, str) or not _ID.match(rid):
            raise ConfigError(f"{where} id must be UPPER_SNAKE_CASE (3-64 chars)")
        if rid in seen or (known_rules and rid in known_rules):
            raise ConfigError(f"{where} id '{rid}' is already used")
        seen.add(rid)
        try:
            rx = re.compile(body["pattern"])
        except (re.error, TypeError) as exc:
            raise ConfigError(f"{where} pattern is not a valid regex: {exc}")
        if rx.search(""):
            raise ConfigError(f"{where} pattern matches the empty string; it would "
                              "flag every line")
        cfg.custom_rules.append(CustomRule(
            id=rid,
            title=str(body["title"]),
            pattern=rx,
            severity=Severity(_severity(f"{where} severity", body["severity"])),
            files=_str_list(f"{where} files", body.get("files", [])),
            message=str(body.get("message", "")),
            remediation=str(body.get("remediation", "")),
            redact=bool(body.get("redact", False)),
        ))
    return cfg


def load(root: Path, explicit: Optional[str] = None, disabled: bool = False,
         known_rules=None, known_scanners=None) -> Config:
    """Load policy from --config FILE, else `<root>/.bbharden.toml`, else defaults."""
    if disabled:
        return Config()
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            raise ConfigError(f"config file not found: {explicit}")
    else:
        path = Path(root) / CONFIG_NAME
        if path.is_symlink() or not path.is_file():
            return Config()
    try:
        import tomllib
    except ImportError:                                    # Python < 3.11
        raise ConfigError(f"{path.name} needs Python 3.11+ (tomllib); "
                          "use --no-config or upgrade Python")
    try:
        if path.stat().st_size > _MAX_CONFIG_BYTES:
            raise ConfigError(f"{path} is unreasonably large")
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise ConfigError(f"cannot read {path}: {exc}")
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: invalid TOML: {exc}")
    cfg = parse(data, known_rules, known_scanners)
    cfg.path = path
    return cfg


def apply_overrides(findings: List[Finding], cfg: Config) -> List[Finding]:
    """Re-grade or drop findings according to [rules.*]."""
    if not cfg.overrides:
        return findings
    out = []
    for f in findings:
        if f.rule_id in cfg.overrides:
            new = cfg.overrides[f.rule_id]
            if new is None:
                continue
            f.severity = new
        out.append(f)
    return out
