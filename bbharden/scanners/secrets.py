"""Detect committed secrets.

Pattern-based with an entropy backstop. Every piece of evidence is redacted
before it leaves this module — we never echo a live secret into a report.
"""

from __future__ import annotations

import math
import re
from typing import Iterator

from ..findings import Finding, Severity

# (rule_id, human title, compiled regex, severity)
_PATTERNS = [
    ("SECRET_AWS_AKID", "AWS access key ID",
     re.compile(r"\b(AKIA|ASIA)[0-9A-Z]{16}\b"), Severity.CRITICAL),
    ("SECRET_PRIVATE_KEY", "Private key material",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
     Severity.CRITICAL),
    ("SECRET_GITHUB_PAT", "GitHub personal access token",
     re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), Severity.CRITICAL),
    ("SECRET_SLACK_TOKEN", "Slack token",
     re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), Severity.HIGH),
    ("SECRET_STRIPE_KEY", "Stripe secret key",
     re.compile(r"\b[sr]k_live_[A-Za-z0-9]{20,}\b"), Severity.CRITICAL),
    ("SECRET_GOOGLE_API", "Google API key",
     re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("SECRET_OPENAI", "OpenAI / Anthropic style key",
     re.compile(r"\b(sk-ant-|sk-)[A-Za-z0-9_\-]{20,}\b"), Severity.HIGH),
    ("SECRET_JWT", "Hardcoded JWT",
     re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
     Severity.MEDIUM),
]

# Generic "assignment to a secret-looking name" with a long opaque value.
# The value MUST be a quoted string literal — this is what separates a
# hardcoded credential from a normal assignment to another variable
# (e.g. `api_key = settings.api_key`), which is the main source of noise.
_ASSIGN = re.compile(
    r"""(?ix)
    \b(password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|
       auth[_-]?token|private[_-]?key|client[_-]?secret)\b
    \s*[:=]\s*
    (?P<q>['"])(?P<val>[A-Za-z0-9/+_\-.=]{12,})(?P=q)
    """,
)

# Word-like values (dictionary words joined by - or _, or dotted identifiers)
# are almost never real secrets, even quoted.
_WORDLIKE = re.compile(r"(?i)^[a-z]+([-_.][a-z]+)*$")

# Values that look like placeholders, not real secrets.
_PLACEHOLDER = re.compile(
    r"(?ix)^(x{3,}|\*{3,}|\.{3,}|<.*>|\$\{.*\}|changeme|example|placeholder|"
    r"your[-_]?.*|dummy|test|sample|none|null|true|false|redacted|"
    r"[0]{6,}|[a-f0-9]{0,6})$"
)

_IGNORE_NAME = re.compile(r"(?i)(\.lock$|\.min\.js$|package-lock\.json$|yarn\.lock$|"
                          r"\.map$|test|spec|fixture|example|sample|mock)")


def _redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return f"{value[:3]}…{value[-2:]} ({len(value)} chars)"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def scan(ctx) -> Iterator[Finding]:
    remediation = (
        "Remove the secret from the code and from git history (e.g. with "
        "`git filter-repo`), then ROTATE it at the provider — assume it is "
        "already compromised. Load it at runtime from an environment variable "
        "or a secrets manager, and add the file pattern to .gitignore."
    )
    for path in ctx.text_files():
        name = ctx.rel(path)
        if _IGNORE_NAME.search(name):
            continue
        text = ctx.read_text(path)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > 1000:
                continue
            matched_rules = set()
            for rule_id, title, rx, sev in _PATTERNS:
                m = rx.search(line)
                if not m:
                    continue
                matched_rules.add(rule_id)
                yield Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=sev,
                    file=name,
                    line=lineno,
                    message=f"Possible {title.lower()} committed to the repository.",
                    remediation=remediation,
                    evidence=_redact(m.group(0)),
                    cwe="CWE-798",
                )
            # Generic assignment heuristic (skip if a specific rule already hit).
            if matched_rules:
                continue
            am = _ASSIGN.search(line)
            if am:
                val = am.group("val")
                if _PLACEHOLDER.match(val):
                    continue
                if _WORDLIKE.match(val):
                    continue
                if _shannon_entropy(val) < 3.2:
                    continue
                yield Finding(
                    rule_id="SECRET_GENERIC_ASSIGN",
                    title="Hardcoded credential",
                    severity=Severity.HIGH,
                    file=name,
                    line=lineno,
                    message=(
                        f"A '{am.group(1)}' value with high entropy appears to be "
                        "hardcoded."
                    ),
                    remediation=remediation,
                    evidence=_redact(val),
                    cwe="CWE-798",
                )
