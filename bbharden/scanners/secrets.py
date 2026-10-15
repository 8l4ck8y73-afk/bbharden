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
    # Anthropic / OpenAI key shapes only. A bare `sk-<words>` also matches SSH
    # security-key algorithm names (`sk-ssh-ed25519-cert-v01@openssh.com`), which
    # is what real-world testing on neovim's syntax files turned up.
    ("SECRET_OPENAI", "OpenAI / Anthropic style key",
     re.compile(r"\b(?:sk-ant-[A-Za-z0-9_\-]{20,}"
                r"|sk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{20,}"
                r"|sk-[A-Za-z0-9]{32,})\b"), Severity.HIGH),
    ("SECRET_GITHUB_FINE_PAT", "GitHub fine-grained token",
     re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,}\b"), Severity.CRITICAL),
    ("SECRET_GITLAB_PAT", "GitLab personal access token",
     re.compile(r"\bglpat-[A-Za-z0-9_\-]{20,}\b"), Severity.CRITICAL),
    ("SECRET_NPM_TOKEN", "npm access token",
     re.compile(r"\bnpm_[A-Za-z0-9]{36}\b"), Severity.CRITICAL),
    ("SECRET_SENDGRID", "SendGrid API key",
     re.compile(r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"), Severity.HIGH),
    ("SECRET_HUGGINGFACE", "Hugging Face token",
     re.compile(r"\bhf_[A-Za-z0-9]{34}\b"), Severity.HIGH),
    ("SECRET_SLACK_WEBHOOK", "Slack incoming webhook URL",
     re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}"),
     Severity.HIGH),
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

# Generated / vendored artefacts that are never worth scanning.
_IGNORE_FILE = re.compile(r"(?i)(\.lock$|\.min\.js$|package-lock\.json$|yarn\.lock$|\.map$)")

# Directories that conventionally hold fake credentials. Matched as WHOLE path
# components — never as substrings, which would also skip `latest/`, `contest/`
# or `attestation/` and silently hide real leaks.
_TESTISH_DIRS = {
    "test", "tests", "__tests__", "spec", "specs", "fixture", "fixtures",
    "mock", "mocks", "example", "examples", "sample", "samples", "testdata",
}
# test_foo.py, foo_test.go, foo.test.js, foo.spec.ts
_TESTISH_FILE = re.compile(r"(?i)^(test_.*|.*_test\.\w+|.*\.(test|spec)\.\w+)$")


def _is_ignored(rel_path: str, scan_tests: bool) -> bool:
    if _IGNORE_FILE.search(rel_path):
        return True
    if scan_tests:
        return False
    parts = rel_path.replace("\\", "/").split("/")
    if any(p.lower() in _TESTISH_DIRS for p in parts[:-1]):
        return True
    return bool(_TESTISH_FILE.match(parts[-1]))


def _accept(rule_id: str, text: str) -> bool:
    """Extra checks for patterns that are broad enough to hit ordinary words."""
    if rule_id == "SECRET_OPENAI":
        tail = text.split("-", 2)[-1] if text.count("-") >= 2 else text[3:]
        # Real keys are high-entropy and mix digits with letters; a long
        # lowercase slug is not a key.
        return any(c.isdigit() for c in tail) and _shannon_entropy(tail) >= 3.5
    return True


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


REMEDIATION = (
    "Remove the secret from the code and from git history (e.g. with "
    "`git filter-repo`), then ROTATE it at the provider — assume it is "
    "already compromised. Load it at runtime from an environment variable "
    "or a secrets manager, and add the file pattern to .gitignore."
)


def match_line(line: str):
    """Yield (rule_id, title, severity, redacted_evidence, message) for a line.

    Shared by the working-tree scan and the git-history scan so both apply the
    exact same rules and calibration.
    """
    # Very long lines (minified bundles) only skip the generic heuristic:
    # provider-signature patterns still run, otherwise padding a line
    # past 1000 chars would hide a real key.
    long_line = len(line) > 1000
    matched = False
    for rule_id, title, rx, sev in _PATTERNS:
        m = rx.search(line)
        if not m or not _accept(rule_id, m.group(0)):
            continue
        matched = True
        yield (rule_id, title, sev, _redact(m.group(0)),
               f"Possible {title.lower()} committed to the repository.")
    # Generic assignment heuristic (skip if a specific rule already hit).
    if matched or long_line:
        return
    am = _ASSIGN.search(line)
    if am:
        val = am.group("val")
        if _PLACEHOLDER.match(val) or _WORDLIKE.match(val):
            return
        if _shannon_entropy(val) < 3.2:
            return
        yield ("SECRET_GENERIC_ASSIGN", "Hardcoded credential", Severity.HIGH,
               _redact(val),
               f"A '{am.group(1)}' value with high entropy appears to be hardcoded.")


def scan(ctx) -> Iterator[Finding]:
    for path in ctx.text_files():
        name = ctx.rel(path)
        if _is_ignored(name, getattr(ctx, "scan_tests", False)):
            continue
        text = ctx.read_text(path)
        if not text:
            continue
        for lineno, line in enumerate(text.splitlines(), start=1):
            for rule_id, title, sev, ev, msg in match_line(line):
                yield Finding(
                    rule_id=rule_id, title=title, severity=sev, file=name,
                    line=lineno, message=msg, remediation=REMEDIATION,
                    evidence=ev, cwe="CWE-798",
                )
