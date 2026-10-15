"""GitHub Actions workflow hardening checks.

Pure text/line analysis (no YAML dependency) so the tool stays stdlib-only. The
checks are indentation-aware: a `run:` block ends where its indentation ends, so
the *recommended* fix (passing the value through `env:`) is never flagged.
"""

from __future__ import annotations

import re
from typing import Iterator, List

from ..findings import Finding, Severity

_USES = re.compile(r"""^\s*-?\s*uses:\s*['"]?([^\s#'"]+)""")
_SHA_REF = re.compile(r"@[0-9a-f]{40}$")
_LOCAL_OR_DOCKER = re.compile(r"^(\./|docker://)")

# Expressions an outside contributor controls. Used inside a shell/script body
# they are expanded BEFORE the shell parses the line -> command injection.
_EVENT_INTERP = re.compile(
    r"\$\{\{\s*(?:"
    r"github\.head_ref"
    r"|github\.event\.[a-zA-Z0-9_.\[\]*]*"
    r"(?:title|body|message|name|ref|label|comment|head_ref|email|page_name)"
    r"[a-zA-Z0-9_.\[\]*]*"
    r")\s*\}\}"
)
# `run:` (shell) and `script:` (actions/github-script) both execute the text.
_CODE_KEY = re.compile(r"^(?P<ind>\s*)(?P<dash>-\s+)?(?P<key>run|script):\s*(?P<val>.*)$")
_BLOCK_SCALAR = re.compile(r"^[|>][+\-0-9]*\s*(#.*)?$")
# A checkout `ref:` that points at the untrusted side of a pull request.
_HEAD_REF = re.compile(
    r"github\.event\.pull_request\.head|github\.head_ref|refs/pull/"
    r"|github\.event\.workflow_run\.head")


def _workflow_files(ctx):
    d = ctx.root / ".github" / "workflows"
    if d.is_dir() and not d.is_symlink():
        for p in sorted(d.iterdir()):
            if (p.suffix.lower() in (".yml", ".yaml") and ctx.is_regular(p)
                    and not ctx.is_excluded(p)):
                yield p


def _indent(s: str) -> int:
    return len(s) - len(s.lstrip(" "))


def _code_lines(lines: List[str]):
    """Yield (lineno, text) for every line that is part of a run:/script: body."""
    block_key_indent = None
    for i, raw in enumerate(lines, start=1):
        if block_key_indent is not None:
            if not raw.strip():
                continue
            if _indent(raw) > block_key_indent:
                yield i, raw
                continue
            block_key_indent = None            # dedent: the block is over
        m = _CODE_KEY.match(raw)
        if not m:
            continue
        key_indent = len(m.group("ind")) + (len(m.group("dash")) if m.group("dash") else 0)
        val = m.group("val").strip()
        if _BLOCK_SCALAR.match(val):
            block_key_indent = key_indent - (len(m.group("dash")) if m.group("dash") else 0)
        else:
            yield i, val


def _checkout_head_lines(lines: List[str]):
    """Line numbers of checkout steps whose `ref:` selects untrusted PR code."""
    for i, raw in enumerate(lines):
        if "actions/checkout" not in raw or not _USES.match(raw):
            continue
        base = _indent(raw)
        for j in range(i + 1, min(i + 15, len(lines))):
            nxt = lines[j]
            if nxt.strip() and re.match(r"^\s*-\s", nxt) and _indent(nxt) <= base:
                break
            if re.match(r"^\s*ref:\s*", nxt) and _HEAD_REF.search(nxt):
                yield i + 1
                break


def scan(ctx) -> Iterator[Finding]:
    for path in _workflow_files(ctx):
        name = ctx.rel(path)
        text = ctx.read_text(path)
        if not text:
            continue
        lines = text.splitlines()
        code = [ln.split("#", 1)[0] if ln.lstrip().startswith("#") else ln
                for ln in lines]

        for i, raw in enumerate(lines, start=1):
            m = _USES.match(raw)
            if not m:
                continue
            ref = m.group(1)
            if _LOCAL_OR_DOCKER.match(ref):
                continue
            if "@" in ref:
                if not _SHA_REF.search(ref):
                    yield Finding(
                        rule_id="CI_ACTION_UNPINNED",
                        title="Third-party action not pinned to a commit SHA",
                        severity=Severity.MEDIUM,
                        file=name, line=i,
                        message=f"`{ref}` is referenced by a mutable tag/branch. "
                                "A compromised tag can run arbitrary code with "
                                "your workflow's token.",
                        remediation="Pin to a full 40-char commit SHA, e.g. "
                                    "`actions/checkout@<sha>  # v4.2.2` — "
                                    "`bbharden fix --pin-actions` does it for you.",
                        evidence=ref, cwe="CWE-829",
                    )
            else:
                yield Finding(
                    rule_id="CI_ACTION_NO_REF",
                    title="Action referenced without any version",
                    severity=Severity.MEDIUM,
                    file=name, line=i,
                    message=f"`{ref}` has no version ref at all.",
                    remediation="Pin the action to a commit SHA.",
                    evidence=ref, cwe="CWE-829",
                )

        for i, body in _code_lines(lines):
            if body.lstrip().startswith("#"):
                continue
            if _EVENT_INTERP.search(body):
                yield Finding(
                    rule_id="CI_SCRIPT_INJECTION",
                    title="Untrusted event data interpolated into a run step",
                    severity=Severity.HIGH,
                    file=name, line=i,
                    message="Attacker-controlled fields (PR title, branch name, "
                            "comment body) are expanded directly into a shell "
                            "command, allowing script injection.",
                    remediation="Pass the value through an `env:` variable and "
                                "reference it quoted as \"$VAR\", instead of "
                                "interpolating ${{ github.event.* }} into run:.",
                    evidence=body.strip()[:120], cwe="CWE-94",
                )

        active = [ln for ln in code if not ln.lstrip().startswith("#")]

        if not any(re.match(r"\s*permissions\s*:", ln) for ln in active):
            yield Finding(
                rule_id="CI_NO_PERMISSIONS",
                title="Workflow does not restrict GITHUB_TOKEN permissions",
                severity=Severity.MEDIUM,
                file=name, line=1,
                message="No `permissions:` block at workflow or job level, so the "
                        "token gets the repository's default scope (often "
                        "read/write on everything). A compromised step or action "
                        "inherits all of it.",
                remediation="Add least-privilege permissions at the top level, "
                            "e.g. `permissions:\n  contents: read`, and grant extra "
                            "scopes per job only where needed. Not auto-applied: a "
                            "too-narrow default can break the workflow.",
                evidence="(no permissions: block)", cwe="CWE-250",
            )

        for i, ln in enumerate(active, start=1):
            if re.match(r"\s*permissions\s*:\s*write-all\b", ln):
                yield Finding(
                    rule_id="CI_PERMISSIONS_WRITE_ALL",
                    title="Workflow grants write-all permissions",
                    severity=Severity.HIGH,
                    file=name, line=i,
                    message="`permissions: write-all` gives every step full write "
                            "access to the repository.",
                    remediation="List only the scopes the job needs, e.g. "
                                "`contents: read`.",
                    evidence=ln.strip()[:120], cwe="CWE-250",
                )

        if any(re.search(r"\bpull_request_target\b", ln) for ln in active):
            for lineno in _checkout_head_lines(lines):
                yield Finding(
                    rule_id="CI_PR_TARGET_CHECKOUT",
                    title="pull_request_target checks out untrusted PR code",
                    severity=Severity.HIGH,
                    file=name, line=lineno,
                    message="`pull_request_target` runs with repository secrets and "
                            "a write token, and this step checks out the fork's "
                            "code — a common RCE/secret-exfiltration pattern.",
                    remediation="Do not check out or execute PR-provided code under "
                                "pull_request_target. Use `pull_request` for "
                                "untrusted code, or split into an unprivileged build "
                                "workflow plus a privileged `workflow_run` that only "
                                "consumes its artifacts.",
                    evidence="pull_request_target + checkout of PR head", cwe="CWE-829",
                )
