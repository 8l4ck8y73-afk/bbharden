"""GitHub Actions workflow hardening checks.

Pure text/line analysis (no YAML dependency) so the tool stays stdlib-only.
"""

from __future__ import annotations

import re
from typing import Iterator

from ..findings import Finding, Severity

_USES = re.compile(r"^\s*-?\s*uses:\s*([^\s#]+)")
_SHA_REF = re.compile(r"@[0-9a-f]{40}$")
_LOCAL_OR_DOCKER = re.compile(r"^(\./|docker://)")
_EVENT_INTERP = re.compile(
    r"\$\{\{\s*github\.event\.(?:[a-zA-Z0-9_.]*"
    r"(title|body|message|name|ref|label|comment|head_ref)[a-zA-Z0-9_.]*)\s*\}\}"
)


def _workflow_files(ctx):
    for sub in (".github/workflows",):
        d = ctx.root / sub
        if d.is_dir():
            for p in d.iterdir():
                if p.suffix.lower() in (".yml", ".yaml") and not ctx.is_excluded(p):
                    yield p


def scan(ctx) -> Iterator[Finding]:
    for path in _workflow_files(ctx):
        name = ctx.rel(path)
        text = ctx.read_text(path)
        if not text:
            continue
        lines = text.splitlines()
        in_run_block = False

        uses_pull_request_target = any(
            re.match(r"\s*pull_request_target\s*:", ln) or
            re.match(r"\s*-?\s*pull_request_target\s*$", ln)
            for ln in lines
        )
        checks_out_code = any("actions/checkout" in ln for ln in lines)

        for i, raw in enumerate(lines, start=1):
            m = _USES.match(raw)
            if m:
                ref = m.group(1)
                if not _LOCAL_OR_DOCKER.match(ref) and "@" in ref:
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
                                        "`actions/checkout@<sha>  # v4.2.2`.",
                            evidence=ref, cwe="CWE-829",
                        )
                elif "@" not in ref and not _LOCAL_OR_DOCKER.match(ref):
                    yield Finding(
                        rule_id="CI_ACTION_NO_REF",
                        title="Action referenced without any version",
                        severity=Severity.MEDIUM,
                        file=name, line=i,
                        message=f"`{ref}` has no version ref at all.",
                        remediation="Pin the action to a commit SHA.",
                        evidence=ref, cwe="CWE-829",
                    )

            # Detect run: blocks and script injection within them.
            if re.match(r"\s*run:\s*\|?\s*$", raw) or re.match(r"\s*run:\s+\S", raw):
                in_run_block = True
            elif in_run_block and raw and not raw[0].isspace():
                in_run_block = False

            if in_run_block and _EVENT_INTERP.search(raw):
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
                    evidence=raw.strip()[:120], cwe="CWE-94",
                )

        if uses_pull_request_target and checks_out_code:
            yield Finding(
                rule_id="CI_PR_TARGET_CHECKOUT",
                title="pull_request_target checks out untrusted PR code",
                severity=Severity.HIGH,
                file=name, line=1,
                message="`pull_request_target` runs with repository secrets while "
                        "checking out a fork's code — a common RCE/secret-exfil "
                        "pattern.",
                remediation="Avoid checking out and running untrusted code under "
                            "pull_request_target. If you must, check out the base "
                            "ref only and never execute PR-provided scripts with "
                            "secrets in scope.",
                evidence="pull_request_target + actions/checkout", cwe="CWE-829",
            )
