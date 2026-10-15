"""Security hygiene files — the scanner that ships real auto-fixes.

Findings here carry `fix_content`, so `bbharden fix` can create the missing
files directly.
"""

from __future__ import annotations

from typing import Iterator

from ..findings import Finding, Severity

_SECURITY_MD = """\
# Security Policy

## Reporting a Vulnerability

Please report security issues privately. Do **not** open a public issue for a
vulnerability.

- Email: {email}
- Or use GitHub's private vulnerability reporting ("Report a vulnerability"
  under the Security tab).

We aim to acknowledge reports within 2 business days and to provide a fix or
mitigation timeline within 10 business days.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| latest  | ✅        |
"""

_DEPENDABOT = """\
version: 2
updates:
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "npm"
    directory: "/"
    schedule:
      interval: "weekly"
"""

_GITIGNORE_SECRETS = [
    ".env", ".env.*", "*.pem", "*.key", "id_rsa", "*.p12", "*.pfx",
    "credentials.json", "*.keystore",
]


def scan(ctx) -> Iterator[Finding]:
    # 1. SECURITY.md
    if not ctx.find("SECURITY.md", ".github/SECURITY.md", "docs/SECURITY.md"):
        email = getattr(ctx, "security_email", None)
        if email:
            # `.replace` (not str.format) so literal braces in the template can
            # never break generation.
            content = _SECURITY_MD.replace("{email}", email)
            how = ("Add a SECURITY.md describing how to report issues privately. "
                   "`bbharden fix` will create one using your --security-email.")
        else:
            # Never invent a contact address: a fake one in a published policy is
            # worse than no policy. Report the gap, but offer no auto-fix.
            content = None
            how = ("Add a SECURITY.md describing how to report issues privately. "
                   "Re-run `bbharden fix --security-email you@example.org` to have "
                   "it generated with your real contact address.")
        yield Finding(
            rule_id="HYGIENE_NO_SECURITY_MD",
            title="No SECURITY.md disclosure policy",
            severity=Severity.LOW,
            file="SECURITY.md", line=1,
            message="The repository has no security policy, so reporters have no "
                    "private channel to disclose vulnerabilities.",
            remediation=how,
            fix_path="SECURITY.md", fix_content=content,
        )

    # 2. Dependabot
    if not ctx.find(".github/dependabot.yml", ".github/dependabot.yaml"):
        yield Finding(
            rule_id="HYGIENE_NO_DEPENDABOT",
            title="No Dependabot configuration",
            severity=Severity.INFO,
            file=".github/dependabot.yml", line=1,
            message="Dependencies and GitHub Actions are not automatically kept "
                    "up to date.",
            remediation="Add .github/dependabot.yml. `bbharden fix` can create a "
                        "sensible default.",
            fix_path=".github/dependabot.yml", fix_content=_DEPENDABOT,
        )

    # 3. .env committed
    for env in ctx.glob("**/.env"):
        yield Finding(
            rule_id="HYGIENE_ENV_COMMITTED",
            title="Environment file committed",
            severity=Severity.HIGH,
            file=ctx.rel(env), line=1,
            message="A .env file is tracked in the repository and typically holds "
                    "secrets.",
            remediation="Remove it from git, rotate any secrets it held, and add "
                        "`.env` to .gitignore.",
            cwe="CWE-538",
        )

    # 4. .gitignore missing common secret patterns
    gi = ctx.find(".gitignore")
    if gi:
        content = ctx.read_text(gi[0]) or ""
        missing = [p for p in _GITIGNORE_SECRETS if p not in content]
        if len(missing) >= 5:
            new_content = content.rstrip("\n") + "\n\n# Secrets (added by bbharden)\n" \
                + "\n".join(_GITIGNORE_SECRETS) + "\n"
            yield Finding(
                rule_id="HYGIENE_GITIGNORE_SECRETS",
                title=".gitignore does not exclude common secret files",
                severity=Severity.LOW,
                file=".gitignore", line=1,
                message="Common secret-bearing files are not ignored, making an "
                        "accidental commit more likely.",
                remediation="Add patterns like .env, *.pem, *.key to .gitignore.",
                fix_path=".gitignore", fix_content=new_content,
            )
