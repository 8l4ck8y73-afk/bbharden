"""Security hygiene files — the scanner that ships real auto-fixes.

Findings here carry `fix_content`, so `bbharden fix` can create the missing
files directly.
"""

from __future__ import annotations

import fnmatch
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

# (ecosystem, manifest basenames or suffix). First match per directory wins.
_ECOSYSTEMS = [
    ("pip", ("requirements.txt", "pyproject.toml", "Pipfile", "setup.py", "setup.cfg")),
    ("npm", ("package.json",)),
    ("docker", ("Dockerfile",)),
    ("gomod", ("go.mod",)),
    ("cargo", ("Cargo.toml",)),
    ("maven", ("pom.xml",)),
    ("gradle", ("build.gradle", "build.gradle.kts")),
    ("bundler", ("Gemfile",)),
    ("composer", ("composer.json",)),
    ("nuget", ("packages.config",)),
    ("terraform", ("main.tf",)),
]


def _detect_ecosystems(ctx):
    """[(ecosystem, directory)] for the manifests that really exist.

    Dependabot reports an *error* for an ecosystem with no manifest, so a
    one-size-fits-all file (pip + npm for a Go repo) is worse than none.
    """
    found = []
    wf = ctx.root / ".github" / "workflows"
    if wf.is_dir() and not wf.is_symlink() and any(
            p.suffix.lower() in (".yml", ".yaml") for p in wf.iterdir()):
        found.append(("github-actions", "/"))
    seen = set(found)
    for p in ctx.walk():
        name = p.name
        for eco, names in _ECOSYSTEMS:
            if name in names or (eco == "docker" and name.lower().startswith("dockerfile")):
                d = "/" + ctx.rel(p.parent) if ctx.rel(p.parent) != "." else "/"
                if eco == "terraform" and not name.endswith(".tf"):
                    continue
                key = (eco, d)
                if key not in seen:
                    seen.add(key)
                    found.append(key)
                break
    return found


def _dependabot_yaml(ecosystems) -> str:
    out = ["version: 2", "updates:"]
    for eco, directory in ecosystems:
        out += [f'  - package-ecosystem: "{eco}"',
                f'    directory: "{directory}"',
                "    schedule:",
                '      interval: "weekly"']
    return "\n".join(out) + "\n"


_GITIGNORE_SECRETS = [
    ".env", ".env.*", "*.pem", "*.key", "id_rsa", "*.p12", "*.pfx",
    "credentials.json", "*.keystore",
]


_ENV_TEMPLATE_SUFFIXES = {"example", "sample", "template", "dist", "defaults", "schema"}


def _is_env_file(name: str) -> bool:
    if name == ".env":
        return True
    if name.startswith(".env."):
        return name.rsplit(".", 1)[-1].lower() not in _ENV_TEMPLATE_SUFFIXES
    return False


def _tracked_in_git(root, rel: str):
    """True/False if `rel` is in the git index; None if it cannot be told.

    Reads .git/index directly (v2/v3) instead of spawning `git`: running git
    inside a repository you do not trust can execute that repository's own
    configured hooks/helpers.
    """
    idx = root / ".git" / "index"
    try:
        if idx.is_symlink() or not idx.is_file() or idx.stat().st_size > 200_000_000:
            return None
        data = idx.read_bytes()
    except OSError:
        return None
    if data[:4] != b"DIRC" or int.from_bytes(data[4:8], "big") not in (2, 3):
        return None
    needle = rel.encode("utf-8") + b"\x00"
    want = min(len(rel.encode("utf-8")), 0xFFF)
    pos = data.find(needle)
    while pos != -1:
        if pos >= 2:
            flags = int.from_bytes(data[pos - 2:pos], "big")
            if (flags & 0xFFF) == want and ((flags >> 12) & 0x3) == 0:
                return True
        pos = data.find(needle, pos + 1)
    return False


def _is_gitignored(ctx, rel: str) -> bool:
    """Approximate .gitignore evaluation (root and parent-directory files)."""
    parts = rel.split("/")
    ignored = False
    for depth in range(len(parts)):
        base = "/".join(parts[:depth])
        gi = ctx.root / base / ".gitignore" if base else ctx.root / ".gitignore"
        text = ctx.read_text(gi) if gi.exists() else None
        if not text:
            continue
        sub = "/".join(parts[depth:])
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            neg = line.startswith("!")
            pat = line[1:] if neg else line
            anchored = "/" in pat.rstrip("/")
            pat = pat.strip("/")
            if not pat:
                continue
            cand = [sub] if anchored else [sub, parts[-1]]
            if any(fnmatch.fnmatch(c, pat) or fnmatch.fnmatch(c, "**/" + pat)
                   for c in cand):
                ignored = not neg
    return ignored


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

    # 2. Dependabot — only for ecosystems that actually have a manifest.
    if not ctx.find(".github/dependabot.yml", ".github/dependabot.yaml"):
        ecosystems = _detect_ecosystems(ctx)
        if ecosystems:
            yield Finding(
                rule_id="HYGIENE_NO_DEPENDABOT",
                title="No Dependabot configuration",
                severity=Severity.INFO,
                file=".github/dependabot.yml", line=1,
                message="Dependencies and GitHub Actions are not automatically kept "
                        "up to date.",
                remediation="Add .github/dependabot.yml. `bbharden fix` generates one "
                            "for the ecosystems detected here: "
                            + ", ".join(sorted({e for e, _ in ecosystems})) + ".",
                fix_path=".github/dependabot.yml",
                fix_content=_dependabot_yaml(ecosystems),
            )

    # 3. Environment files holding real secrets
    for env in ctx.walk():
        if not _is_env_file(env.name):
            continue
        rel = ctx.rel(env)
        tracked = _tracked_in_git(ctx.root, rel)
        ignored = _is_gitignored(ctx, rel)
        if ignored and not tracked:
            continue                      # present locally, correctly kept out of git
        state = ("is tracked by git" if tracked
                 else "is not covered by any .gitignore rule")
        yield Finding(
            rule_id="HYGIENE_ENV_COMMITTED",
            title="Environment file committed" if tracked
            else "Environment file not git-ignored",
            severity=Severity.HIGH,
            file=rel, line=1,
            message=f"`{rel}` {state} and typically holds secrets.",
            remediation="Remove it from git (`git rm --cached`), rotate any secrets "
                        "it held, and add it to .gitignore. Commit a `.env.example` "
                        "with placeholder values instead.",
            cwe="CWE-538",
        )

    # 4. .gitignore missing common secret patterns
    gi = ctx.find(".gitignore")
    if gi:
        content = ctx.read_text(gi[0]) or ""
        present = {ln.strip() for ln in content.splitlines()}
        missing = [p for p in _GITIGNORE_SECRETS if p not in present]
        if len(missing) >= 5:
            sep = "" if content.endswith("\n") or not content else "\n"
            new_content = (content + sep + "\n# Secrets (added by bbharden)\n"
                           + "\n".join(missing) + "\n")
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
