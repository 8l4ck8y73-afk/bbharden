<div align="center">

# 🛡️ BlackByte Hardener

### Find the security holes in your repo — and get the fix, not just the finding.

`bbharden` is a **defensive** security scanner that reviews a codebase for
committed secrets, insecure Dockerfiles, risky CI workflows and dependency
hygiene problems — then writes the remediation for you.

**Zero dependencies. One Python file to run. Works offline and in any CI.**

[Quick start](#-quick-start) · [What it checks](#-what-it-checks) · [GitHub Action](#-github-action) · [Auto-fix](#-auto-fix)

</div>

---

> **Defensive by design.** BlackByte Hardener inspects code **you own or are
> authorized to audit** and suggests hardening. It never attacks, exploits, or
> contacts third-party systems. It is the opposite of an offensive pentest tool:
> it closes holes instead of opening them.

## Why another scanner?

Most free tools stop at *"here is a list of problems."* BlackByte Hardener goes
one step further and **generates the fix** — a ready-to-commit `SECURITY.md`, a
`dependabot.yml`, a hardened `.gitignore` — and emits **SARIF** so findings show
up natively in GitHub's Security tab.

| | Legacy linters | Secret scanners | **BlackByte Hardener** |
|---|:---:|:---:|:---:|
| Secrets detection | ❌ | ✅ | ✅ |
| Dockerfile / CI hardening | partial | ❌ | ✅ |
| **Writes the fix for you** | ❌ | ❌ | ✅ |
| SARIF → GitHub Security tab | some | some | ✅ |
| Runtime dependencies | many | many | **none** |

## 🚀 Quick start

```bash
# Clone and run — no install, no pip, nothing to download
git clone https://github.com/8L4CK8Y73/bbharden.git
cd bbharden
python3 -m bbharden.cli scan /path/to/your/repo
```

Or install it:

```bash
pip install bbharden        # once published to PyPI
bbharden scan .
```

Example output:

```
🟥 CRITICAL SECRET_AWS_AKID
   AWS access key ID
   config.py:7
   evidence: AKI…LE (20 chars)
   → Possible aws access key id committed to the repository.

🟧 HIGH     DOCKER_RUNS_AS_ROOT
   Container runs as root
   Dockerfile:1
   → No non-root USER is set ...

Summary: 🟥 2 critical  🟧 6 high  🟨 4 medium  🟦 4 low  ⬜ 1 info
```

## 🔍 What it checks

| Scanner | Examples of what it catches |
|---|---|
| **secrets** | AWS keys, private keys, GitHub/Slack/Stripe tokens, hardcoded high-entropy credentials (evidence is always redacted) |
| **dockerfile** | runs as root, `:latest` base image, secrets in `ENV`, `curl \| bash`, `ADD <url>` |
| **workflows** | `pull_request_target` + checkout, script injection via `${{ github.event.* }}`, actions not pinned to a SHA |
| **dependencies** | unpinned pip / npm versions, npm install-time lifecycle scripts |
| **security-files** | missing `SECURITY.md`, missing Dependabot, committed `.env`, weak `.gitignore` — **all auto-fixable** |

Run a subset:

```bash
bbharden scan . --only secrets dockerfile
bbharden scan . --skip dependencies
```

## 🔧 Auto-fix

```bash
bbharden fix . --dry-run   # show what would change
bbharden fix .             # write the fixes
```

This creates the missing hygiene files directly. Pair it with a bot step in CI
to open a hardening pull request automatically.

## 🤖 GitHub Action

Drop this in `.github/workflows/security.yml`:

```yaml
name: Security Scan
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  harden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: 8L4CK8Y73/bbharden@v0.1.0
        with:
          fail-on: high        # fail the build on high/critical findings
```

Findings appear in **Security → Code scanning** via SARIF, and the job fails if
anything at or above your threshold is found.

## 📤 Output formats

```bash
bbharden scan . --format console          # human-readable (default)
bbharden scan . --format markdown -o report.md   # PR comment / docs
bbharden scan . --format sarif   -o out.sarif    # GitHub code scanning
bbharden scan . --format json    -o out.json     # pipe into other tools
```

Gate your pipeline:

```bash
bbharden scan . --fail-on high   # exit code 1 if high+ findings exist
```

## Roadmap

- [ ] Live CVE matching via optional `osv-scanner` / `pip-audit` hook
- [ ] Auto-open hardening PRs (GitHub App)
- [ ] Terraform / Kubernetes manifest hardening
- [ ] Custom rule packs (`.bbharden.yml`)
- [ ] Baseline file to suppress accepted findings

## License

Apache-2.0 © 8L4CK8Y73

---

<div align="center">
<sub>BlackByte Hardener is a defensive tool. Use it on code you own or are
authorized to audit.</sub>
</div>
