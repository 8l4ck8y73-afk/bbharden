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

### Honest positioning

BlackByte Hardener is **not** a replacement for the specialists. Use them too:

| Need | Best tool | Where bbharden fits |
|---|---|---|
| Deep secret detection, git **history**, live key verification | gitleaks, TruffleHog | bbharden scans the working tree only and does not verify keys — it is a cheap first pass |
| Broad code SAST (hundreds of languages/rules) | Semgrep, CodeQL | out of scope |
| Container / IaC / OS-package CVEs | Trivy, Grype | bbharden covers Dockerfile *hygiene* and pinned PyPI/npm CVEs via OSV |
| Repo-level supply-chain scoring | OpenSSF Scorecard | complementary |

Where bbharden is different: **zero dependencies** (one `git clone`, no Go
binary, no Docker pull), **it writes the fix** (`SECURITY.md`, Dependabot,
`.gitignore`, SHA-pinned Actions) and can open the hardening PR for you, and it
covers repo-hygiene + CI + Docker + secrets in one pass with SARIF output.

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
| **secrets** | AWS keys, private keys, GitHub (classic + fine-grained)/GitLab/npm/Slack/Stripe/SendGrid/Hugging Face tokens, hardcoded high-entropy credentials (evidence is always redacted) |
| **dockerfile** | runs as root, unpinned / `:latest` base image (understands `scratch`, multi-stage aliases, `ARG` defaults and digests), secrets in `ENV`, `curl \| bash`, `ADD <url>` |
| **workflows** | `pull_request_target` + checkout of the PR head, script injection via `${{ github.event.* }}` / `github.head_ref` in `run:` and `github-script` (indentation-aware: the `env:` fix is not flagged), unpinned actions, missing or `write-all` `permissions:` |
| **dependencies** | unpinned pip / npm versions (extras, markers, `==1.*`, `1.x`), npm install-time lifecycle scripts; with `--osv`, CVEs for direct pins **and lockfiles** (`package-lock.json`, `Pipfile.lock`, `poetry.lock`) |
| **security-files** | missing `SECURITY.md`, missing Dependabot, a `.env` that is tracked by git or not ignored, weak `.gitignore`, Dependabot config generated only for the ecosystems you actually use — **all auto-fixable** |

Run a subset, or leave paths out (repeatable; a bare directory name excludes
everything beneath it):

```bash
bbharden scan . --only secrets dockerfile
bbharden scan . --skip dependencies
bbharden scan . --exclude examples --exclude 'docs/*.md'
```

Test, fixture and example paths are skipped by the secrets scanner (they usually
hold fake keys); add `--scan-tests` to include them.

## 🙈 Suppressions & baselines

Adopt it on an existing repo without day-one noise, and still fail on anything new:

```bash
bbharden scan . --write-baseline .bbharden-baseline.json   # accept today's findings
bbharden scan . --baseline .bbharden-baseline.json --fail-on high   # fail only on NEW ones
```

Fingerprints ignore line numbers, so editing code above a finding doesn't revive it.
For one-off exceptions, comment the line (any comment style):

```python
legacy = "..."  # bbharden:ignore SECRET_GENERIC_ASSIGN
# bbharden:ignore-next-line DOCKER_RUNS_AS_ROOT
```

No rule id after the marker means "all rules on that line".

## 🧬 Known-CVE matching (`--osv`)

Turn "unpinned dependency" into "this exact version has CVE-XXXX":

```bash
bbharden scan . --osv
```

```
🟧 HIGH     DEP_KNOWN_VULN
   Known vulnerability in demo-lib 2.0.0 (CVE-2099-0001)
   requirements.txt:1
   → Upgrade `demo-lib` to 2.5.1 or later.
```

- **Opt-in**, because it needs network access to [OSV.dev](https://osv.dev).
- **Privacy:** only package names and versions are sent — never source code,
  file paths or repository names.
- **No guessing:** only exact pins (`==1.2.3`, `"1.2.3"`) are matched. Ranges like
  `>=1.0` or `^1.2` are reported as unpinned instead of being matched to a
  made-up version.
- **Fails soft:** if OSV is unreachable the scan completes normally and prints a
  note to stderr (so SARIF/JSON on stdout stays valid).
- Covers PyPI (`requirements*.txt`) and npm (`package.json`) today.

## 🔧 Auto-fix

```bash
bbharden fix . --dry-run   # show what would change
bbharden fix .             # write the fixes
```

This creates the missing hygiene files directly. Pair it with a bot step in CI
to open a hardening pull request automatically.

### Pin Actions to commit SHAs

```bash
bbharden fix . --pin-actions --only workflows
```

Rewrites `uses: actions/checkout@v4` to `uses: actions/checkout@<sha>  # v4`.
SHAs are resolved read-only with `git ls-remote` against the action's public repo
(annotated tags are peeled to the real commit). Anything that can't be resolved is
left untouched and reported — it never guesses. Note: the default `GITHUB_TOKEN`
cannot push workflow-file changes, so run this locally or give the auto-PR a PAT.

`SECURITY.md` needs a real contact address, and `bbharden` will never invent one:

```bash
bbharden fix . --security-email you@example.org
# or: export BBHARDEN_SECURITY_EMAIL=you@example.org
```

Without an address the missing policy is still reported, but no file is created.

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

## 🔁 Auto-hardening pull requests

Let BlackByte Hardener open a PR with the fixes it can apply safely — the same
pattern as Dependabot. Add `.github/workflows/auto-harden.yml`:

```yaml
name: Auto-Harden
on:
  workflow_dispatch:
  schedule:
    - cron: "23 7 * * 1"
permissions:
  contents: write
  pull-requests: write
jobs:
  auto-harden:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: |
          python3 -m bbharden.cli fix . \
            --security-email you@example.org \
            --summary "$RUNNER_TEMP/pr-body.md" --require-changes || \
            [ $? -eq 3 ] && echo "nothing to fix"
      - uses: peter-evans/create-pull-request@v6
        with:
          branch: bbharden/auto-harden
          title: "🛡️ Automated hardening fixes"
          body-path: ${{ runner.temp }}/pr-body.md
          commit-message: "chore(security): apply automated hardening fixes"
          labels: security, automated
```

Only machine-safe fixes are applied (missing `SECURITY.md`, Dependabot config,
`.gitignore` hardening). Findings that need human judgment — secrets to rotate,
Dockerfile and CI changes — are reported but never auto-committed. If there is
nothing to fix, no PR is opened. The ready-to-use workflow ships in this repo.

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

## 📱 Batch scan (Termux / Linux)

Scan many repositories at once and get a sheet to mark true/false positives:

```bash
pkg install -y git python        # Termux, once
./scripts/batch-scan.sh repos.txt            # one GitHub URL or folder per line
./scripts/batch-scan.sh --osv -o ~/results repos.txt
```

Produces `summary.md` (counts per repo and the most frequent rules) and
`review.tsv` (one row per finding; fill the `verdict` column with TP/FP). Repos are
cloned shallow with git hooks disabled. Use it to measure false positives on real
code before relying on a rule.

## 🔒 Exit codes & security model

| Code | Meaning |
|---|---|
| `0` | scan finished; nothing at/above `--fail-on` |
| `1` | findings at/above `--fail-on` |
| `2` | usage error, **a scanner crashed** (incomplete result), or `--osv-required` and the CVE lookup failed |
| `3` | `fix --require-changes` and there was nothing to fix |

A security gate must never fail *open*: if a scanner crashes, the run exits `2`
instead of reporting a clean pass.

bbharden is meant to be pointed at repositories you do not trust, so:

- **Symlinks are never followed or written through**, and only regular files are
  opened (a FIFO in a hostile tree cannot hang the scan). `fix` refuses any target
  that is a symlink, has a symlinked parent, or escapes the repo, and writes
  atomically (temp file + rename).
- **Nothing in the repo is executed.** The tool never runs the project's code, and
  it reads `.git/index` directly rather than spawning `git` inside the target.
- **Untrusted text is neutralised in reports**: terminal escapes and bidi
  overrides are stripped, Markdown/HTML is escaped, and secret values are never
  echoed (secrets and Dockerfile `ENV`/`ARG` evidence are redacted).
- **Network is opt-in and minimal**: only `--osv` (package names + versions) and
  `--pin-actions` (read-only `git ls-remote` on the actions' public repos).

## Roadmap

- [x] Auto-open hardening PRs (GitHub Action)
- [x] Live CVE matching via OSV.dev (`--osv`)
- [ ] Lockfile support (`package-lock.json`, `poetry.lock`, `Pipfile.lock`) for transitive CVEs
- [ ] Terraform / Kubernetes manifest hardening
- [ ] Custom rule packs (`.bbharden.yml`)
- [x] Baseline file and inline suppressions
- [x] SHA-pin GitHub Actions (`fix --pin-actions`)

## License

Apache-2.0 © 8L4CK8Y73

---

<div align="center">
<sub>BlackByte Hardener is a defensive tool. Use it on code you own or are
authorized to audit.</sub>
</div>
