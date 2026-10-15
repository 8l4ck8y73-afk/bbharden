# Changelog

## 0.8.2 — one finding per vulnerable package

- `--osv` now reports **one finding per package** ("django 4.2.1: 50 known vulnerabilities (4 critical, …)") with the single upgrade that fixes them, instead of one line per advisory. Severity is the worst advisory. The full list is kept in JSON (`details`) and shown as a table in the HTML report.
- `--osv-detail` restores one finding per advisory.
- HTML: groups mixing different findings of the same rule get a neutral header and per-row titles/fixes (previously only the first finding's text was shown for the whole group). Footer no longer claims history is never scanned.

## 0.8.1 — OSV de-duplication (found by the first live `--osv` run)

- First live run (django 4.2.1) returned 74 findings for one package: OSV lists the same flaw once per database (GHSA-…, PYSEC-…), so each CVE appeared 2-3 times, sometimes with different severities.
- Advisories sharing any id/alias are now merged into one finding; a rating that is actually known beats a defaulted MEDIUM; the highest fixed version is used.
- Each finding now also says which single upgrade resolves all advisories that list a fix.
- Same merge applies to `sbom --osv`.

## 0.8.0 — more ecosystems for SBOM and `--osv`

- Exact-version packages are now read from **go.mod**, **Cargo.lock** (registry crates only), **pom.xml** (literal versions; `${property}` and ranges skipped), **Gemfile.lock** and **composer.lock**, in addition to PyPI/npm. They feed both `sbom` and `--osv`.
- Correct purls (`pkg:golang`, `pkg:cargo`, `pkg:maven`, `pkg:gem`, `pkg:composer`).
- Verified: SBOMs for ripgrep (71 crates across two lockfiles) and fzf (11 Go modules, 15 gems) match the raw lockfile counts and validate against the official CycloneDX 1.5 schema. Parsers are linear-time on hostile input (a lazy-regex quadratic in pom parsing was found and fixed before release).
- Not yet validated live: OSV matching for these ecosystems (no network to api.osv.dev here); Go pseudo-versions and `+incompatible` versions are passed through as-is.

## 0.7.0 — git-history secret scanning

- **`scan --history`** (opt-in): finds secrets that were committed and later removed, reporting the oldest commit that introduced each (`SECRET_IN_HISTORY`, evidence redacted). Secrets still in the tree are not double-reported. `--history-max-commits N`.
- Same rules and calibration as the working-tree scanner (shared `match_line`).
- Runs system `git` read-only with hooks, external diff, textconv, fsmonitor and user/system config disabled (tested against a hostile `.git/config`); symlinked `.git` refused. Caps on commits, bytes and time: hitting one is reported as PARTIAL, never as clean. Shallow clones are flagged.
- Verified: parsed added lines match raw `git log` exactly on a 2,879-commit repo; 3 public repos (6,400+ commits) scan in ≤3 s with 0 findings.

## 0.6.0 — enterprise tranche 1

- **Policy file** `.bbharden.toml`: `fail_on`, `only`/`skip`, severity overrides, custom regex rules. `--config`, `--no-config`.
- **IaC scanner:** Kubernetes, Docker Compose, Terraform.
- **`sbom` command:** CycloneDX 1.5, validated against the official schema; optional OSV vulnerabilities; reproducible via `SOURCE_DATE_EPOCH`.
- **HTML report** (`--format html`): self-contained, no scripts, strict CSP, escaped untrusted text.
- **Compliance references** in JSON/SARIF/HTML (indicative only, never a compliance claim).
- Fix: `HYGIENE_GITIGNORE_SECRETS` was missing a mapping (caught by a new completeness test).

## 0.5.2 — calibration from real-world scans

Measured by scanning 15 public repositories (ripgrep, fzf, neovim, axios, lodash, black, ...)
and 4 private ones. Findings per repo before -> after for the affected rules:

- **False positive fixed:** `SECRET_OPENAI` matched SSH security-key algorithm names such as
  `sk-ssh-ed25519-cert-v01@openssh.com` (4 "high" findings in neovim, all false). The rule now
  only matches real key shapes: `sk-ant-...`, `sk-proj-/svcacct-/admin-...`, and legacy
  `sk-` + 32+ alphanumerics, each with an entropy check.
- `CI_ACTION_UNPINNED` is LOW for GitHub-owned actions (`actions/*`, `github/*`) and stays
  MEDIUM for third-party actions. neovim: 49 medium -> 0; 130 medium across the sample were
  mostly first-party.
- `DEP_UNPINNED_NPM` is INFO when a lockfile (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`,
  ...) sits next to the `package.json`, because the lockfile fixes the installed version.
  axios: 50 low -> 50 info.
- Not changed on purpose: `DOCKER_RUNS_AS_ROOT` stays HIGH. In build-only images (e.g.
  shellcheck's `builders/`) it is lower risk; that needs human judgment and is documented.
- 7 new regression tests.

## 0.5.1 — security & correctness audit

**Security hardening**
- Symlinks are never read or written through; only regular files are opened (FIFO hang fixed).
- `fix` refuses symlinked/escaping targets and writes atomically; `--pin-actions` preserves CRLF and quoting.
- A crashed scanner now exits `2` instead of passing the gate (fail-closed). New `--osv-required`.
- Dockerfile `ENV`/`ARG` secrets are redacted in every report format (previously echoed in full).
- Reports strip terminal escapes / bidi overrides and escape Markdown/HTML from repo-controlled text.
- A secret hidden on a >1000-character line is now found.

**Correctness**
- Repos living under a path containing `build/`, `dist/` or `vendor/` were silently skipped by the dependency scanner.
- `--exclude .github` stripped the leading dot and matched nothing.
- `CI_SCRIPT_INJECTION` missed the common `- run: ...` form and `github.head_ref`; it also looked past the end of a `run:` block. Now indentation-aware; also covers `github-script`.
- `CI_PR_TARGET_CHECKOUT` only fires when the PR head is actually checked out (a base checkout is safe); `on: pull_request_target` inline/list forms are recognised.
- Quoted `uses: "a/b@<sha>"` was reported as unpinned.
- `package.json` whose top level is not an object crashed the whole dependency scanner.
- `requests[extra]>=2`, `pkg  # comment` and `==3.*` were missed or sent to OSV as bogus versions.
- Dockerfile: the *final* stage decides root; `USER root:root`/`0:0`, a late `USER root`, `\` continuations and `ADD --chown` handled.
- `.env` is flagged only if tracked by git or not ignored; `.env.example` is never flagged.
- Dependabot config is generated only for ecosystems that have a manifest; `.gitignore` fix no longer duplicates patterns.
- OSV: truncated replies are an error (not "clean"), pagination followed, withdrawn advisories skipped, one unreachable advisory no longer drops the rest, "fixed in" never recommends a downgrade, CVSS v3 vectors are scored.
- SARIF: real repository URL, CWE tags, stable `partialFingerprints`, `/` separators.
- Baselines count duplicates: a second copy of a baselined secret is new.

**Added**
- Rules: `CI_PERMISSIONS_WRITE_ALL`; secrets for GitHub fine-grained, GitLab, npm, SendGrid, Hugging Face, Slack webhooks.
- OSV matching for `package-lock.json`, `Pipfile.lock`, `poetry.lock` (transitive dependencies).
- 52 new regression tests (46 fail on 0.5.0).

## 0.5.0
Baselines, inline suppressions, `fix --pin-actions`, `CI_NO_PERMISSIONS`.
