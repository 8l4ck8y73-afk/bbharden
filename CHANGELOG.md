# Changelog

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
