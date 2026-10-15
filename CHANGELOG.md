# Changelog

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
