"""BlackByte Hardener CLI."""

from __future__ import annotations

import argparse
import os
import re
import sys
from pathlib import Path
from typing import List

from . import __version__, config as config_mod, pin as pin_mod, report, sbom as sbom_mod, suppress
from .context import RepoContext
from .findings import Finding, Severity
from .remediate import apply as apply_fixes
from .scanners import enabled_scanners

_SEV_ORDER = [s.value for s in Severity]


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")


def _resolve_email(args):
    """--security-email, else $BBHARDEN_SECURITY_EMAIL, else None. Validated."""
    email = getattr(args, "security_email", None) or os.environ.get(
        "BBHARDEN_SECURITY_EMAIL")
    if email and not _EMAIL_RE.match(email):
        print(f"error: not a valid email address: {email}", file=sys.stderr)
        raise SystemExit(2)
    return email or None


def _load_config(args, root: Path):
    """Policy from --config / <root>/.bbharden.toml (or defaults). Exits 2 on error."""
    from .scanners import ALL_SCANNERS
    try:
        cfg = config_mod.load(
            root, getattr(args, "config", None), getattr(args, "no_config", False),
            known_scanners={n for n, _ in ALL_SCANNERS})
    except config_mod.ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        raise SystemExit(2)
    if cfg.path:
        # Announced, because a repo under audit controls its own policy file.
        print(f"note: using policy {cfg.path} (--no-config to ignore)", file=sys.stderr)
    return cfg


def _make_context(args, root: Path, cfg, **extra) -> RepoContext:
    return RepoContext(
        root=root, exclude=list(args.exclude) + cfg.exclude,
        security_email=_resolve_email(args),
        scan_tests=bool(args.scan_tests or cfg.scan_tests),
        custom_rules=cfg.custom_rules, **extra)


def _run_scan(ctx: RepoContext, only, skip, baseline=None, cfg=None) -> List[Finding]:
    findings: List[Finding] = []
    for _name, fn in enabled_scanners(only, skip):
        try:
            findings.extend(fn(ctx))
        except Exception as exc:  # noqa: BLE001 — one scanner must not kill the run
            # Recorded, not just printed: a crashed scanner means "unknown", never
            # "clean", so the CLI exits non-zero instead of letting a gate pass.
            ctx.errors.append(f"scanner '{_name}' failed: {exc}")
            print(f"error: scanner '{_name}' failed: {exc}", file=sys.stderr)
    if cfg is not None:
        findings = config_mod.apply_overrides(findings, cfg)
    findings, counts = suppress.apply(ctx, findings, baseline)
    if counts["inline"] or counts["baseline"]:
        # stderr, so machine-readable stdout stays clean.
        print(f"note: suppressed {counts['inline']} inline and "
              f"{counts['baseline']} baseline finding(s).", file=sys.stderr)
    return findings


def _threshold_hit(findings, fail_on: str) -> bool:
    threshold = Severity(fail_on).rank
    return any(f.severity.rank >= threshold for f in findings)


def cmd_scan(args) -> int:
    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"error: target is not a directory: {root}", file=sys.stderr)
        return 2
    cfg = _load_config(args, root)
    ctx = _make_context(args, root, cfg, use_osv=args.osv)
    baseline = suppress.load_baseline(args.baseline) if args.baseline else None
    findings = _run_scan(ctx, args.only or cfg.only, args.skip or cfg.skip,
                         baseline, cfg)
    fail_on = args.fail_on or cfg.fail_on
    if args.write_baseline:
        n = suppress.write_baseline(args.write_baseline, findings)
        print(f"wrote baseline with {n} finding(s) to {args.write_baseline}",
              file=sys.stderr)
        return 0
    # Non-fatal notes (e.g. OSV unreachable) go to stderr so they never corrupt
    # machine-readable output on stdout (SARIF / JSON).
    for note in ctx.notes:
        print(f"note: {note}", file=sys.stderr)

    fmt = args.format
    rendered = {
        "console": report.console,
        "markdown": report.markdown,
        "sarif": report.sarif,
        "json": report.as_json,
        "html": report.html_report,
    }[fmt](findings, str(root))

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        if fmt != "console":
            print(f"wrote {fmt} report to {args.output}")
        else:
            print(rendered)
    else:
        print(rendered)

    if ctx.errors:
        print(f"error: {len(ctx.errors)} scanner(s) failed; the result is "
              "incomplete.", file=sys.stderr)
        return 2
    if args.osv_required and ctx.osv_failed:
        print("error: --osv-required was set but CVE lookup did not complete.",
              file=sys.stderr)
        return 2
    if fail_on and _threshold_hit(findings, fail_on):
        return 1
    return 0


def cmd_fix(args) -> int:
    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"error: target is not a directory: {root}", file=sys.stderr)
        return 2
    cfg = _load_config(args, root)
    ctx = _make_context(args, root, cfg)
    baseline = suppress.load_baseline(args.baseline) if args.baseline else None
    findings = _run_scan(ctx, args.only or cfg.only, args.skip or cfg.skip,
                         baseline, cfg)
    actions = apply_fixes(root, findings, dry_run=args.dry_run)

    pins = []
    if args.pin_actions:
        pins = pin_mod.pin_workflows(ctx, dry_run=args.dry_run)

    if args.summary:
        Path(args.summary).write_text(
            _fix_summary_md(actions, findings, pins), encoding="utf-8"
        )

    for r in pins:
        for action, ref, why in r.skipped:
            print(f"note: could not pin {action}@{ref} in {r.path}: {why}",
                  file=sys.stderr)

    refused = [(p, a) for p, a in actions if a.startswith("skipped")]
    actions = [(p, a) for p, a in actions if not a.startswith("skipped")]
    for path, why in refused:
        print(f"warning: {path}: {why}", file=sys.stderr)

    pinned_total = sum(len(r.pinned) for r in pins)
    if not actions and not pinned_total:
        print("No machine-applicable fixes available.")
        # Signal "nothing to do" so CI can skip opening an empty PR.
        if ctx.errors:
            return 2
        return 0 if not args.require_changes else 3

    verb = "Planned" if args.dry_run else "Applied"
    n_fixes = len(actions) + sum(1 for r in pins if r.changed)
    print(f"{verb} {n_fixes} fix(es):")
    for path, action in actions:
        print(f"  {action}: {path}")
    for r in pins:
        if r.changed:
            what = "would pin" if args.dry_run else "pinned"
            print(f"  {what} {len(r.pinned)} action(s) to commit SHAs: {r.path}")
            for action, ref, sha in r.pinned:
                print(f"      {action}@{ref} -> {sha[:12]}")
    if args.dry_run:
        print("\n(dry run — nothing was written; re-run without --dry-run to apply)")
    return 2 if ctx.errors else 0


def _fix_summary_md(actions, findings, pins=()) -> str:
    from .remediate import applicable
    by_path = {(f.fix_path or f.file): f for f in applicable(findings)}
    changed_pins = [r for r in pins if r.changed]
    total = len(actions) + len(changed_pins)
    lines = ["## 🛡️ BlackByte Hardener — automated hardening", ""]
    if not total:
        lines.append("No machine-applicable fixes were needed. ✅")
        return "\n".join(lines) + "\n"
    lines.append(
        f"This PR applies **{total}** hardening fix(es) that BlackByte "
        "Hardener can make automatically:\n"
    )
    for path, action in actions:
        f = by_path.get(path)
        if f:
            lines.append(f"- **{action.capitalize()} `{path}`** — {f.title} "
                         f"(`{f.rule_id}`)")
        else:
            lines.append(f"- **{action.capitalize()} `{path}`**")
    for r in changed_pins:
        lines.append(f"- **Pinned {len(r.pinned)} action(s) to commit SHAs in "
                     f"`{r.path}`** (`CI_ACTION_UNPINNED`)")
        for action, ref, sha in r.pinned:
            lines.append(f"  - `{action}@{ref}` → `{sha[:12]}…`")
    lines.append("")
    lines.append("Review the diff before merging. Findings that need human "
                 "judgment (secrets to rotate, Dockerfile/CI changes) are reported "
                 "in the scan but intentionally not auto-applied.")
    lines.append("")
    lines.append("<sub>Generated by BlackByte Hardener.</sub>")
    return "\n".join(lines) + "\n"


def cmd_sbom(args) -> int:
    root = Path(args.target).resolve()
    if not root.is_dir():
        print(f"error: target is not a directory: {root}", file=sys.stderr)
        return 2
    cfg = _load_config(args, root)
    ctx = _make_context(args, root, cfg)
    vulns = None
    if args.osv:
        from . import osv as osv_mod
        from .scanners.dependencies import _collect_packages
        try:
            vulns = osv_mod.query(list(_collect_packages(ctx)))
        except osv_mod.OSVUnavailable as exc:
            print(f"note: CVE lookup skipped (could not reach api.osv.dev: {exc}); "
                  "the SBOM has no vulnerabilities section.", file=sys.stderr)
            if args.osv_required:
                return 2
    doc = sbom_mod.build(ctx, vulns)
    rendered = sbom_mod.render(doc)
    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        print(f"wrote CycloneDX SBOM ({len(doc['components'])} components) to {args.output}")
    else:
        print(rendered, end="")
    if not doc["components"]:
        print("note: no exact-version dependencies found (commit a lockfile for a "
              "complete SBOM).", file=sys.stderr)
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="bbharden",
        description="BlackByte Hardener — defensive repo hardening & auto-remediation.",
    )
    p.add_argument("--version", action="version",
                   version=f"bbharden {__version__}")
    sub = p.add_subparsers(dest="command", required=True)

    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("target", nargs="?", default=".",
                        help="path to the repository (default: .)")
    common.add_argument("--only", nargs="*", metavar="SCANNER",
                        help="run only these scanners")
    common.add_argument("--skip", nargs="*", metavar="SCANNER",
                        help="skip these scanners")
    common.add_argument("--security-email", metavar="EMAIL",
                        help="contact address for a generated SECURITY.md "
                             "(or set $BBHARDEN_SECURITY_EMAIL); without it, "
                             "SECURITY.md is reported but not auto-created")
    common.add_argument("--baseline", metavar="FILE",
                        help="hide the findings recorded in this baseline file "
                             "(see `scan --write-baseline`)")
    common.add_argument("--scan-tests", action="store_true",
                        help="also scan test/fixture/example paths for secrets "
                             "(skipped by default; they usually hold fake keys)")
    common.add_argument("--config", metavar="FILE",
                        help="policy file (default: ./.bbharden.toml if present)")
    common.add_argument("--no-config", action="store_true",
                        help="ignore any .bbharden.toml (use when auditing a "
                             "repository you do not own)")
    common.add_argument("--exclude", action="append", default=[], metavar="GLOB",
                        help="leave paths out of the scan (repeatable), e.g. "
                             "--exclude examples --exclude 'docs/*.md'")

    s = sub.add_parser("scan", parents=[common], help="scan and report")
    s.add_argument("--format", choices=["console", "markdown", "sarif", "json", "html"],
                   default="console")
    s.add_argument("--output", "-o", help="write the report to a file")
    s.add_argument("--fail-on", choices=_SEV_ORDER, default=None,
                   help="exit non-zero if a finding at or above this severity exists")
    s.add_argument("--osv", action="store_true",
                   help="match pinned dependencies against OSV.dev for known CVEs "
                        "(needs network; sends package names+versions only)")
    s.add_argument("--osv-required", action="store_true",
                   help="with --osv: exit 2 if the CVE lookup could not complete "
                        "(default: continue and print a note)")
    s.add_argument("--write-baseline", metavar="FILE",
                   help="record today's findings as accepted and exit 0; later "
                        "runs with --baseline FILE then fail only on NEW findings")
    s.set_defaults(func=cmd_scan)

    b = sub.add_parser("sbom", parents=[common],
                       help="write a CycloneDX 1.5 SBOM (JSON)")
    b.add_argument("--output", "-o", help="write the SBOM to a file (default: stdout)")
    b.add_argument("--osv", action="store_true",
                   help="add a vulnerabilities section from OSV.dev (needs network)")
    b.add_argument("--osv-required", action="store_true",
                   help="with --osv: exit 2 if the lookup could not complete")
    b.set_defaults(func=cmd_sbom)

    f = sub.add_parser("fix", parents=[common],
                       help="apply machine-applicable fixes")
    f.add_argument("--dry-run", action="store_true",
                   help="show what would change without writing")
    f.add_argument("--summary", metavar="PATH",
                   help="write a markdown summary of the changes (for PR bodies)")
    f.add_argument("--pin-actions", action="store_true",
                   help="pin GitHub Actions in .github/workflows to commit SHAs "
                        "(resolved read-only via `git ls-remote`; needs network). "
                        "NB: a workflow-modifying PR needs a PAT, not GITHUB_TOKEN")
    f.add_argument("--require-changes", action="store_true",
                   help="exit 3 when there is nothing to fix (lets CI skip the PR)")
    f.set_defaults(func=cmd_fix)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
