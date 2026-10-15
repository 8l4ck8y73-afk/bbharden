"""BlackByte Hardener CLI."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import List

from . import __version__, report
from .context import RepoContext
from .findings import Finding, Severity
from .remediate import apply as apply_fixes
from .scanners import enabled_scanners

_SEV_ORDER = [s.value for s in Severity]


def _run_scan(ctx: RepoContext, only, skip) -> List[Finding]:
    findings: List[Finding] = []
    for _name, fn in enabled_scanners(only, skip):
        try:
            findings.extend(fn(ctx))
        except Exception as exc:  # noqa: BLE001 — one scanner must not kill the run
            print(f"warning: scanner '{_name}' failed: {exc}", file=sys.stderr)
    return findings


def _threshold_hit(findings, fail_on: str) -> bool:
    threshold = Severity(fail_on).rank
    return any(f.severity.rank >= threshold for f in findings)


def cmd_scan(args) -> int:
    root = Path(args.target).resolve()
    if not root.exists():
        print(f"error: target not found: {root}", file=sys.stderr)
        return 2
    ctx = RepoContext(root=root)
    findings = _run_scan(ctx, args.only, args.skip)

    fmt = args.format
    rendered = {
        "console": report.console,
        "markdown": report.markdown,
        "sarif": report.sarif,
        "json": report.as_json,
    }[fmt](findings, str(root))

    if args.output:
        Path(args.output).write_text(rendered, encoding="utf-8")
        if fmt != "console":
            print(f"wrote {fmt} report to {args.output}")
        else:
            print(rendered)
    else:
        print(rendered)

    if args.fail_on and _threshold_hit(findings, args.fail_on):
        return 1
    return 0


def cmd_fix(args) -> int:
    root = Path(args.target).resolve()
    ctx = RepoContext(root=root)
    findings = _run_scan(ctx, args.only, args.skip)
    actions = apply_fixes(root, findings, dry_run=args.dry_run)
    if not actions:
        print("No machine-applicable fixes available.")
        return 0
    verb = "Planned" if args.dry_run else "Applied"
    print(f"{verb} {len(actions)} fix(es):")
    for path, action in actions:
        print(f"  {action}: {path}")
    if args.dry_run:
        print("\n(dry run — nothing was written; re-run without --dry-run to apply)")
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

    s = sub.add_parser("scan", parents=[common], help="scan and report")
    s.add_argument("--format", choices=["console", "markdown", "sarif", "json"],
                   default="console")
    s.add_argument("--output", "-o", help="write the report to a file")
    s.add_argument("--fail-on", choices=_SEV_ORDER, default=None,
                   help="exit non-zero if a finding at or above this severity exists")
    s.set_defaults(func=cmd_scan)

    f = sub.add_parser("fix", parents=[common],
                       help="apply machine-applicable fixes")
    f.add_argument("--dry-run", action="store_true",
                   help="show what would change without writing")
    f.set_defaults(func=cmd_fix)

    return p


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
