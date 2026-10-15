"""v0.5.0: regressions for fixed scanner bugs, suppressions, SHA pinning."""

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bbharden import pin, suppress
from bbharden.context import RepoContext
from bbharden.scanners import dockerfile, secrets, workflows

ROOT = Path(__file__).resolve().parent.parent
SHA = "a" * 40


def _write(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def _aws() -> str:  # assembled at runtime; never committed as a literal
    return "AKIA" + "ABCDEFGHIJKLMNOP"


class TestSecretsPathMatching(unittest.TestCase):
    def test_latest_and_contest_dirs_are_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            for sub in ("latest", "contest", "attestation"):
                _write(root, f"{sub}/cfg.py", f'k = "{_aws()}"\n')
            files = {f.file for f in secrets.scan(RepoContext(root=root))}
        self.assertEqual(len(files), 3)

    def test_real_test_dirs_skipped_unless_opted_in(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "tests/a.py", f'k = "{_aws()}"\n')
            _write(root, "src/test_b.py", f'k = "{_aws()}"\n')
            self.assertEqual(list(secrets.scan(RepoContext(root=root))), [])
            found = list(secrets.scan(RepoContext(root=root, scan_tests=True)))
        self.assertEqual(len(found), 2)


class TestDockerfileBaseImages(unittest.TestCase):
    def _rules(self, text):
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), "Dockerfile", text)
            return [f for f in dockerfile.scan(RepoContext(root=Path(d)))
                    if f.rule_id == "DOCKER_LATEST_TAG"]

    def test_scratch_stage_alias_digest_and_unknown_arg_are_fine(self):
        text = ("ARG BASE\nFROM python:3.12 AS build\nFROM build AS test\n"
                "FROM scratch\nFROM ${BASE}\n"
                f"FROM alpine@sha256:{'b' * 64}\nUSER app\n")
        self.assertEqual(self._rules(text), [])

    def test_untagged_multistage_and_latest_arg_default_flagged(self):
        self.assertEqual(len(self._rules("FROM node AS build\nUSER app\n")), 1)
        self.assertEqual(len(self._rules("ARG B=ubuntu:latest\nFROM ${B}\nUSER a\n")), 1)

    def test_registry_port_is_not_a_tag(self):
        self.assertEqual(len(self._rules("FROM localhost:5000/img\nUSER a\n")), 1)
        self.assertEqual(self._rules("FROM localhost:5000/img:1.2\nUSER a\n"), [])


class TestWorkflowPermissions(unittest.TestCase):
    def _ids(self, text):
        with tempfile.TemporaryDirectory() as d:
            _write(Path(d), ".github/workflows/ci.yml", text)
            return {f.rule_id for f in workflows.scan(RepoContext(root=Path(d)))}

    def test_missing_permissions_flagged(self):
        self.assertIn("CI_NO_PERMISSIONS", self._ids("on: push\njobs:\n  a:\n    steps: []\n"))

    def test_top_or_job_level_permissions_ok(self):
        self.assertNotIn("CI_NO_PERMISSIONS",
                         self._ids("on: push\npermissions:\n  contents: read\njobs: {}\n"))
        self.assertNotIn("CI_NO_PERMISSIONS",
                         self._ids("on: push\njobs:\n  a:\n    permissions:\n      contents: read\n"))


class TestSuppress(unittest.TestCase):
    def _findings(self, root):
        ctx = RepoContext(root=root)
        return ctx, list(secrets.scan(ctx))

    def test_inline_same_line_and_next_line(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "a.py", f'k = "{_aws()}"  # bbharden:ignore SECRET_AWS_AKID\n')
            _write(root, "b.py", f'# bbharden:ignore-next-line\nk = "{_aws()}"\n')
            _write(root, "c.py", f'k = "{_aws()}"  # bbharden:ignore OTHER_RULE\n')
            ctx, fs = self._findings(root)
            kept, counts = suppress.apply(ctx, fs)
        self.assertEqual(counts["inline"], 2)
        self.assertEqual([f.file for f in kept], ["c.py"])

    def test_baseline_roundtrip_ignores_line_shifts_and_flags_new(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "a.py", f'k = "{_aws()}"\n')
            ctx, fs = self._findings(root)
            bl = root / "bl.json"
            suppress.write_baseline(str(bl), fs)
            # shift the finding down a line and add a brand-new one
            _write(root, "a.py", f'\nk = "{_aws()}"\n')
            _write(root, "new.py", f'k = "{_aws()}"\n')
            ctx, fs = self._findings(root)
            kept, counts = suppress.apply(ctx, fs, suppress.load_baseline(str(bl)))
        self.assertEqual(counts["baseline"], 1)
        self.assertEqual([f.file for f in kept], ["new.py"])

    def test_bad_baseline_exits(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "x.json"
            p.write_text(json.dumps({"version": 99}))
            with self.assertRaises(SystemExit):
                suppress.load_baseline(str(p))


class TestPin(unittest.TestCase):
    def test_resolve_prefers_peeled_tag(self):
        lines = [f"{'1' * 40}\trefs/tags/v3", f"{'2' * 40}\trefs/tags/v3^{{}}"]
        self.assertEqual(pin.resolve_sha("o/r", "v3", lambda u, p: lines), "2" * 40)

    def test_resolve_none_when_missing_and_passthrough_sha(self):
        self.assertIsNone(pin.resolve_sha("o/r", "v9", lambda u, p: []))
        self.assertEqual(pin.resolve_sha("o/r", SHA, lambda u, p: 1 / 0), SHA)

    def test_pin_text_rewrites_keeps_comment_and_skips_pinned(self):
        text = ("steps:\n"
                "  - uses: actions/checkout@v4\n"
                f"  - uses: a/b/sub@{SHA}\n"
                "  - uses: x/y@main # keep me\n"
                "  - uses: ./local\n"
                "  - uses: gone/away@v1\n"
                "  # - uses: commented/out@v1\n")
        table = {("actions/checkout", "v4"): "c" * 40, ("x/y", "main"): "d" * 40}
        new, pinned, skipped = pin.pin_text(text, lambda r, ref: table.get((r, ref)))
        self.assertIn(f"actions/checkout@{'c' * 40}  # v4", new)
        self.assertIn(f"x/y@{'d' * 40} # keep me", new)
        self.assertIn("uses: ./local", new)
        self.assertIn("commented/out@v1", new)
        self.assertEqual(len(pinned), 2)
        self.assertEqual([s[0] for s in skipped], ["gone/away"])

    def test_pin_workflows_dry_run_does_not_write_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = _write(root, ".github/workflows/ci.yml", "- uses: a/b@v1\n")
            ctx = RepoContext(root=root)
            res = pin.pin_workflows(ctx, dry_run=True, resolve=lambda r, ref: "e" * 40)
            self.assertTrue(res[0].changed)
            self.assertEqual(p.read_text(), "- uses: a/b@v1\n")
            pin.pin_workflows(ctx, resolve=lambda r, ref: "e" * 40)
            again = pin.pin_workflows(ctx, resolve=lambda r, ref: 1 / 0)
            self.assertEqual(again, [])

    def test_lookup_failure_leaves_file_untouched(self):
        def boom(r, ref):
            raise OSError("offline")
        text = "- uses: a/b@v1\n"
        new, pinned, skipped = pin.pin_text(text, boom)
        self.assertEqual(new, text)
        self.assertEqual(pinned, [])
        self.assertIn("offline", skipped[0][2])


class TestCLI(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run([sys.executable, "-m", "bbharden.cli", *args],
                              capture_output=True, text=True, cwd=ROOT)

    def test_write_baseline_then_scan_passes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            _write(root, "a.py", f'k = "{_aws()}"\n')
            bl = str(root / "bl.json")
            r = self._run("scan", str(root), "--write-baseline", bl)
            self.assertEqual(r.returncode, 0, r.stderr)
            bad = self._run("scan", str(root), "--fail-on", "high",
                            "--only", "secrets")
            self.assertNotEqual(bad.returncode, 0)
            ok = self._run("scan", str(root), "--fail-on", "high",
                           "--only", "secrets", "--baseline", bl)
            self.assertEqual(ok.returncode, 0, ok.stdout + ok.stderr)


if __name__ == "__main__":
    unittest.main()
