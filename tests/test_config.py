import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bbharden import config
from bbharden.context import RepoContext
from bbharden.findings import Finding, Severity
from bbharden.scanners import custom

ROOT = Path(__file__).resolve().parent.parent
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"


def w(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def cli(*args):
    return subprocess.run([sys.executable, "-m", "bbharden.cli", *args],
                          capture_output=True, text=True, cwd=ROOT)


class TestParse(unittest.TestCase):
    def test_full_document(self):
        cfg = config.parse({
            "scan": {"fail_on": "HIGH", "exclude": ["examples"], "scan_tests": True,
                     "skip": ["dependencies"]},
            "rules": {"CI_ACTION_UNPINNED": {"severity": "low"},
                      "HYGIENE_NO_DEPENDABOT": {"severity": "off"}},
            "custom_rule": [{"id": "ACME_HOST", "title": "t", "pattern": r"corp\.internal",
                             "severity": "medium", "files": ["*.py"]}],
        }, known_scanners={"dependencies", "secrets"})
        self.assertEqual(cfg.fail_on, "high")
        self.assertEqual(cfg.overrides["CI_ACTION_UNPINNED"], Severity.LOW)
        self.assertIsNone(cfg.overrides["HYGIENE_NO_DEPENDABOT"])
        self.assertEqual(cfg.custom_rules[0].id, "ACME_HOST")

    def test_rejects_typos_and_bad_values(self):
        bad = [
            {"scna": {}},                                         # unknown top-level
            {"scan": {"fail_o": "high"}},                         # unknown key
            {"scan": {"fail_on": "urgent"}},
            {"scan": {"exclude": "examples"}},                    # not a list
            {"scan": {"skip": ["nope"]}},                         # unknown scanner
            {"rules": {"X": {"severity": "loud"}}},
            {"rules": {"X": {}}},
            {"custom_rule": [{"id": "lower", "title": "t", "pattern": "x", "severity": "low"}]},
            {"custom_rule": [{"id": "ABC", "title": "t", "pattern": "(", "severity": "low"}]},
            {"custom_rule": [{"id": "ABC", "title": "t", "pattern": "x*", "severity": "low"}]},
            {"custom_rule": [{"id": "ABC", "title": "t", "severity": "low"}]},
        ]
        for doc in bad:
            with self.assertRaises(config.ConfigError, msg=str(doc)):
                config.parse(doc, known_scanners={"dependencies"})

    def test_custom_id_cannot_shadow_builtin_or_repeat(self):
        rule = {"id": "SECRET_JWT", "title": "t", "pattern": "x", "severity": "low"}
        with self.assertRaises(config.ConfigError):
            config.parse({"custom_rule": [rule]}, known_rules={"SECRET_JWT"})
        dup = {"id": "ABC", "title": "t", "pattern": "x", "severity": "low"}
        with self.assertRaises(config.ConfigError):
            config.parse({"custom_rule": [dup, dup]})

    def test_apply_overrides(self):
        mk = lambda rid, sev: Finding(rid, "t", sev, "f", 1, "m", "r")
        cfg = config.parse({"rules": {"A_B": {"severity": "low"}, "C_D": {"severity": "off"}}})
        out = config.apply_overrides([mk("A_B", Severity.HIGH), mk("C_D", Severity.HIGH),
                                      mk("E_F", Severity.HIGH)], cfg)
        self.assertEqual([(f.rule_id, f.severity) for f in out],
                         [("A_B", Severity.LOW), ("E_F", Severity.HIGH)])


class TestLoad(unittest.TestCase):
    def test_missing_file_is_defaults_and_symlink_is_ignored(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as o:
            self.assertIsNone(config.load(Path(d)).path)
            w(o, "real.toml", '[scan]\nfail_on = "low"\n')
            (Path(d) / ".bbharden.toml").symlink_to(Path(o) / "real.toml")
            self.assertIsNone(config.load(Path(d)).path)

    def test_disabled_and_invalid_toml(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, ".bbharden.toml", "this is = = not toml")
            self.assertIsNone(config.load(Path(d), disabled=True).path)
            with self.assertRaises(config.ConfigError):
                config.load(Path(d))


class TestCustomScanner(unittest.TestCase):
    def _scan(self, toml, files):
        with tempfile.TemporaryDirectory() as d:
            for rel, text in files.items():
                w(d, rel, text)
            cfg = config.parse(__import__("tomllib").loads(toml))
            ctx = RepoContext(root=Path(d), custom_rules=cfg.custom_rules)
            return sorted((f.rule_id, f.file, f.line, f.evidence) for f in custom.scan(ctx))

    RULE = ('[[custom_rule]]\nid="ACME_HOST"\ntitle="t"\npattern=\'corp\\.internal\'\n'
            'severity="medium"\n')

    def test_files_globs(self):
        files = {"a.py": "x = 'db.corp.internal'\n", "b.txt": "db.corp.internal\n",
                 "src/c.js": "db.corp.internal\n"}
        self.assertEqual({f[1] for f in self._scan(self.RULE, files)},
                         {"a.py", "b.txt", "src/c.js"})
        self.assertEqual({f[1] for f in self._scan(self.RULE + 'files=["*.py"]\n', files)},
                         {"a.py"})
        self.assertEqual({f[1] for f in self._scan(self.RULE + 'files=["src/**"]\n', files)},
                         {"src/c.js"})

    def test_redact_and_long_lines(self):
        got = self._scan(self.RULE.replace("corp", "tok") .replace("\\.internal", "[a-z]{8}")
                         + "redact=true\n", {"a.txt": "tokenabcdefgh\n"})
        self.assertNotIn("abcdefgh", got[0][3])
        self.assertEqual(self._scan(self.RULE, {"a.txt": "x" * 3000 + "corp.internal\n"}), [])

    def test_inline_ignore_works_for_custom_rules(self):
        from bbharden import suppress
        with tempfile.TemporaryDirectory() as d:
            w(d, "a.py", "h = 'db.corp.internal'  # bbharden:ignore ACME_HOST\n")
            cfg = config.parse(__import__("tomllib").loads(self.RULE))
            ctx = RepoContext(root=Path(d), custom_rules=cfg.custom_rules)
            kept, counts = suppress.apply(ctx, list(custom.scan(ctx)))
        self.assertEqual((kept, counts["inline"]), ([], 1))


class TestCli(unittest.TestCase):
    def test_policy_is_applied_announced_and_overridable(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "a.py", f'k = "{AWS}"\n')
            w(d, ".bbharden.toml",
              '[scan]\nfail_on = "high"\n[rules.SECRET_AWS_AKID]\nseverity = "low"\n')
            r = cli("scan", d, "--only", "secrets")
            self.assertEqual(r.returncode, 0, r.stderr)           # downgraded below fail_on
            self.assertIn("using policy", r.stderr)
            self.assertIn("LOW", r.stdout)
            # CLI beats file
            self.assertEqual(cli("scan", d, "--only", "secrets", "--fail-on", "low").returncode, 1)
            # --no-config: original severity, no announcement
            r = cli("scan", d, "--only", "secrets", "--no-config", "--fail-on", "high")
            self.assertEqual(r.returncode, 1)
            self.assertNotIn("using policy", r.stderr)

    def test_rule_off_cannot_hide_findings_when_no_config(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "a.py", f'k = "{AWS}"\n')
            w(d, ".bbharden.toml", '[rules.SECRET_AWS_AKID]\nseverity = "off"\n')
            self.assertEqual(cli("scan", d, "--only", "secrets", "--fail-on", "low").returncode, 0)
            self.assertEqual(cli("scan", d, "--only", "secrets", "--fail-on", "low",
                                 "--no-config").returncode, 1)

    def test_invalid_policy_exits_2(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, ".bbharden.toml", '[scan]\nfailon = "high"\n')
            r = cli("scan", d)
            self.assertEqual(r.returncode, 2)
            self.assertIn("unknown key", r.stderr)

    def test_custom_rule_end_to_end_and_exclude_union(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "a.py", "h = 'db.corp.internal'\n")
            w(d, "skip/b.py", "h = 'db.corp.internal'\n")
            w(d, ".bbharden.toml",
              '[scan]\nexclude = ["skip"]\n[[custom_rule]]\nid="ACME_HOST"\ntitle="Internal host"\n'
              'pattern=\'corp\\.internal\'\nseverity="high"\n')
            r = cli("scan", d, "--only", "custom", "--format", "json", "--fail-on", "high")
            self.assertEqual(r.returncode, 1)
            self.assertIn("ACME_HOST", r.stdout)
            self.assertEqual(r.stdout.count('"file"'), 1)         # skip/ excluded by policy


if __name__ == "__main__":
    unittest.main()
