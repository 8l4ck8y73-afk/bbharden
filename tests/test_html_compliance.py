import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bbharden import compliance, report
from bbharden.findings import Finding, Severity

ROOT = Path(__file__).resolve().parent.parent


def f(**kw):
    base = dict(rule_id="SECRET_AWS_AKID", title="AWS key", severity=Severity.CRITICAL,
                file="a/b.py", line=3, message="m `code` here", remediation="fix `x`",
                evidence="AKI…LE (20 chars)", cwe="CWE-798")
    base.update(kw)
    return Finding(**base)


class TestHtml(unittest.TestCase):
    def test_hostile_text_is_inert(self):
        evil = '<script>alert(1)</script><img src=x onerror=alert(1)>"\'&'
        out = report.html_report([f(title=evil, file=evil, message=evil, remediation=evil,
                                    evidence=evil, rule_id="X_Y")], "/tmp/<b>repo")
        body = out.split("</style>", 1)[1]
        self.assertNotIn("<script", body.lower())
        self.assertNotIn("<img", body.lower())
        self.assertNotIn("onerror=alert", body.replace("&lt;", "").replace("&quot;", "")
                         .split("onerror=alert")[0] + "")  # only inside escaped text
        self.assertIn("&lt;script&gt;", body)
        self.assertNotIn("<b>repo", out)

    def test_is_self_contained_with_csp_and_no_scripts_or_remote_urls(self):
        out = report.html_report([f()], "repo")
        self.assertIn("Content-Security-Policy", out)
        self.assertIn("default-src 'none'", out)
        self.assertIsNone(re.search(r"<script|<link|<iframe|src=\"http|href=\"http", out, re.I))

    def test_terminal_and_bidi_characters_removed(self):
        out = report.html_report([f(evidence="a\x1b[31mb‮c")], "repo")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("‮", out)

    def test_code_spans_rendered_but_only_after_escaping(self):
        out = report.html_report([f(message="use `<b>x</b>` now")], "repo")
        self.assertIn("<code>&lt;b&gt;x&lt;/b&gt;</code>", out)

    def test_target_shown_as_basename_not_full_path(self):
        out = report.html_report([f()], "/home/secret-user/clients/acme")
        self.assertIn("acme", out)
        self.assertNotIn("secret-user", out)

    def test_empty_and_grouping(self):
        self.assertIn("No findings", report.html_report([], "r"))
        many = [f(line=i) for i in range(1, 60)]
        out = report.html_report(many, "r")
        self.assertEqual(out.count("<details>"), 1)
        self.assertIn("+ 9 more", out)

    def test_cli_html_format(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / "a.py").write_text('k = "' + "AKIA" + 'ABCDEFGHIJKLMNOP"\n')
            r = subprocess.run([sys.executable, "-m", "bbharden.cli", "scan", d, "--no-config",
                                "--only", "secrets", "--format", "html"],
                               capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(r.stdout.startswith("<!doctype html>"))
        self.assertIn("CICD-SEC-6", r.stdout)


class TestCompliance(unittest.TestCase):
    def _rule_ids_in_source(self):
        ids = set()
        for p in (ROOT / "bbharden" / "scanners").glob("*.py"):
            ids |= set(re.findall(r'"((?:SECRET|DOCKER|K8S|COMPOSE|TF|CI|DEP|HYGIENE)_[A-Z0-9_]+)"',
                                  p.read_text()))
        ids -= {"SECRET_*"}
        return ids

    def test_every_builtin_rule_has_a_mapping(self):
        ids = self._rule_ids_in_source()
        self.assertGreater(len(ids), 40)
        missing = sorted(i for i in ids if not compliance.references(i))
        self.assertEqual(missing, [])

    def test_unknown_and_custom_rules_have_none(self):
        self.assertEqual(compliance.references("ACME_HOST"), [])

    def test_json_and_sarif_carry_references_and_disclaimer(self):
        j = json.loads(report.as_json([f()], "."))
        self.assertIn("CICD-SEC-6", " ".join(j["findings"][0]["references"]))
        self.assertIn("not a statement of compliance", j["references_note"])
        s = json.loads(report.sarif([f()], "."))
        tags = s["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["tags"]
        self.assertTrue(any("A.5.17" in t for t in tags))

    def test_no_claim_of_compliance_in_any_mapping_text(self):
        text = " ".join(" ".join(v) for v in compliance._MAP.values()).lower()
        for bad in ("compliant", "certified", "guarantee"):
            self.assertNotIn(bad, text)


if __name__ == "__main__":
    unittest.main()
