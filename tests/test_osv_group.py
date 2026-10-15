import json
import tempfile
import unittest
from pathlib import Path

from bbharden import report
from bbharden.context import RepoContext
from bbharden.findings import Severity
from bbharden.osv import Vuln
from bbharden.scanners import dependencies

SEVS = [Severity.CRITICAL, Severity.HIGH, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


def lookup(pkgs):
    out = {}
    for p in pkgs:
        if p[1] == "django":
            out[p] = [Vuln(f"GHSA-{i}", f"bug <b>{i}</b>", [f"CVE-2026-{i}"], SEVS[i % 5],
                           None if i == 7 else f"4.2.{10 + i}") for i in range(12)]
        elif p[1] == "one":
            out[p] = [Vuln("GHSA-x", "s", ["CVE-1"], Severity.HIGH, "2.0")]
    return out


def scan(detail=False):
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / "requirements.txt").write_text("django==4.2.1\none==1.0\nsafe==1.0\n")
        ctx = RepoContext(root=Path(d), use_osv=True, osv_query=lookup, osv_detail=detail)
        return [f for f in dependencies.scan(ctx) if f.rule_id == "DEP_KNOWN_VULN"]


class TestGroup(unittest.TestCase):
    def test_one_finding_per_package(self):
        fs = scan()
        self.assertEqual(len(fs), 2)
        g = next(f for f in fs if "django" in f.evidence)
        self.assertEqual(g.severity, Severity.CRITICAL)
        self.assertIn("12 known vulnerabilities", g.title)
        self.assertIn("3 critical", g.title)
        self.assertIn("4.2.21", g.remediation)          # highest fix
        self.assertIn("1 advisory(ies) list no fix", g.remediation)
        self.assertEqual(len(g.details), 12)
        self.assertEqual(g.details[0]["severity"], "critical")   # sorted worst first
        self.assertIn("+4 more", g.message)

    def test_single_advisory_keeps_classic_form(self):
        one = next(f for f in scan() if "one" in f.evidence)
        self.assertIn("(CVE-1)", one.title)
        self.assertIsNone(one.details)

    def test_detail_flag_restores_per_advisory(self):
        self.assertEqual(len(scan(detail=True)), 13)

    def test_json_carries_details_and_omits_when_absent(self):
        j = json.loads(report.as_json(scan(), "."))
        has = [x for x in j["findings"] if "details" in x]
        self.assertEqual(len(has), 1)
        self.assertEqual(len(has[0]["details"]), 12)

    def test_html_lists_advisories_escaped(self):
        out = report.html_report(scan(), "r")
        self.assertIn("CVE-2026-0", out)
        self.assertIn("&lt;b&gt;0&lt;/b&gt;", out)
        self.assertNotIn("<b>0</b>", out)


if __name__ == "__main__":
    unittest.main()
