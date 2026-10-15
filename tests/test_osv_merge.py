import unittest

from bbharden import osv
from bbharden.findings import Severity
from bbharden.osv import Vuln, merge


class TestMerge(unittest.TestCase):
    def test_same_cve_across_databases_becomes_one(self):
        a = Vuln("GHSA-aaaa", "short", ["CVE-1"], Severity.LOW, "4.2.5")
        b = Vuln("PYSEC-1", "very long raw text", ["CVE-1"], Severity.MEDIUM, "4.2.7", severity_known=False)
        c = Vuln("GHSA-bbbb", "other", ["CVE-2"], Severity.HIGH, "4.2.3")
        m = merge([b, a, c])
        self.assertEqual(len(m), 2)
        one = next(v for v in m if v.cve == "CVE-1")
        self.assertEqual(one.id, "GHSA-aaaa")                 # GHSA preferred
        self.assertEqual(one.severity, Severity.LOW)           # known rating beats a default
        self.assertEqual(one.summary, "short")
        self.assertEqual(one.fixed_in, "4.2.7")                # highest fix covers all
        self.assertIn("PYSEC-1", one.aliases)

    def test_known_rating_takes_max_and_unknown_defaults_to_medium(self):
        m = merge([Vuln("PYSEC-9", "x", ["CVE-9"], Severity.MEDIUM, severity_known=False)])
        self.assertEqual((m[0].severity, m[0].severity_known), (Severity.MEDIUM, False))
        m = merge([Vuln("GHSA-1", "", ["CVE-9"], Severity.LOW), Vuln("GHSA-2", "", ["CVE-9"], Severity.CRITICAL)])
        self.assertEqual(m[0].severity, Severity.CRITICAL)

    def test_chain_merge_and_distinct_stay_distinct(self):
        m = merge([Vuln("A", aliases=["B"]), Vuln("C", aliases=["D"]), Vuln("B", aliases=["C"])])
        self.assertEqual(len(m), 1)
        self.assertEqual(len(merge([Vuln("A"), Vuln("B")])), 2)

    def test_empty_and_query_integration(self):
        self.assertEqual(merge([]), [])
        recs = {"GHSA-1": {"id": "GHSA-1", "aliases": ["CVE-1"], "summary": "s",
                           "database_specific": {"severity": "LOW"}},
                "PYSEC-1": {"id": "PYSEC-1", "aliases": ["CVE-1"], "summary": "long"}}
        post = lambda url, body: {"results": [{"vulns": [{"id": "PYSEC-1"}, {"id": "GHSA-1"}]}]}
        get = lambda url: recs[url.rsplit("/", 1)[-1]]
        r = osv.query([("PyPI", "django", "4.2.1")], post=post, get=get)
        v = r[("PyPI", "django", "4.2.1")]
        self.assertEqual((len(v), v[0].severity), (1, Severity.LOW))


if __name__ == "__main__":
    unittest.main()
