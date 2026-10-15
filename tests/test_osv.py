"""OSV integration tests — fully offline, using canned OSV-shaped responses."""

import tempfile
import unittest
from pathlib import Path

from bbharden import osv
from bbharden.context import RepoContext
from bbharden.findings import Severity
from bbharden.scanners import dependencies

# Shaped like a real OSV /v1/vulns/{id} record (GitHub advisory flavour).
_OSV_RECORD = {
    "id": "GHSA-xxxx-yyyy-zzzz",
    "aliases": ["CVE-2099-0001"],
    "summary": "Example remote code execution in demo-lib",
    "database_specific": {"severity": "CRITICAL"},
    "affected": [{
        "package": {"ecosystem": "PyPI", "name": "demo-lib"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "0"}, {"fixed": "2.5.1"}]}],
    }],
}


def _fake_post(url, payload):
    results = []
    for q in payload["queries"]:
        if q["package"]["name"] == "demo-lib" and q["version"] == "2.0.0":
            results.append({"vulns": [{"id": "GHSA-xxxx-yyyy-zzzz"}]})
        else:
            results.append({})
    return {"results": results}


def _fake_get(url):
    assert url.endswith("GHSA-xxxx-yyyy-zzzz")
    return _OSV_RECORD


def _fake_lookup(packages):
    return osv.query(packages, post=_fake_post, get=_fake_get)


class TestOsvClient(unittest.TestCase):
    def test_query_maps_vulns_to_packages(self):
        pkgs = [("PyPI", "demo-lib", "2.0.0"), ("PyPI", "safe-lib", "1.0.0")]
        res = osv.query(pkgs, post=_fake_post, get=_fake_get)
        self.assertEqual(len(res[pkgs[0]]), 1)
        self.assertEqual(res[pkgs[1]], [])
        v = res[pkgs[0]][0]
        self.assertEqual(v.cve, "CVE-2099-0001")
        self.assertEqual(v.severity, Severity.CRITICAL)
        self.assertEqual(v.fixed_in, "2.5.1")

    def test_severity_fallbacks(self):
        self.assertEqual(osv.severity_from_osv({}), Severity.MEDIUM)
        self.assertEqual(
            osv.severity_from_osv({"database_specific": {"severity": "MODERATE"}}),
            Severity.MEDIUM)
        self.assertEqual(
            osv.severity_from_osv({"severity": [{"type": "CVSS_V3", "score": "9.8"}]}),
            Severity.CRITICAL)
        # A CVSS *vector* string is not a number: must fall back, not crash.
        self.assertEqual(
            osv.severity_from_osv(
                {"severity": [{"type": "CVSS_V3",
                               "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}]}),
            Severity.MEDIUM)

    def test_no_network_raises_unavailable(self):
        def boom(url, payload):
            raise osv.OSVUnavailable("down")
        with self.assertRaises(osv.OSVUnavailable):
            osv.query([("PyPI", "x", "1.0.0")], post=boom)


class TestDependencyScannerOsv(unittest.TestCase):
    def _repo(self, requirements: str):
        d = tempfile.TemporaryDirectory()
        (Path(d.name) / "requirements.txt").write_text(requirements)
        return d

    def test_vulnerable_pinned_dep_is_reported(self):
        d = self._repo("demo-lib==2.0.0\nsafe-lib==1.0.0\n")
        with d:
            ctx = RepoContext(root=Path(d.name), use_osv=True, osv_query=_fake_lookup)
            vulns = [f for f in dependencies.scan(ctx) if f.rule_id == "DEP_KNOWN_VULN"]
        self.assertEqual(len(vulns), 1)
        f = vulns[0]
        self.assertEqual(f.severity, Severity.CRITICAL)
        self.assertIn("CVE-2099-0001", f.title)
        self.assertIn("2.5.1", f.remediation)
        self.assertEqual(f.evidence, "demo-lib==2.0.0")

    def test_ranges_are_never_sent_to_osv(self):
        d = self._repo("demo-lib>=2.0.0\nrequests\n")
        sent = []

        def spy(pkgs):
            sent.extend(pkgs)
            return {}

        with d:
            ctx = RepoContext(root=Path(d.name), use_osv=True, osv_query=spy)
            list(dependencies.scan(ctx))
        self.assertEqual(sent, [])  # ranges/unpinned must not be guessed

    def test_osv_off_by_default_makes_no_lookup(self):
        d = self._repo("demo-lib==2.0.0\n")
        called = []
        with d:
            ctx = RepoContext(root=Path(d.name), osv_query=lambda p: called.append(p))
            list(dependencies.scan(ctx))
        self.assertEqual(called, [])

    def test_unreachable_osv_degrades_with_note(self):
        d = self._repo("demo-lib==2.0.0\n")

        def down(pkgs):
            raise osv.OSVUnavailable("no route")

        with d:
            ctx = RepoContext(root=Path(d.name), use_osv=True, osv_query=down)
            findings = list(dependencies.scan(ctx))
        self.assertFalse(any(f.rule_id == "DEP_KNOWN_VULN" for f in findings))
        self.assertTrue(any("OSV lookup skipped" in n for n in ctx.notes))


if __name__ == "__main__":
    unittest.main()
