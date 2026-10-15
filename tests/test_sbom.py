import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bbharden import osv, sbom
from bbharden.context import RepoContext
from bbharden.findings import Severity

ROOT = Path(__file__).resolve().parent.parent


def repo(files):
    d = tempfile.TemporaryDirectory()
    for rel, text in files.items():
        p = Path(d.name) / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    return d


LOCK = json.dumps({"lockfileVersion": 3, "packages": {
    "": {"name": "root"},
    "node_modules/left-pad": {"version": "1.3.0"},
    "node_modules/a/node_modules/@s/b": {"version": "2.0.1+x"}}})
FILES = {"requirements.txt": "flask==2.0.1\nRequests_Lib==1.0\ndjango==3.*\nflask==2.0.1\n",
         "package-lock.json": LOCK}


class TestPurl(unittest.TestCase):
    def test_purls(self):
        self.assertEqual(sbom.purl("PyPI", "Requests_Lib", "1.0"), "pkg:pypi/requests-lib@1.0")
        self.assertEqual(sbom.purl("npm", "left-pad", "1.3.0"), "pkg:npm/left-pad@1.3.0")
        self.assertEqual(sbom.purl("npm", "@s/b", "2.0.1+x"), "pkg:npm/%40s/b@2.0.1%2Bx")


class TestBuild(unittest.TestCase):
    def doc(self, files=FILES, vulns=None):
        with repo(files) as d:
            return sbom.build(RepoContext(root=Path(d)), vulns, name="demo")

    def test_components_are_exact_unique_and_sorted(self):
        refs = [c["bom-ref"] for c in self.doc()["components"]]
        self.assertEqual(refs, sorted(refs))
        self.assertEqual(set(refs), {"pkg:pypi/flask@2.0.1", "pkg:pypi/requests-lib@1.0",
                                     "pkg:npm/left-pad@1.3.0", "pkg:npm/%40s/b@2.0.1%2Bx"})

    def test_wildcard_ranges_never_listed_and_completeness_is_stated(self):
        doc = self.doc()
        self.assertNotIn("django", json.dumps(doc["components"]))
        self.assertIn("lockfile", doc["metadata"]["properties"][0]["value"])

    def test_reproducible_with_source_date_epoch(self):
        os.environ["SOURCE_DATE_EPOCH"] = "1700000000"
        try:
            a, b = self.doc(), self.doc()
        finally:
            del os.environ["SOURCE_DATE_EPOCH"]
        self.assertEqual(a, b)
        self.assertEqual(a["metadata"]["timestamp"], "2023-11-14T22:13:20Z")
        self.assertTrue(a["serialNumber"].startswith("urn:uuid:"))

    def test_serial_changes_when_components_change(self):
        other = dict(FILES, **{"requirements.txt": "flask==2.0.2\n"})
        self.assertNotEqual(self.doc()["serialNumber"], self.doc(other)["serialNumber"])

    def test_root_depends_on_every_component(self):
        doc = self.doc()
        dep = doc["dependencies"][0]
        self.assertEqual(sorted(dep["dependsOn"]), [c["bom-ref"] for c in doc["components"]])

    def test_empty_repo(self):
        doc = self.doc({"README.md": "x"})
        self.assertEqual(doc["components"], [])

    def test_vulnerabilities_section(self):
        v = osv.Vuln(id="GHSA-aaaa", summary="s", aliases=["CVE-2024-1"],
                     severity=Severity.CRITICAL, fixed_in="2.0.3")
        doc = self.doc(vulns={("PyPI", "flask", "2.0.1"): [v],
                              ("PyPI", "not-in-sbom", "9"): [v]})
        self.assertEqual(len(doc["vulnerabilities"]), 1)
        e = doc["vulnerabilities"][0]
        self.assertEqual((e["id"], e["ratings"][0]["severity"]), ("CVE-2024-1", "critical"))
        self.assertEqual(e["affects"], [{"ref": "pkg:pypi/flask@2.0.1"}])
        self.assertIn("2.0.3", e["recommendation"])
        self.assertNotIn("vulnerabilities", self.doc())


class TestCli(unittest.TestCase):
    def test_sbom_command_writes_valid_json(self):
        with repo(FILES) as d, tempfile.TemporaryDirectory() as o:
            out = Path(o) / "sbom.json"
            r = subprocess.run([sys.executable, "-m", "bbharden.cli", "sbom", d,
                                "--no-config", "-o", str(out)],
                               capture_output=True, text=True, cwd=ROOT)
            self.assertEqual(r.returncode, 0, r.stderr)
            doc = json.loads(out.read_text())
        self.assertEqual((doc["bomFormat"], doc["specVersion"]), ("CycloneDX", "1.5"))
        self.assertEqual(len(doc["components"]), 4)

    def test_sbom_of_unreachable_osv_is_soft_unless_required(self):
        env = dict(os.environ, HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
        with repo(FILES) as d:
            base = [sys.executable, "-m", "bbharden.cli", "sbom", d, "--no-config", "--osv"]
            soft = subprocess.run(base, capture_output=True, text=True, cwd=ROOT, env=env)
            hard = subprocess.run(base + ["--osv-required"], capture_output=True, text=True,
                                  cwd=ROOT, env=env)
        self.assertEqual(soft.returncode, 0, soft.stderr)
        self.assertNotIn("vulnerabilities", json.loads(soft.stdout))
        self.assertEqual(hard.returncode, 2)


@unittest.skipUnless(os.environ.get("CYCLONEDX_SCHEMA_DIR"),
                     "set CYCLONEDX_SCHEMA_DIR to a CycloneDX/specification clone's schema/ dir")
class TestOfficialSchema(unittest.TestCase):
    """Validates against the official CycloneDX 1.5 JSON schema (needs jsonschema)."""

    def test_valid(self):
        from jsonschema import Draft7Validator
        from referencing import Registry, Resource
        s = Path(os.environ["CYCLONEDX_SCHEMA_DIR"])
        load = lambda n: json.loads((s / n).read_text())
        bom = load("bom-1.5.schema.json")
        reg = Registry().with_resources([
            ("http://cyclonedx.org/schema/spdx.schema.json", Resource.from_contents(load("spdx.schema.json"))),
            ("http://cyclonedx.org/schema/jsf-0.82.schema.json", Resource.from_contents(load("jsf-0.82.schema.json"))),
            ("http://cyclonedx.org/schema/bom-1.5.schema.json", Resource.from_contents(bom))])
        v = osv.Vuln(id="GHSA-aaaa", summary="s", aliases=["CVE-2024-1"],
                     severity=Severity.HIGH, fixed_in="2.0.3")
        with repo(FILES) as d:
            ctx = RepoContext(root=Path(d))
            for doc in (sbom.build(ctx), sbom.build(ctx, {("PyPI", "flask", "2.0.1"): [v]})):
                errs = list(Draft7Validator(bom, registry=reg).iter_errors(doc))
                self.assertEqual([e.message for e in errs], [])


if __name__ == "__main__":
    unittest.main()
