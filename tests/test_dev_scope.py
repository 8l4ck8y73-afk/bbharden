import json
import tempfile
import unittest
from pathlib import Path

from bbharden.context import RepoContext
from bbharden.findings import Severity
from bbharden.osv import Vuln
from bbharden.scanners import dependencies
from bbharden.scanners.dependencies import _collect_packages


def lookup(pkgs):
    return {p: [Vuln("GHSA-1", "s", ["CVE-1"], Severity.CRITICAL, "9.9.9")] for p in pkgs}


def repo(files):
    d = tempfile.TemporaryDirectory()
    for n, c in files.items():
        f = Path(d.name) / n
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(c)
    return d


class TestDevScope(unittest.TestCase):
    def test_sources_of_dev_marking(self):
        lock_v1 = {"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "dev": True},
                                                          "b": {"version": "1.0.0"}}}
        lock_v3 = {"lockfileVersion": 3, "packages": {"": {}, "node_modules/c": {"version": "1.0.0", "dev": True},
                                                      "node_modules/d": {"version": "1.0.0", "devOptional": True}}}
        with repo({"package-lock.json": json.dumps(lock_v1), "x/package-lock.json": json.dumps(lock_v3),
                   "requirements-dev.txt": "pytest==7.0.0\n", "requirements.txt": "flask==2.0.0\n",
                   "Pipfile.lock": json.dumps({"default": {"r": {"version": "==1.0"}},
                                               "develop": {"t": {"version": "==1.0"}}}),
                   "pom.xml": "<dependency><groupId>j</groupId><artifactId>junit</artifactId>"
                              "<version>4.12</version><scope>test</scope></dependency>"}) as d:
            m = _collect_packages(RepoContext(root=Path(d)))
        dev = {k[1] for k in m if m.dev_only(k)}
        self.assertEqual(dev, {"a", "c", "d", "pytest", "t", "j:junit"})

    def test_prod_anywhere_wins(self):
        with repo({"requirements.txt": "x==1.0\n", "requirements-dev.txt": "x==1.0\n"}) as d:
            m = _collect_packages(RepoContext(root=Path(d)))
        self.assertFalse(m.dev_only(("PyPI", "x", "1.0")))

    def test_dev_vuln_lowered_and_labelled(self):
        with repo({"requirements.txt": "flask==2.0.0\n", "requirements-test.txt": "pytest==7.0.0\n"}) as d:
            ctx = RepoContext(root=Path(d), use_osv=True, osv_query=lookup)
            fs = {f.evidence: f for f in dependencies.scan(ctx) if f.rule_id == "DEP_KNOWN_VULN"}
        self.assertEqual(fs["flask==2.0.0"].severity, Severity.CRITICAL)
        self.assertEqual(fs["pytest==7.0.0"].severity, Severity.HIGH)
        self.assertIn("[dev dependency]", fs["pytest==7.0.0"].title)

    def test_requirements_dev_regex_is_not_too_broad(self):
        r = dependencies._DEV_REQ
        for yes in ("requirements-dev.txt", "a/requirements_test.txt", "requirements/dev.txt", "requirements-docs.txt"):
            self.assertTrue(r.search(yes), yes)
        for no in ("requirements.txt", "requirements-prod.txt", "requirements/base.txt", "requirements-device.txt"):
            self.assertFalse(r.search(no), no)


if __name__ == "__main__":
    unittest.main()


class TestDockerTooling(unittest.TestCase):
    def _sev(self, path):
        from bbharden.scanners import dockerfile
        with repo({path: "FROM alpine:3.20\nRUN echo hi\n"}) as d:
            fs = [f for f in dockerfile.scan(RepoContext(root=Path(d))) if f.rule_id == "DOCKER_RUNS_AS_ROOT"]
        return fs[0].severity

    def test_service_images_stay_high(self):
        for p in ("Dockerfile", "app/Dockerfile", "Dockerfile.prod", "deploy/Dockerfile"):
            self.assertEqual(self._sev(p), Severity.HIGH, p)

    def test_build_test_images_are_medium(self):
        for p in ("builders/linux.x86_64/Dockerfile", "testing/zipapp/Dockerfile",
                  ".devcontainer/Dockerfile", "Dockerfile.dev", "ci/Dockerfile", "test.Dockerfile"):
            self.assertEqual(self._sev(p), Severity.MEDIUM, p)
