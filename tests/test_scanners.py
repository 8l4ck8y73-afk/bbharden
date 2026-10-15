"""Smoke + behaviour tests. Run with: python3 -m pytest  (or python3 -m unittest)."""

import tempfile
import unittest
from pathlib import Path

from bbharden.context import RepoContext
from bbharden.findings import Severity
from bbharden.scanners import secrets, dockerfile, workflows
from bbharden import remediate
from bbharden.scanners import security_files

ROOT = Path(__file__).resolve().parent.parent
EXAMPLE = ROOT / "examples" / "vulnerable-app"


def _ctx(path):
    return RepoContext(root=path)


class TestSecrets(unittest.TestCase):
    def test_detects_aws(self):
        rules = {f.rule_id for f in secrets.scan(_ctx(EXAMPLE))}
        self.assertIn("SECRET_AWS_AKID", rules)

    def test_detects_provider_keys_from_generated_fixture(self):
        # Provider-signature secrets are assembled at runtime in a temp dir so
        # no real-looking live key is ever committed to this repository (which
        # would — correctly — be blocked by push protection).
        stripe = "sk_" + "live_" + ("a1B2c3" * 5)          # matches Stripe rule
        ghpat = "ghp_" + ("A1b2C3d4" * 5)                   # matches GitHub PAT
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "leak.py").write_text(
                f'stripe_key = "{stripe}"\ngithub_token = "{ghpat}"\n'
            )
            rules = {f.rule_id for f in secrets.scan(_ctx(root))}
        self.assertIn("SECRET_STRIPE_KEY", rules)
        self.assertIn("SECRET_GITHUB_PAT", rules)

    def test_ignores_placeholder(self):
        findings = list(secrets.scan(_ctx(EXAMPLE)))
        # 'api_key = "placeholder"' must not be flagged.
        for f in findings:
            self.assertNotEqual(f.evidence, "placeholder")

    def test_evidence_is_redacted(self):
        # A generated full-length secret must never appear raw in the evidence.
        secret = "sk_" + "live_" + ("Zz9Yy8" * 5)
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "leak.py").write_text(f'k = "{secret}"\n')
            for f in secrets.scan(_ctx(root)):
                self.assertNotIn(secret, f.evidence)


class TestDockerfile(unittest.TestCase):
    def test_flags_root_and_latest(self):
        rules = {f.rule_id for f in dockerfile.scan(_ctx(EXAMPLE))}
        self.assertIn("DOCKER_RUNS_AS_ROOT", rules)
        self.assertIn("DOCKER_LATEST_TAG", rules)
        self.assertIn("DOCKER_CURL_PIPE_SHELL", rules)


class TestWorkflows(unittest.TestCase):
    def test_flags_pr_target_and_injection(self):
        rules = {f.rule_id for f in workflows.scan(_ctx(EXAMPLE))}
        self.assertIn("CI_PR_TARGET_CHECKOUT", rules)
        self.assertIn("CI_SCRIPT_INJECTION", rules)
        self.assertIn("CI_ACTION_UNPINNED", rules)


class TestAutofix(unittest.TestCase):
    def test_dry_run_plans_security_md_when_email_given(self):
        ctx = RepoContext(root=EXAMPLE, security_email="sec@corp.test")
        findings = list(security_files.scan(ctx))
        actions = remediate.apply(EXAMPLE, findings, dry_run=True)
        paths = {p for p, _ in actions}
        self.assertIn("SECURITY.md", paths)
        md = next(f for f in findings if f.rule_id == "HYGIENE_NO_SECURITY_MD")
        self.assertIn("sec@corp.test", md.fix_content)
        self.assertNotIn("example.com", md.fix_content)

    def test_never_invents_a_contact_email(self):
        # Regression: a fake placeholder contact in a published policy is worse
        # than no policy, so without an email there must be NO autofix.
        findings = list(security_files.scan(_ctx(EXAMPLE)))
        md = next(f for f in findings if f.rule_id == "HYGIENE_NO_SECURITY_MD")
        self.assertFalse(md.has_autofix)
        self.assertIn("--security-email", md.remediation)
        paths = {p for p, _ in remediate.apply(EXAMPLE, findings, dry_run=True)}
        self.assertNotIn("SECURITY.md", paths)
        self.assertIn(".github/dependabot.yml", paths)  # other fixes unaffected


class TestDockerfileDetection(unittest.TestCase):
    def test_source_files_named_dockerfile_dot_ext_are_not_dockerfiles(self):
        from bbharden.scanners.dockerfile import _is_dockerfile
        for name in ("Dockerfile", "dockerfile", "Dockerfile.prod",
                     "Dockerfile.dev", "app.dockerfile"):
            self.assertTrue(_is_dockerfile(name), name)
        for name in ("dockerfile.py", "Dockerfile.md", "dockerfile.js",
                     "dockerfile.txt", "dockerfile.yml"):
            self.assertFalse(_is_dockerfile(name), name)


class TestExclude(unittest.TestCase):
    def test_exclude_directory_and_glob(self):
        base = RepoContext(root=EXAMPLE)
        self.assertTrue(list(dockerfile.scan(base)))  # findings without exclude
        self.assertTrue(RepoContext(root=ROOT, exclude=["examples"]).is_excluded(
            EXAMPLE / "Dockerfile"))
        self.assertTrue(RepoContext(root=ROOT, exclude=["examples/*"]).is_excluded(
            EXAMPLE / "Dockerfile"))
        self.assertFalse(RepoContext(root=ROOT, exclude=["examples"]).is_excluded(
            ROOT / "README.md"))

    def test_excluded_paths_produce_no_findings(self):
        ctx = RepoContext(root=ROOT, exclude=["examples"])
        files = {ctx.rel(p) for p in ctx.walk()}
        self.assertFalse(any(f.startswith("examples") for f in files))
        self.assertEqual(list(dockerfile.scan(ctx)), [])


if __name__ == "__main__":
    unittest.main()
