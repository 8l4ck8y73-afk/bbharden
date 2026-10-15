"""v0.5.2: false positives found by scanning real public repositories."""

import json
import tempfile
import unittest
from pathlib import Path

from bbharden.context import RepoContext
from bbharden.findings import Severity
from bbharden.scanners import dependencies, secrets, workflows


def w(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


def scan(mod, d):
    return list(mod.scan(RepoContext(root=Path(d))))


class TestOpenAIPattern(unittest.TestCase):
    def test_ssh_security_key_algorithm_names_are_not_keys(self):
        # Seen verbatim in neovim's runtime/syntax/sshconfig.vim
        with tempfile.TemporaryDirectory() as d:
            w(d, "sshconfig.vim",
              'syn match Algo "\\<sk-ssh-ed25519-cert-v01@openssh\\.com\\>"\n'
              'syn match Algo "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"\n'
              'x = sk-ssh-ed25519@openssh.com\n')
            self.assertEqual(scan(secrets, d), [])

    def test_real_key_shapes_are_still_found(self):
        keys = [
            "sk-ant-" + "api03-aB3dE5gH7jK9mN1pQ3rS5tU7wX9yZ1aB3dE5",
            "sk-proj-" + "aB3dE5gH7jK9mN1pQ3rS5tU7wX9yZ1aB3dE5",
            "sk-" + "aB3dE5gH7jK9mN1pQ3rS5tU7wX9yZ1aB3dE5gH7jK9mN1p",
        ]
        with tempfile.TemporaryDirectory() as d:
            for i, k in enumerate(keys):
                w(d, f"f{i}.txt", f"OPENAI_API_KEY={k}\n")
            found = {f.file for f in scan(secrets, d) if f.rule_id == "SECRET_OPENAI"}
        self.assertEqual(found, {"f0.txt", "f1.txt", "f2.txt"})


class TestActionSeverity(unittest.TestCase):
    def test_github_owned_actions_rate_below_third_party(self):
        sha = "a" * 40
        wf = ("on: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
              "      - uses: actions/checkout@v4\n"
              "      - uses: github/codeql-action/init@v3\n"
              "      - uses: some-org/thing@v1\n"
              f"      - uses: other/pinned@{sha}\n")
        with tempfile.TemporaryDirectory() as d:
            w(d, ".github/workflows/a.yml", wf)
            got = {f.evidence: f.severity for f in scan(workflows, d)
                   if f.rule_id == "CI_ACTION_UNPINNED"}
        self.assertEqual(got, {
            "actions/checkout@v4": Severity.LOW,
            "github/codeql-action/init@v3": Severity.LOW,
            "some-org/thing@v1": Severity.MEDIUM,
        })

    def test_lookalike_owner_is_not_first_party(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, ".github/workflows/a.yml",
              "on: push\npermissions: {}\njobs:\n  a:\n    steps:\n"
              "      - uses: actions-evil/checkout@v4\n")
            f = [x for x in scan(workflows, d) if x.rule_id == "CI_ACTION_UNPINNED"][0]
        self.assertEqual(f.severity, Severity.MEDIUM)


class TestNpmLockfile(unittest.TestCase):
    PKG = json.dumps({"devDependencies": {"a": "^1.0.0"}})

    def _sev(self, extra_files=()):
        with tempfile.TemporaryDirectory() as d:
            w(d, "package.json", self.PKG)
            for n in extra_files:
                w(d, n, "x")
            return [f.severity for f in scan(dependencies, d)
                    if f.rule_id == "DEP_UNPINNED_NPM"]

    def test_range_without_lockfile_is_low(self):
        self.assertEqual(self._sev(), [Severity.LOW])

    def test_range_with_any_lockfile_is_info(self):
        for lock in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml"):
            self.assertEqual(self._sev([lock]), [Severity.INFO], lock)

    def test_lockfile_in_another_directory_does_not_count(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "pkg/package.json", self.PKG)
            w(d, "other/package-lock.json", "{}")
            sev = [f.severity for f in scan(dependencies, d)
                   if f.rule_id == "DEP_UNPINNED_NPM"]
        self.assertEqual(sev, [Severity.LOW])


if __name__ == "__main__":
    unittest.main()
