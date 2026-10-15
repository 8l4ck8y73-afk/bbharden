import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bbharden.context import RepoContext
from bbharden.scanners import history

ROOT = Path(__file__).resolve().parent.parent
KEY = "AKIA" + "ABCDEFGHIJKLMNOP"
ENV = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
       "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": os.devnull}


def git(d, *a):
    subprocess.run(["git", "-C", str(d), *a], check=True, capture_output=True, env=ENV)


def make_repo(d):
    d = Path(d)
    git(d, "init", "-q", "-b", "main")
    (d / "app.py").write_text(f'k = "{KEY}"\nprint(1)\n')
    git(d, "add", "-A"); git(d, "commit", "-qm", "oops")
    (d / "app.py").write_text("import os\nk = os.environ['K']\n")
    git(d, "commit", "-qam", "fix")
    return d


class TestHistory(unittest.TestCase):
    def test_finds_removed_secret_with_commit_and_redaction(self):
        with tempfile.TemporaryDirectory() as t:
            d = make_repo(t)
            ctx = RepoContext(root=d, history=True)
            fs = list(history.scan(ctx))
            self.assertEqual(len(fs), 1)
            f = fs[0]
            self.assertEqual((f.rule_id, f.file, f.line), ("SECRET_IN_HISTORY", "app.py", 1))
            self.assertNotIn(KEY, f.evidence + f.message)
            self.assertRegex(f.message, r"[0-9a-f]{12}")

    def test_off_by_default(self):
        with tempfile.TemporaryDirectory() as t:
            self.assertEqual(list(history.scan(RepoContext(root=make_repo(t)))), [])

    def test_secret_still_in_tree_not_double_reported(self):
        with tempfile.TemporaryDirectory() as t:
            d = make_repo(t)
            (d / "app.py").write_text(f'k = "{KEY}"\n')
            git(d, "commit", "-qam", "again")
            self.assertEqual(list(history.scan(RepoContext(root=d, history=True))), [])

    def test_not_a_git_repo_notes_and_no_crash(self):
        with tempfile.TemporaryDirectory() as t:
            ctx = RepoContext(root=Path(t), history=True)
            self.assertEqual(list(history.scan(ctx)), [])
            self.assertTrue(any("not a git" in n for n in ctx.notes))

    def test_symlinked_dotgit_refused(self):
        with tempfile.TemporaryDirectory() as t, tempfile.TemporaryDirectory() as o:
            make_repo(o)
            os.symlink(Path(o) / ".git", Path(t) / ".git")
            ctx = RepoContext(root=Path(t), history=True)
            self.assertEqual(list(history.scan(ctx)), [])

    def test_commit_cap_is_reported_as_partial(self):
        with tempfile.TemporaryDirectory() as t:
            d = make_repo(t)
            ctx = RepoContext(root=d, history=True, history_max_commits=1)
            list(history.scan(ctx))
            self.assertTrue(any("NOT scanned" in n for n in ctx.notes))

    def test_content_that_looks_like_diff_header_is_not_misparsed(self):
        with tempfile.TemporaryDirectory() as t:
            d = Path(t); git(d, "init", "-q", "-b", "main")
            (d / "a.txt").write_text("x\n++ b/evil.py\n")  # added line '+++ b/evil.py'
            (d / "b.py").write_text(f'k = "{KEY}"\n')
            git(d, "add", "-A"); git(d, "commit", "-qm", "c")
            (d / "b.py").write_text("")
            git(d, "commit", "-qam", "d")
            fs = list(history.scan(RepoContext(root=d, history=True)))
            self.assertEqual([f.file for f in fs], ["b.py"])

    def test_hostile_repo_config_does_not_execute(self):
        with tempfile.TemporaryDirectory() as t:
            d = make_repo(t); marker = d / "PWNED"
            cfg = d / ".git" / "config"
            cfg.write_text(cfg.read_text() + f"[core]\n\tfsmonitor = touch {marker}\n"
                           f"[diff \"x\"]\n\tcommand = touch {marker}\n\ttextconv = touch {marker}\n")
            (d / ".gitattributes").write_text("* diff=x\n")
            list(history.scan(RepoContext(root=d, history=True)))
            self.assertFalse(marker.exists())

    def test_cli_flag_and_only_interaction(self):
        with tempfile.TemporaryDirectory() as t:
            d = make_repo(t)
            r = subprocess.run([sys.executable, "-m", "bbharden.cli", "scan", str(d), "--no-config",
                                "--only", "secrets", "--history", "--format", "json"],
                               capture_output=True, text=True, cwd=ROOT)
            self.assertIn("SECRET_IN_HISTORY", r.stdout)
            r = subprocess.run([sys.executable, "-m", "bbharden.cli", "scan", str(d), "--no-config",
                                "--format", "json"], capture_output=True, text=True, cwd=ROOT)
            self.assertNotIn("SECRET_IN_HISTORY", r.stdout)


if __name__ == "__main__":
    unittest.main()
