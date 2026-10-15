"""Regression tests for the v0.5.1 audit. Each test pins one real defect."""

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from bbharden import osv, pin, remediate, report
from bbharden.context import RepoContext
from bbharden.findings import Finding, Severity
from bbharden.scanners import dependencies, dockerfile, secrets, security_files, workflows

ROOT = Path(__file__).resolve().parent.parent
AWS = "AKIA" + "ABCDEFGHIJKLMNOP"      # assembled at runtime, never a literal


def w(root, rel, text):
    p = Path(root) / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def ids(findings):
    return [f.rule_id for f in findings]


class TestContextSafety(unittest.TestCase):
    def test_repo_under_build_dir_is_still_scanned(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d) / "build" / "vendor" / "repo"
            w(root, "requirements.txt", "flask\n")
            self.assertIn("DEP_UNPINNED_PY", ids(dependencies.scan(RepoContext(root=root))))

    def test_exclude_keeps_leading_dot(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, ".github/x.py", f'k = "{AWS}"\n')
            self.assertEqual(
                list(secrets.scan(RepoContext(root=Path(d), exclude=[".github"]))), [])
            self.assertEqual(
                list(secrets.scan(RepoContext(root=Path(d), exclude=["./.github/"]))), [])

    def test_symlinks_are_never_read(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            outside = w(out, "secret.txt", f'k = "{AWS}"\n')
            os.symlink(outside, Path(d) / "link.txt")
            self.assertEqual(list(secrets.scan(RepoContext(root=Path(d)))), [])

    @unittest.skipUnless(hasattr(os, "mkfifo"), "needs POSIX")
    def test_fifo_does_not_hang(self):
        with tempfile.TemporaryDirectory() as d:
            os.mkfifo(Path(d) / "pipe")
            r = subprocess.run([sys.executable, "-m", "bbharden.cli", "scan", d],
                               capture_output=True, text=True, cwd=ROOT, timeout=20)
            self.assertEqual(r.returncode, 0, r.stderr)


class TestSafeWrites(unittest.TestCase):
    def _fix(self, root):
        f = Finding("X", "t", Severity.LOW, "SECURITY.md", 1, "m", "r",
                    fix_path="SECURITY.md", fix_content="hello\n")
        return remediate.apply(root, [f])

    def test_symlink_target_is_refused_and_untouched(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            victim = Path(out) / "victim.md"
            os.symlink(victim, Path(d) / "SECURITY.md")
            actions = self._fix(Path(d))
            self.assertTrue(actions[0][1].startswith("skipped"))
            self.assertFalse(victim.exists())

    def test_symlinked_parent_dir_is_refused(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            os.symlink(out, Path(d) / ".github")
            f = Finding("X", "t", Severity.LOW, "a", 1, "m", "r",
                        fix_path=".github/dependabot.yml", fix_content="x")
            self.assertTrue(remediate.apply(Path(d), [f])[0][1].startswith("skipped"))
            self.assertEqual(list(Path(out).iterdir()), [])

    def test_path_traversal_is_refused(self):
        with tempfile.TemporaryDirectory() as d:
            f = Finding("X", "t", Severity.LOW, "a", 1, "m", "r",
                        fix_path="../escape.txt", fix_content="x")
            self.assertTrue(remediate.apply(Path(d), [f])[0][1].startswith("skipped"))

    def test_normal_write_is_atomic_and_leaves_no_temp_files(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self._fix(Path(d))[0], ("SECURITY.md", "created"))
            self.assertEqual(sorted(p.name for p in Path(d).iterdir()), ["SECURITY.md"])


class TestSecretsHardening(unittest.TestCase):
    def test_secret_on_very_long_line_is_found(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "bundle.js", "x='" + "a" * 1500 + f"'; k='{AWS}'")
            self.assertIn("SECRET_AWS_AKID", ids(secrets.scan(RepoContext(root=Path(d)))))

    def test_new_provider_patterns(self):
        samples = {
            "SECRET_GITLAB_PAT": "glpat-" + "aB3dE5gH7jK9mN1pQ3rS",
            "SECRET_NPM_TOKEN": "npm_" + "aB3dE5gH7jK9mN1pQ3rS5tU7wX9yZ1aB3dE5",
            "SECRET_GITHUB_FINE_PAT": "github_pat_" + "11AAAAAAA0abcdefghij12",
            "SECRET_HUGGINGFACE": "hf_" + "aB3dE5gH7jK9mN1pQ3rS5tU7wX9yZ1aB3d",
        }
        with tempfile.TemporaryDirectory() as d:
            for i, v in enumerate(samples.values()):
                w(d, f"f{i}.txt", f"token {v}\n")
            got = set(ids(secrets.scan(RepoContext(root=Path(d)))))
        self.assertTrue(set(samples) <= got, set(samples) - got)

    def test_sk_dash_slug_is_not_a_key(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "a.md", "see sk-learn-something-very-long-identifier-name here\n")
            self.assertEqual(list(secrets.scan(RepoContext(root=Path(d)))), [])


class TestDockerfileHardening(unittest.TestCase):
    def _ids(self, text):
        with tempfile.TemporaryDirectory() as d:
            w(d, "Dockerfile", text)
            return ids(dockerfile.scan(RepoContext(root=Path(d))))

    def test_secret_value_is_never_echoed(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "Dockerfile", "FROM python:3.12\nENV API_KEY=supersecretvalue123\nUSER app\n")
            fs = [f for f in dockerfile.scan(RepoContext(root=Path(d)))
                  if f.rule_id == "DOCKER_SECRET_IN_ENV"]
            self.assertEqual(len(fs), 1)
            self.assertNotIn("supersecretvalue123", fs[0].evidence)
            self.assertNotIn("supersecretvalue123", report.sarif(fs, "."))

    def test_final_stage_decides_root(self):
        self.assertIn("DOCKER_RUNS_AS_ROOT", self._ids(
            "FROM python:3.12 AS b\nUSER app\nFROM python:3.12\nCMD x\n"))
        self.assertNotIn("DOCKER_RUNS_AS_ROOT", self._ids(
            "FROM python:3.12 AS b\nFROM python:3.12\nUSER app\n"))

    def test_root_spellings_and_late_switch_back(self):
        for u in ("root", "0", "root:root", "0:0"):
            self.assertIn("DOCKER_RUNS_AS_ROOT",
                          self._ids(f"FROM python:3.12\nUSER {u}\n"), u)
        self.assertIn("DOCKER_RUNS_AS_ROOT",
                      self._ids("FROM python:3.12\nUSER app\nUSER root\n"))
        self.assertNotIn("DOCKER_RUNS_AS_ROOT",
                         self._ids("FROM python:3.12\nUSER 10001:10001\n"))

    def test_continuation_lines_are_joined(self):
        self.assertIn("DOCKER_CURL_PIPE_SHELL", self._ids(
            "FROM python:3.12\nUSER a\nRUN curl -s https://x.sh \\\n  | bash\n"))
        self.assertIn("DOCKER_ADD_REMOTE", self._ids(
            "FROM python:3.12\nUSER a\nADD --chown=a:a https://x/y.tgz /y\n"))


class TestWorkflowHardening(unittest.TestCase):
    def _ids(self, text):
        with tempfile.TemporaryDirectory() as d:
            w(d, ".github/workflows/a.yml", text)
            return ids(workflows.scan(RepoContext(root=Path(d))))

    HEAD = "on: pull_request\npermissions: {}\njobs:\n  a:\n    steps:\n"

    def test_list_item_run_form_is_checked(self):
        self.assertIn("CI_SCRIPT_INJECTION", self._ids(
            self.HEAD + "      - run: echo ${{ github.event.pull_request.title }}\n"))

    def test_github_head_ref_is_flagged(self):
        self.assertIn("CI_SCRIPT_INJECTION", self._ids(
            self.HEAD + "      - run: echo ${{ github.head_ref }}\n"))

    def test_env_indirection_is_not_flagged(self):
        safe = (self.HEAD +
                "      - run: echo hi\n"
                "      - name: safe\n"
                "        env:\n"
                "          TITLE: ${{ github.event.pull_request.title }}\n"
                "        run: echo \"$TITLE\"\n")
        self.assertNotIn("CI_SCRIPT_INJECTION", self._ids(safe))

    def test_block_scalar_run_is_checked_until_dedent(self):
        wf = (self.HEAD +
              "      - run: |\n"
              "          echo ok\n"
              "          echo ${{ github.event.comment.body }}\n"
              "      - name: after\n"
              "        with:\n"
              "          t: ${{ github.event.pull_request.title }}\n")
        got = [f for f in self._scan(wf) if f.rule_id == "CI_SCRIPT_INJECTION"]
        self.assertEqual(len(got), 1)
        self.assertIn("comment.body", got[0].evidence)

    def _scan(self, text):
        with tempfile.TemporaryDirectory() as d:
            w(d, ".github/workflows/a.yml", text)
            return list(workflows.scan(RepoContext(root=Path(d))))

    def test_github_script_body_is_checked(self):
        self.assertIn("CI_SCRIPT_INJECTION", self._ids(
            self.HEAD + "      - uses: actions/github-script@" + "a" * 40 + "\n"
            "        with:\n          script: |\n"
            "            console.log('${{ github.event.issue.title }}')\n"))

    def test_pr_target_only_flagged_when_head_is_checked_out(self):
        sha = "a" * 40
        base = "on: pull_request_target\npermissions: {}\njobs:\n  a:\n    steps:\n"
        self.assertNotIn("CI_PR_TARGET_CHECKOUT",
                         self._ids(base + f"      - uses: actions/checkout@{sha}\n"))
        self.assertIn("CI_PR_TARGET_CHECKOUT", self._ids(
            base + f"      - uses: actions/checkout@{sha}\n        with:\n"
                   "          ref: ${{ github.event.pull_request.head.sha }}\n"))
        # `on:` inline and list forms are recognised too
        self.assertIn("CI_PR_TARGET_CHECKOUT", self._ids(
            "on: [push, pull_request_target]\npermissions: {}\njobs:\n  a:\n    steps:\n"
            f"      - uses: actions/checkout@{sha}\n        with:\n"
            "          ref: ${{ github.head_ref }}\n"))

    def test_quoted_pinned_action_is_not_unpinned(self):
        sha = "a" * 40
        self.assertNotIn("CI_ACTION_UNPINNED", self._ids(
            self.HEAD + f"      - uses: \"actions/checkout@{sha}\"\n"))
        self.assertIn("CI_ACTION_UNPINNED", self._ids(
            self.HEAD + "      - uses: 'actions/checkout@v4'\n"))

    def test_write_all_is_flagged(self):
        self.assertIn("CI_PERMISSIONS_WRITE_ALL", self._ids(
            "on: push\npermissions: write-all\njobs: {}\n"))

    def test_commented_out_lines_are_ignored(self):
        self.assertNotIn("CI_SCRIPT_INJECTION", self._ids(
            self.HEAD + "      - run: |\n          # echo ${{ github.head_ref }}\n"
                        "          echo ok\n"))


class TestDependenciesHardening(unittest.TestCase):
    def _scan(self, name, text):
        with tempfile.TemporaryDirectory() as d:
            w(d, name, text)
            return list(dependencies.scan(RepoContext(root=Path(d))))

    def test_extras_comments_markers_and_wildcards_are_unpinned(self):
        fs = self._scan("requirements.txt",
                        "requests[security]>=2\nflask  # todo\ndjango==3.*\n"
                        "numpy>=1 ; python_version>'3'\nok==1.0.0\n--hash=abc\n"
                        "pkg @ https://x/y.whl\n")
        self.assertEqual(sorted(f.evidence.split()[0] for f in fs),
                         ["django==3.*", "flask", "numpy>=1", "requests[security]>=2"])

    def test_wildcard_never_sent_to_osv(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "requirements.txt", "django==3.*\nflask==2.0.1\nRequests_Lib==1.0\n")
            pk = dependencies._collect_packages(RepoContext(root=Path(d)))
        self.assertEqual(set(pk), {("PyPI", "flask", "2.0.1"), ("PyPI", "requests-lib", "1.0")})

    def test_non_dict_package_json_does_not_crash(self):
        for body in ("[]", "null", "42", '"x"', "{bad json"):
            self.assertEqual(self._scan("package.json", body), [], body)

    def test_npm_partial_ranges_flagged_but_urls_and_exact_not(self):
        fs = self._scan("package.json", json.dumps({"dependencies": {
            "a": "1.x", "b": "^1.2.3", "c": "1.2.3", "d": "file:../d",
            "e": "git+https://x/y.git", "f": "owner/repo", "g": "*", "h": "latest"}}))
        self.assertEqual(sorted(f.evidence.split(":")[0] for f in fs), ["a", "b", "g", "h"])

    def test_lockfiles_expose_transitive_packages(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "package-lock.json", json.dumps({"lockfileVersion": 3, "packages": {
                "": {"name": "root"},
                "node_modules/left-pad": {"version": "1.3.0"},
                "node_modules/a/node_modules/@s/b": {"version": "2.0.1"}}}))
            w(d, "Pipfile.lock", json.dumps({"default": {"Jinja2": {"version": "==3.0.0"}}}))
            w(d, "poetry.lock", '[[package]]\nname = "Foo_Bar"\nversion = "9.9.9"\n')
            pk = set(dependencies._collect_packages(RepoContext(root=Path(d))))
        self.assertEqual(pk, {("npm", "left-pad", "1.3.0"), ("npm", "@s/b", "2.0.1"),
                              ("PyPI", "jinja2", "3.0.0"), ("PyPI", "foo-bar", "9.9.9")})


class TestSecurityFilesHardening(unittest.TestCase):
    def _ctx(self, d, **kw):
        return RepoContext(root=Path(d), **kw)

    def test_gitignored_env_is_not_flagged_but_unignored_is(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, ".gitignore", ".env\n")
            w(d, ".env", "A=1\n")
            self.assertNotIn("HYGIENE_ENV_COMMITTED",
                             ids(security_files.scan(self._ctx(d))))
            (Path(d) / ".gitignore").write_text("node_modules\n")
            self.assertIn("HYGIENE_ENV_COMMITTED",
                          ids(security_files.scan(self._ctx(d))))

    def test_env_templates_are_never_flagged(self):
        with tempfile.TemporaryDirectory() as d:
            for n in (".env.example", ".env.sample", ".env.template"):
                w(d, n, "A=changeme\n")
            self.assertNotIn("HYGIENE_ENV_COMMITTED",
                             ids(security_files.scan(self._ctx(d))))

    def test_tracked_env_is_flagged_even_if_ignored(self):
        if subprocess.run(["git", "--version"], capture_output=True).returncode:
            self.skipTest("git not installed")
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull)
            run = lambda *a: subprocess.run(["git", *a], cwd=d, env=env,
                                            capture_output=True, check=True)
            run("init", "-q")
            w(d, ".env", "A=1\n")
            run("add", "-f", ".env")
            w(d, ".gitignore", ".env\n")
            fs = [f for f in security_files.scan(self._ctx(d))
                  if f.rule_id == "HYGIENE_ENV_COMMITTED"]
            self.assertEqual(len(fs), 1)
            self.assertIn("tracked", fs[0].message)

    def test_dependabot_covers_only_detected_ecosystems(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "go.mod", "module x\n")
            w(d, ".github/workflows/ci.yml", "on: push\n")
            w(d, "web/package.json", "{}")
            f = [x for x in security_files.scan(self._ctx(d))
                 if x.rule_id == "HYGIENE_NO_DEPENDABOT"][0]
        c = f.fix_content
        self.assertIn('"gomod"', c)
        self.assertIn('"github-actions"', c)
        self.assertIn('directory: "/web"', c)
        self.assertNotIn('"pip"', c)

    def test_no_manifests_means_no_dependabot_finding(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "README.md", "x")
            self.assertNotIn("HYGIENE_NO_DEPENDABOT",
                             ids(security_files.scan(self._ctx(d))))

    def test_gitignore_fix_adds_only_missing_patterns(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, ".gitignore", "*.pem\n*.key\nnode_modules")
            f = [x for x in security_files.scan(self._ctx(d))
                 if x.rule_id == "HYGIENE_GITIGNORE_SECRETS"][0]
        self.assertEqual(f.fix_content.count("*.pem"), 1)
        self.assertIn("node_modules\n\n# Secrets", f.fix_content)
        self.assertIn(".env\n", f.fix_content)


class TestPinHardening(unittest.TestCase):
    def test_crlf_files_stay_crlf(self):
        t = "steps:\r\n  - uses: a/b@v1\r\n  - uses: c/d@v2 # keep\r\n"
        new, pinned, _ = pin.pin_text(t, lambda r, ref: "e" * 40)
        self.assertEqual(len(pinned), 2)
        self.assertEqual(new.count("\r\n"), 3)
        self.assertNotIn("\n", new.replace("\r\n", ""))

    def test_quotes_preserved(self):
        new, pinned, _ = pin.pin_text('- uses: "a/b@v1"\n', lambda r, ref: "e" * 40)
        self.assertIn(f'"a/b@{"e" * 40}"  # v1', new)

    def test_templated_and_glob_refs_are_not_looked_up(self):
        called = []
        def res(r, ref):
            called.append(ref)
            return "e" * 40
        t = "- uses: a/b@${{ matrix.v }}\n- uses: a/b@v*\n"
        new, pinned, skipped = pin.pin_text(t, res)
        self.assertEqual((new, pinned, called), (t, [], []))
        self.assertEqual(len(skipped), 2)

    def test_symlinked_workflow_is_not_written_through(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            target = w(out, "wf.yml", "- uses: a/b@v1\n")
            (Path(d) / ".github/workflows").mkdir(parents=True)
            os.symlink(target, Path(d) / ".github/workflows/ci.yml")
            pin.pin_workflows(RepoContext(root=Path(d)), resolve=lambda r, ref: "e" * 40)
            self.assertEqual(target.read_text(), "- uses: a/b@v1\n")


class TestBaselineMultiplicity(unittest.TestCase):
    def test_second_copy_of_a_baselined_secret_is_new(self):
        from bbharden import suppress
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            w(root, "a.py", f'k = "{AWS}"\n')
            ctx = RepoContext(root=root)
            bl = root / "bl.json"
            suppress.write_baseline(str(bl), list(secrets.scan(ctx)))
            w(root, "a.py", f'k = "{AWS}"\nk2 = "{AWS}"\n')
            ctx = RepoContext(root=root)
            kept, counts = suppress.apply(ctx, list(secrets.scan(ctx)),
                                          suppress.load_baseline(str(bl)))
        self.assertEqual((len(kept), counts["baseline"]), (1, 1))


class TestReports(unittest.TestCase):
    def _f(self, **kw):
        base = dict(rule_id="R", title="t", severity=Severity.HIGH, file="a/b.py",
                    line=3, message="m", remediation="r", evidence="e", cwe="CWE-798")
        base.update(kw)
        return Finding(**base)

    def test_terminal_escapes_and_bidi_are_neutralised(self):
        f = self._f(file="evil\x1b[31m.py", evidence="x\x1b]0;pwn\x07y\u202eabc")
        out = report.console([f], ".")
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\u202e", out)

    def test_markdown_is_inert(self):
        f = self._f(title="<img src=x onerror=1> | pipe", file="a|b.py")
        md = report.markdown([f], ".")
        self.assertNotIn("<img", md)
        self.assertIn("&lt;img", md)

    def test_sarif_has_real_repo_url_tags_and_stable_fingerprints(self):
        doc = json.loads(report.sarif([self._f(file="a\\b.py")], "."))
        run = doc["runs"][0]
        self.assertEqual(run["tool"]["driver"]["informationUri"], report.REPO_URL)
        self.assertIn("8l4ck8y73-afk", report.REPO_URL)
        self.assertIn("external/cwe/cwe-798", run["tool"]["driver"]["rules"][0]["properties"]["tags"])
        res = run["results"][0]
        self.assertEqual(res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"], "a/b.py")
        a = res["partialFingerprints"]["bbharden/v1"]
        moved = json.loads(report.sarif([self._f(file="a\\b.py", line=99)], "."))
        self.assertEqual(a, moved["runs"][0]["results"][0]["partialFingerprints"]["bbharden/v1"])


class TestOsvHardening(unittest.TestCase):
    PKG = ("PyPI", "flask", "2.0.1")

    def test_cvss3_vectors_match_official_scores(self):
        for vec, want in [
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
            ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N", 5.5),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
            ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
        ]:
            self.assertEqual(osv.cvss3_score(vec), want, vec)
        self.assertIsNone(osv.cvss3_score("CVSS:3.1/AV:X"))
        self.assertIsNone(osv.cvss3_score("nonsense"))

    def test_truncated_reply_is_an_error_not_clean(self):
        with self.assertRaises(osv.OSVUnavailable):
            osv.query([self.PKG, ("PyPI", "x", "1.0")],
                      post=lambda u, p: {"results": [{}]})
        with self.assertRaises(osv.OSVUnavailable):
            osv.query([self.PKG], post=lambda u, p: {"oops": 1})

    def test_pagination_is_followed(self):
        calls = []
        def post(url, body):
            calls.append(body)
            q = body["queries"][0]
            if q.get("page_token") == "p2":
                return {"results": [{"vulns": [{"id": "GHSA-2"}]}]}
            return {"results": [{"vulns": [{"id": "GHSA-1"}], "next_page_token": "p2"}]}
        get = lambda url: {"id": url.rsplit("/", 1)[-1]}
        res = osv.query([self.PKG], post=post, get=get)
        self.assertEqual([v.id for v in res[self.PKG]], ["GHSA-1", "GHSA-2"])
        self.assertEqual(len(calls), 2)

    def test_withdrawn_skipped_and_detail_failure_keeps_the_match(self):
        def get(url):
            if url.endswith("W"):
                return {"id": "W", "withdrawn": "2024-01-01T00:00:00Z"}
            raise osv.OSVUnavailable("boom")
        post = lambda u, b: {"results": [{"vulns": [{"id": "W"}, {"id": "KEEP"}]}]}
        res = osv.query([self.PKG], post=post, get=get)
        self.assertEqual([v.id for v in res[self.PKG]], ["KEEP"])

    def test_fixed_version_is_never_a_downgrade(self):
        rec = {"affected": [{"package": {"ecosystem": "PyPI", "name": "Flask"},
                             "ranges": [{"events": [{"fixed": "1.2.5"}, {"fixed": "2.0.3"},
                                                    {"fixed": "2.1.0"}]}]}]}
        self.assertEqual(osv.fixed_version(rec, "PyPI", "flask", "2.0.1"), "2.0.3")
        self.assertEqual(osv.fixed_version(rec, "PyPI", "flask", "1.0.0"), "1.2.5")
        self.assertIsNone(osv.fixed_version(rec, "PyPI", "flask", "3.0.0"))
        self.assertEqual(osv.fixed_version(rec, "PyPI", "flask"), "1.2.5")


class TestCliGates(unittest.TestCase):
    def _run(self, *a):
        return subprocess.run([sys.executable, "-m", "bbharden.cli", *a],
                              capture_output=True, text=True, cwd=ROOT)

    def test_scanner_crash_fails_closed(self):
        from bbharden import cli
        from bbharden.scanners import ALL_SCANNERS  # noqa: F401
        import bbharden.scanners as sc
        orig = sc.ALL_SCANNERS
        try:
            def boom(ctx):
                raise RuntimeError("kaboom")
                yield  # pragma: no cover
            sc.ALL_SCANNERS = [("boom", boom)]
            with tempfile.TemporaryDirectory() as d:
                ctx = RepoContext(root=Path(d))
                findings = cli._run_scan(ctx, None, None)
        finally:
            sc.ALL_SCANNERS = orig
        self.assertEqual(findings, [])
        self.assertEqual(len(ctx.errors), 1)

    def test_missing_or_file_target_is_exit_2(self):
        with tempfile.TemporaryDirectory() as d:
            missing = str(Path(d) / "nope")
            self.assertEqual(self._run("scan", missing).returncode, 2)
            self.assertEqual(self._run("fix", missing).returncode, 2)
            self.assertFalse(Path(missing).exists())     # fix must not create it
        self.assertEqual(self._run("scan", str(ROOT / "README.md")).returncode, 2)

    def test_osv_required_exits_2_when_unreachable(self):
        with tempfile.TemporaryDirectory() as d:
            w(d, "requirements.txt", "flask==2.0.1\n")
            env = dict(os.environ, HTTPS_PROXY="http://127.0.0.1:9", HTTP_PROXY="http://127.0.0.1:9")
            base = [sys.executable, "-m", "bbharden.cli", "scan", d, "--only", "dependencies", "--osv"]
            soft = subprocess.run(base, capture_output=True, text=True, cwd=ROOT, env=env)
            hard = subprocess.run(base + ["--osv-required"], capture_output=True, text=True, cwd=ROOT, env=env)
        self.assertEqual(soft.returncode, 0, soft.stderr)
        self.assertEqual(hard.returncode, 2, hard.stderr)

    def test_fix_refuses_symlinked_security_md_end_to_end(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as out:
            victim = Path(out) / "victim.md"
            os.symlink(victim, Path(d) / "SECURITY.md")
            r = self._run("fix", d, "--only", "security-files", "--security-email", "a@b.co")
            self.assertFalse(victim.exists(), r.stdout + r.stderr)


if __name__ == "__main__":
    unittest.main()
