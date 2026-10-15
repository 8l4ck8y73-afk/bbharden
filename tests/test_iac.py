import tempfile
import unittest
from pathlib import Path

from bbharden.context import RepoContext
from bbharden.findings import Severity
from bbharden.scanners import iac


def scan(files):
    with tempfile.TemporaryDirectory() as d:
        for rel, text in files.items():
            p = Path(d) / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(text, encoding="utf-8")
        return list(iac.scan(RepoContext(root=Path(d))))


def ids(fs):
    return sorted(f.rule_id for f in fs)


K8S_HEAD = "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: a\nspec:\n  template:\n    spec:\n"


class TestKubernetes(unittest.TestCase):
    def one(self, body, name="d.yaml"):
        return scan({name: K8S_HEAD + body})

    def test_each_dangerous_setting(self):
        cases = {
            "K8S_PRIVILEGED": "      containers:\n      - name: c\n        image: a:1\n        securityContext:\n          privileged: true\n",
            "K8S_PRIVILEGE_ESCALATION": "      containers:\n      - name: c\n        image: a:1\n        securityContext:\n          allowPrivilegeEscalation: true\n",
            "K8S_RUNS_AS_ROOT": "      containers:\n      - name: c\n        image: a:1\n        securityContext:\n          runAsUser: 0\n",
            "K8S_HOST_NAMESPACE": "      hostPID: true\n      containers:\n      - name: c\n        image: a:1\n",
            "K8S_HOSTPATH": "      volumes:\n      - name: v\n        hostPath:\n          path: /var/run/docker.sock\n",
            "K8S_IMAGE_NOT_PINNED": "      containers:\n      - name: c\n        image: nginx:latest\n",
            "K8S_DANGEROUS_CAPABILITY": "      containers:\n      - name: c\n        image: a:1\n        securityContext:\n          capabilities:\n            add:\n            - SYS_ADMIN\n",
        }
        for rule, body in cases.items():
            self.assertIn(rule, ids(self.one(body)), rule)

    def test_safe_deployment_has_no_findings(self):
        body = ("      containers:\n      - name: c\n        image: nginx:1.27.1\n"
                "        securityContext:\n          privileged: false\n"
                "          allowPrivilegeEscalation: false\n          runAsNonRoot: true\n"
                "          capabilities:\n            drop: [ALL]\n")
        self.assertEqual(self.one(body), [])

    def test_digest_pinned_and_templated_images_are_fine(self):
        sha = "a" * 64
        body = (f"      containers:\n      - name: c\n        image: nginx@sha256:{sha}\n"
                "      - name: d\n        image: \"{{ .Values.image }}\"\n")
        self.assertEqual(self.one(body), [])

    def test_cap_add_inline_list_and_safe_cap(self):
        body = ("      containers:\n      - name: c\n        image: a:1\n"
                "        securityContext:\n          capabilities:\n            add: [NET_BIND_SERVICE, SYS_ADMIN]\n")
        self.assertEqual(ids(self.one(body)), ["K8S_DANGEROUS_CAPABILITY"])

    def test_hostpath_ordinary_is_medium_sensitive_is_high(self):
        mk = lambda p: self.one("      volumes:\n      - name: v\n        hostPath:\n          path: %s\n" % p)
        self.assertEqual(mk("/data/app")[0].severity, Severity.MEDIUM)
        self.assertEqual(mk("/etc")[0].severity, Severity.HIGH)

    def test_secret_env_literal_flagged_and_redacted_but_secretkeyref_ok(self):
        lit = ("      containers:\n      - name: c\n        image: a:1\n        env:\n"
               "        - name: DB_PASSWORD\n          value: hunter2-production-value\n")
        fs = self.one(lit)
        self.assertEqual(ids(fs), ["K8S_SECRET_IN_ENV"])
        self.assertNotIn("hunter2-production-value", fs[0].evidence)
        ref = ("      containers:\n      - name: c\n        image: a:1\n        env:\n"
               "        - name: DB_PASSWORD\n          valueFrom:\n            secretKeyRef:\n"
               "              name: s\n              key: k\n")
        self.assertEqual(self.one(ref), [])

    def test_multidoc_line_numbers_and_non_workload_ignored(self):
        text = ("apiVersion: v1\nkind: ConfigMap\ndata:\n  privileged: \"true\"\n---\n"
                + K8S_HEAD + "      hostNetwork: true\n      containers:\n      - name: c\n        image: a:1\n")
        fs = scan({"m.yaml": text})
        self.assertEqual(ids(fs), ["K8S_HOST_NAMESPACE"])
        self.assertEqual(text.splitlines()[fs[0].line - 1].strip(), "hostNetwork: true")

    def test_non_k8s_yaml_and_workflows_are_ignored(self):
        self.assertEqual(scan({"a.yaml": "privileged: true\nimage: nginx\n"}), [])
        self.assertEqual(scan({".github/workflows/x.yml": K8S_HEAD + "      hostPID: true\n"}), [])


class TestCompose(unittest.TestCase):
    def test_dangerous_settings(self):
        text = ("services:\n  a:\n    image: nginx:latest\n    privileged: true\n"
                "    network_mode: host\n    pid: host\n    cap_add:\n      - SYS_ADMIN\n"
                "    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n")
        self.assertEqual(ids(scan({"docker-compose.yml": text})), sorted([
            "COMPOSE_IMAGE_NOT_PINNED", "COMPOSE_PRIVILEGED", "COMPOSE_HOST_NETWORK",
            "COMPOSE_HOST_NAMESPACE", "COMPOSE_DANGEROUS_CAPABILITY", "COMPOSE_DOCKER_SOCKET"]))

    def test_secret_env_list_and_map_forms_redacted(self):
        text = ("services:\n  a:\n    image: pg:16\n    environment:\n"
                "      - POSTGRES_PASSWORD=supersecretvalue1\n      - TZ=UTC\n"
                "  b:\n    image: pg:16\n    environment:\n      API_TOKEN: another-secret-value\n"
                "      NAME: app\n")
        fs = scan({"compose.yaml": text})
        self.assertEqual(ids(fs), ["COMPOSE_SECRET_IN_ENV"] * 2)
        for f in fs:
            self.assertNotIn("supersecretvalue1", f.evidence + f.message)
            self.assertNotIn("another-secret-value", f.evidence + f.message)

    def test_env_from_variables_and_placeholders_are_fine(self):
        text = ("services:\n  a:\n    image: pg:16\n    environment:\n"
                "      - POSTGRES_PASSWORD=${DB_PASSWORD}\n      - API_TOKEN=changeme\n"
                "    ports:\n      - \"5432:5432\"\n")
        self.assertEqual(scan({"docker-compose.yml": text}), [])

    def test_clean_compose_and_block_cap_add_safe(self):
        text = ("services:\n  a:\n    image: nginx:1.27\n    cap_add:\n      - NET_BIND_SERVICE\n"
                "    volumes:\n      - ./data:/data\n")
        self.assertEqual(scan({"docker-compose.prod.yml": text}), [])

    def test_socket_as_command_flag_is_not_a_mount(self):
        # portainer/compose.yaml in docker/awesome-compose
        text = ("services:\n  p:\n    image: portainer/portainer-ce:2.19.0\n"
                "    command: -H unix:///var/run/docker.sock\n"
                "    volumes:\n      - \"/var/run/docker.sock:/var/run/docker.sock\"\n")
        fs = scan({"compose.yaml": text})
        self.assertEqual(ids(fs), ["COMPOSE_DOCKER_SOCKET"])
        self.assertEqual(fs[0].line, 6)
        long_form = ("services:\n  p:\n    image: x:1\n    volumes:\n      - type: bind\n"
                     "        source: /var/run/docker.sock\n        target: /s\n")
        self.assertEqual(ids(scan({"compose.yml": long_form})), ["COMPOSE_DOCKER_SOCKET"])

    def test_constant_like_token_values_are_identifiers_not_secrets(self):
        # ETCD_INITIAL_CLUSTER_TOKEN in kubernetes/examples
        k8s = (K8S_HEAD + "      containers:\n      - name: c\n        image: a:1\n        env:\n"
               "        - name: ETCD_INITIAL_CLUSTER_TOKEN\n          value: INITIAL_CLUSTER_TOKEN_V1\n")
        self.assertEqual(scan({"e.yaml": k8s}), [])
        # ...but a constant-looking value for a PASSWORD is still a finding
        pw = k8s.replace("ETCD_INITIAL_CLUSTER_TOKEN", "DB_PASSWORD")
        self.assertEqual(ids(scan({"e.yaml": pw})), ["K8S_SECRET_IN_ENV"])

    def test_commented_socket_ignored_and_other_yaml_not_treated_as_compose(self):
        self.assertEqual(scan({"docker-compose.yml": "# - /var/run/docker.sock:/x\nservices: {}\n"}), [])
        self.assertEqual(scan({"config.yml": "privileged: true\n"}), [])


class TestTerraform(unittest.TestCase):
    def tf(self, text):
        return scan({"main.tf": text})

    def test_open_ssh_ingress_flagged_with_line(self):
        text = ('resource "aws_security_group" "a" {\n  ingress {\n    from_port = 22\n'
                '    to_port = 22\n    protocol = "tcp"\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
        fs = self.tf(text)
        self.assertEqual(ids(fs), ["TF_OPEN_INGRESS"])
        self.assertEqual(fs[0].line, 6)

    def test_public_web_ports_and_private_cidr_are_fine(self):
        web = ('resource "aws_security_group" "a" {\n  ingress {\n    from_port = 443\n'
               '    to_port = 443\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n'
               '  ingress {\n    from_port = 22\n    to_port = 22\n    cidr_blocks = ["10.0.0.0/8"]\n  }\n}\n')
        self.assertEqual(self.tf(web), [])

    def test_egress_open_is_not_flagged_and_rule_resource_form_is(self):
        egress = ('resource "aws_security_group" "a" {\n  egress {\n    from_port = 0\n'
                  '    to_port = 0\n    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n')
        self.assertEqual(self.tf(egress), [])
        rule = ('resource "aws_security_group_rule" "r" {\n  type = "ingress"\n  from_port = 3389\n'
                '  to_port = 3389\n  cidr_blocks = ["0.0.0.0/0"]\n}\n')
        self.assertEqual(ids(self.tf(rule)), ["TF_OPEN_INGRESS"])

    def test_misc_rules(self):
        text = ('resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
                'resource "aws_db_instance" "d" {\n  publicly_accessible = true\n'
                '  storage_encrypted = false\n}\n')
        self.assertEqual(ids(self.tf(text)), sorted(
            ["TF_PUBLIC_S3_ACL", "TF_DB_PUBLIC", "TF_UNENCRYPTED_STORAGE"]))
        ok = ('resource "aws_s3_bucket" "b" {\n  acl = "private"\n}\n'
              'resource "aws_db_instance" "d" {\n  publicly_accessible = false\n'
              '  storage_encrypted = true\n}\n')
        self.assertEqual(self.tf(ok), [])

    def test_hardcoded_credential_redacted_but_variables_fine(self):
        bad = 'provider "aws" {\n  secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n}\n'
        fs = self.tf(bad)
        self.assertEqual(ids(fs), ["TF_HARDCODED_CREDENTIAL"])
        self.assertNotIn("bPxRfiCY", fs[0].evidence)
        good = ('provider "aws" {\n  secret_key = var.secret_key\n}\n'
                'resource "x" "y" {\n  password = "${var.db_password}"\n  token = "changeme"\n}\n')
        self.assertEqual(self.tf(good), [])

    def test_test_fixture_and_example_paths_skipped_unless_opted_in(self):
        bad = 'resource "aws_s3_bucket" "b" {\n  acl = "public-read"\n}\n'
        for rel in ("internal/testdata/a/main.tf", "examples/x/main.tf", "tests/main.tf"):
            self.assertEqual(scan({rel: bad}), [], rel)
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "testdata" / "main.tf"
            p.parent.mkdir()
            p.write_text(bad)
            got = list(iac.scan(RepoContext(root=Path(d), scan_tests=True)))
        self.assertEqual(ids(got), ["TF_PUBLIC_S3_ACL"])

    def test_commented_lines_ignored_and_terraform_dir_skipped(self):
        self.assertEqual(self.tf('# acl = "public-read"\n// publicly_accessible = true\n'), [])
        self.assertEqual(scan({".terraform/modules/m/main.tf": 'acl = "public-read"\n'}), [])


if __name__ == "__main__":
    unittest.main()
