"""Infrastructure-as-code checks: Kubernetes manifests, docker-compose, Terraform.

Line/indentation analysis only (no YAML or HCL dependency, nothing is executed or
rendered). The rules are deliberately few and precise: each one names a
configuration that is dangerous on its own, so a hit is worth a human's time.
Secret values are redacted from evidence.
"""

from __future__ import annotations

import re
from typing import Iterator, List, Optional, Tuple

from ..findings import Finding, Severity
from .dockerfile import _base_image_problem

_MAX_LINE = 2000
_TEMPLATED = re.compile(r"\{\{|\$\{|\$\(|<%")
_SECRET_KEY = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|access[_-]?key|private[_-]?key)")
_PLACEHOLDER = re.compile(
    r"(?i)^(changeme|change[_-]?me|example|placeholder|your[_-].*|<.*>|x{3,}|\*{3,}|"
    r"todo|none|null|true|false|\.{3,}|redacted)$")
_K8S_WORKLOAD = re.compile(
    r"^kind:\s*(Pod|Deployment|StatefulSet|DaemonSet|ReplicaSet|ReplicationController|"
    r"Job|CronJob)\s*(#.*)?$")
_COMPOSE_NAME = re.compile(r"(?i)^(docker-)?compose([.\-].+)?\.ya?ml$")
_KV = re.compile(r"""^(?P<ind>\s*)(?:-\s+)?(?P<key>[A-Za-z0-9_.\-/"']+)\s*:\s*(?P<val>.*?)\s*$""")
_DANGEROUS_CAPS = {"ALL": Severity.HIGH, "SYS_ADMIN": Severity.HIGH,
                   "SYS_PTRACE": Severity.HIGH, "SYS_MODULE": Severity.HIGH,
                   "DAC_READ_SEARCH": Severity.MEDIUM, "NET_ADMIN": Severity.MEDIUM}
# `ETCD_INITIAL_CLUSTER_TOKEN=INITIAL_CLUSTER_TOKEN_V1`: an ALL_CAPS constant is an
# identifier, not a credential.
_CONSTANT_LIKE = re.compile(r"^[A-Z][A-Z0-9_]{7,}$")
_SENSITIVE_HOST_PATHS = {"/", "/etc", "/proc", "/sys", "/root", "/var/run/docker.sock",
                         "/run/docker.sock", "/var/lib/kubelet", "/var/lib/docker"}


def _looks_secret(key: str, v: str) -> bool:
    return bool(v) and not _PLACEHOLDER.match(v) and not _TEMPLATED.search(v) and \
        not (_CONSTANT_LIKE.match(v) and not re.search(r"(?i)pass|secret", key))


def _redact(v: str) -> str:
    return "****" if len(v) <= 8 else f"{v[:2]}…{v[-1:]} ({len(v)} chars)"


def _clean_value(raw: str) -> str:
    v = raw.split(" #", 1)[0].strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        v = v[1:-1]
    return v


def _kv(line: str) -> Optional[Tuple[int, str, str]]:
    """(indent, key, value) for a `key: value` YAML line, else None."""
    if line.lstrip().startswith("#") or len(line) > _MAX_LINE:
        return None
    m = _KV.match(line)
    if not m:
        return None
    return len(m.group("ind")), m.group("key").strip("\"'"), _clean_value(m.group("val"))


def _is_true(v: str) -> bool:
    return v.lower() in ("true", "yes", "on")


def _finding(rule, title, sev, file, line, message, remediation, evidence="", cwe=None):
    return Finding(rule_id=rule, title=title, severity=sev, file=file, line=line,
                   message=message, remediation=remediation, evidence=evidence, cwe=cwe)


def _image_finding(rule, file, lineno, image):
    if not image or _TEMPLATED.search(image):
        return None
    why = _base_image_problem(image, set(), {})
    if not why:
        return None
    return _finding(
        rule, "Container image is not pinned to a version", Severity.MEDIUM, file, lineno,
        f"Image `{image}` {why}. The same manifest can run different code tomorrow.",
        "Pin to a specific version and ideally a digest: `image:1.2.3@sha256:...`.",
        image, "CWE-1104")


# --------------------------------------------------------------- Kubernetes
def _split_docs(lines: List[str]):
    """Yield (offset, doc_lines) for each `---`-separated YAML document."""
    start = 0
    for i, ln in enumerate(lines + ["---"]):
        if ln.startswith("---"):
            if i > start:
                yield start, lines[start:i]
            start = i + 1


def _scan_k8s(name: str, lines: List[str]) -> Iterator[Finding]:
    for off, doc in _split_docs(lines):
        if not any(_K8S_WORKLOAD.match(ln) for ln in doc):
            continue
        n = lambda i: off + i + 1                      # 1-based file line number
        caps_indent = None                             # inside `capabilities.add`
        for i, ln in enumerate(doc):
            kv = _kv(ln)
            if kv is None:
                stripped = ln.strip()
                if caps_indent is not None and stripped.startswith("- "):
                    cap = _clean_value(stripped[2:]).upper()
                    if cap in _DANGEROUS_CAPS:
                        yield _finding(
                            "K8S_DANGEROUS_CAPABILITY",
                            f"Container adds the {cap} capability", _DANGEROUS_CAPS[cap],
                            name, n(i),
                            f"Adding `{cap}` gives the container powers close to root on "
                            "the node.", "Drop all capabilities and add back only what is "
                            "needed: `drop: [ALL]`.", cap, "CWE-250")
                continue
            ind, key, val = kv
            if caps_indent is not None and ind <= caps_indent and key != "add":
                caps_indent = None
            if key == "add":
                caps_indent = ind
                for cap in re.findall(r"[A-Z_]+", val if val.startswith("[") else ""):
                    if cap in _DANGEROUS_CAPS:
                        yield _finding("K8S_DANGEROUS_CAPABILITY",
                                       f"Container adds the {cap} capability",
                                       _DANGEROUS_CAPS[cap], name, n(i),
                                       f"Adding `{cap}` gives the container powers close to "
                                       "root on the node.",
                                       "Drop all capabilities and add back only what is "
                                       "needed.", cap, "CWE-250")
            if key == "privileged" and _is_true(val):
                yield _finding("K8S_PRIVILEGED", "Privileged container", Severity.HIGH,
                               name, n(i),
                               "A privileged container has nearly unrestricted access to "
                               "the node: a compromise of the app is a compromise of the host.",
                               "Remove `privileged: true`; grant only the specific "
                               "capabilities needed.", ln.strip(), "CWE-250")
            elif key in ("hostPID", "hostIPC") and _is_true(val):
                yield _finding("K8S_HOST_NAMESPACE", f"Pod shares the host's {key[4:]} "
                               "namespace", Severity.HIGH, name, n(i),
                               f"`{key}: true` lets the pod see or signal host processes.",
                               f"Remove `{key}: true`.", ln.strip(), "CWE-250")
            elif key == "hostNetwork" and _is_true(val):
                yield _finding("K8S_HOST_NAMESPACE", "Pod uses the host network",
                               Severity.MEDIUM, name, n(i),
                               "`hostNetwork: true` bypasses network policies and exposes "
                               "node-local services.", "Remove `hostNetwork: true`.",
                               ln.strip(), "CWE-668")
            elif key == "allowPrivilegeEscalation" and _is_true(val):
                yield _finding("K8S_PRIVILEGE_ESCALATION", "Privilege escalation allowed",
                               Severity.MEDIUM, name, n(i),
                               "Processes may gain more privileges than their parent.",
                               "Set `allowPrivilegeEscalation: false`.", ln.strip(), "CWE-250")
            elif (key == "runAsUser" and val == "0") or \
                    (key == "runAsNonRoot" and val.lower() == "false"):
                yield _finding("K8S_RUNS_AS_ROOT", "Container runs as root", Severity.MEDIUM,
                               name, n(i), "The container process runs as UID 0.",
                               "Set `runAsNonRoot: true` and a non-zero `runAsUser`.",
                               ln.strip(), "CWE-250")
            elif key == "hostPath":
                path = ""
                for nxt in doc[i + 1:i + 4]:
                    nk = _kv(nxt)
                    if nk and nk[1] == "path":
                        path = nk[2].rstrip("/") or "/"
                        break
                sensitive = path in _SENSITIVE_HOST_PATHS
                yield _finding("K8S_HOSTPATH",
                               "Pod mounts a sensitive host path" if sensitive
                               else "Pod mounts a host path",
                               Severity.HIGH if sensitive else Severity.MEDIUM, name, n(i),
                               f"`hostPath` {path or '(unknown)'} exposes the node's "
                               "filesystem to the pod.",
                               "Use a PersistentVolume, emptyDir or ConfigMap instead.",
                               path or "hostPath", "CWE-668")
            elif key == "image":
                f = _image_finding("K8S_IMAGE_NOT_PINNED", name, n(i), val)
                if f:
                    yield f
            elif key == "name" and _SECRET_KEY.search(val) and \
                    ln.lstrip().startswith("-"):
                # `- name: DB_PASSWORD` followed by a literal `value:` (not valueFrom).
                for nxt in doc[i + 1:i + 3]:
                    nk = _kv(nxt)
                    if nk and nk[1] == "value" and nk[0] >= ind:
                        v = nk[2]
                        if _looks_secret(val, v):
                            yield _finding(
                                "K8S_SECRET_IN_ENV", "Secret value written into the manifest",
                                Severity.HIGH, name, n(i),
                                f"Environment variable `{val}` has a literal value in the "
                                "manifest, so it lives in git and in the cluster spec.",
                                "Use a Secret with `valueFrom.secretKeyRef` (or an external "
                                "secrets operator), and rotate this value.",
                                f"{val}={_redact(v)}", "CWE-798")
                        break
                    if nk and nk[1] == "valueFrom":
                        break


# ----------------------------------------------------------- docker-compose
def _scan_compose(name: str, lines: List[str]) -> Iterator[Finding]:
    in_env, env_indent = False, -1
    for i, ln in enumerate(lines, start=1):
        s = ln.strip()
        kv = _kv(ln)
        if in_env:
            if s and not s.startswith("#") and (len(ln) - len(ln.lstrip())) <= env_indent \
                    and not s.startswith("-"):
                in_env = False
            else:
                key = val = None
                if s.startswith("- ") and "=" in s:
                    key, _, val = s[2:].partition("=")
                    val = _clean_value(val)
                elif kv and not s.startswith("- "):
                    key, val = kv[1], kv[2]
                if key and _SECRET_KEY.search(key) and _looks_secret(key, val):
                    yield _finding(
                        "COMPOSE_SECRET_IN_ENV", "Secret value written into compose file",
                        Severity.HIGH, name, i,
                        f"`{key.strip()}` has a literal value in the compose file, so it is "
                        "committed to git.", "Reference an `.env` file kept out of git, "
                        "or use Docker secrets: `${%s}`." % key.strip(),
                        f"{key.strip()}={_redact(val)}", "CWE-798")
                continue
        if "docker.sock" in ln and not s.startswith("#") and (
                s.startswith("- ") or (kv is not None and kv[1] == "source")):
            # A mount. `command: -H unix:///var/run/docker.sock` (a CLI flag that
            # tells a tool where the socket is) is not one and is not flagged.
            yield _finding(
                "COMPOSE_DOCKER_SOCKET", "Docker socket mounted into a container",
                Severity.HIGH, name, i,
                "Access to the Docker socket is root on the host: anything that "
                "compromises this container controls every container.",
                "Remove the mount, or put a socket proxy with a restricted API in "
                "front of it.", s[:120], "CWE-250")
            continue
        if kv is None:
            continue
        ind, key, val = kv
        if key == "environment":
            if val.startswith(("[", "{")) is False:
                in_env, env_indent = True, ind
        elif key == "privileged" and _is_true(val):
            yield _finding("COMPOSE_PRIVILEGED", "Privileged container", Severity.HIGH,
                           name, i, "A privileged container has nearly unrestricted access "
                           "to the host.", "Remove `privileged: true`; use `cap_add` with "
                           "the specific capability if one is needed.", s, "CWE-250")
        elif key == "network_mode" and val == "host":
            yield _finding("COMPOSE_HOST_NETWORK", "Container uses the host network",
                           Severity.MEDIUM, name, i, "`network_mode: host` removes network "
                           "isolation.", "Publish only the ports you need.", s, "CWE-668")
        elif key in ("pid", "ipc") and val == "host":
            yield _finding("COMPOSE_HOST_NAMESPACE", f"Container shares the host {key} "
                           "namespace", Severity.HIGH, name, i,
                           f"`{key}: host` lets the container see or signal host processes.",
                           f"Remove `{key}: host`.", s, "CWE-250")
        elif key == "image":
            f = _image_finding("COMPOSE_IMAGE_NOT_PINNED", name, i, val)
            if f:
                yield f
        elif key == "cap_add":
            for cap in re.findall(r"[A-Z_]+", val):
                if cap in _DANGEROUS_CAPS:
                    yield _finding("COMPOSE_DANGEROUS_CAPABILITY",
                                   f"Container adds the {cap} capability",
                                   _DANGEROUS_CAPS[cap], name, i,
                                   f"`{cap}` is close to root on the host.",
                                   "Add only the narrowest capability required.", cap,
                                   "CWE-250")
    # block-style `cap_add:` lists
    for i, ln in enumerate(lines):
        kv = _kv(ln)
        if kv and kv[1] == "cap_add" and not kv[2]:
            for j in range(i + 1, min(i + 12, len(lines))):
                s = lines[j].strip()
                if not s.startswith("- "):
                    if s and not s.startswith("#"):
                        break
                    continue
                cap = _clean_value(s[2:]).upper()
                if cap in _DANGEROUS_CAPS:
                    yield _finding("COMPOSE_DANGEROUS_CAPABILITY",
                                   f"Container adds the {cap} capability",
                                   _DANGEROUS_CAPS[cap], name, j + 1,
                                   f"`{cap}` is close to root on the host.",
                                   "Add only the narrowest capability required.", cap,
                                   "CWE-250")


# ---------------------------------------------------------------- Terraform
_OPEN_CIDR = re.compile(r'"(0\.0\.0\.0/0|::/0)"')
_TF_ASSIGN = re.compile(r'^\s*([A-Za-z0-9_]+)\s*=\s*(.*?)\s*$')
_WEB_PORTS = {80, 443}


def _tf_blocks(lines: List[str]):
    """Yield (header, start_index, block_lines) for every `{ ... }` block."""
    stack: List[Tuple[str, int]] = []
    for i, ln in enumerate(lines):
        code = ln.split("#", 1)[0].split("//", 1)[0]
        opens, closes = code.count("{"), code.count("}")
        if opens and code.rstrip().endswith("{"):
            stack.append((code.strip(), i))
            opens -= 1
        for _ in range(closes):
            if stack:
                header, start = stack.pop()
                yield header, start, lines[start:i + 1]


def _scan_terraform(name: str, lines: List[str]) -> Iterator[Finding]:
    for header, start, block in _tf_blocks(lines):
        flat = "\n".join(block)
        is_ingress = bool(re.match(r"^ingress\s*\{", header)) or (
            header.startswith("resource") and (
                "aws_vpc_security_group_ingress_rule" in header or
                ("aws_security_group_rule" in header and
                 re.search(r'type\s*=\s*"ingress"', flat))))
        if not is_ingress:
            continue
        m = _OPEN_CIDR.search(flat)
        if not m:
            continue
        ports = {}
        for ln in block:
            a = _TF_ASSIGN.match(ln)
            if a and a.group(1) in ("from_port", "to_port"):
                try:
                    ports[a.group(1)] = int(a.group(2).strip('"'))
                except ValueError:
                    pass
        if ports and set(ports.values()) <= _WEB_PORTS:
            continue                              # public web ports are intentional
        lineno = start + 1
        for off, ln in enumerate(block):
            if _OPEN_CIDR.search(ln):
                lineno = start + off + 1
                break
        rng = (f"{ports.get('from_port', '?')}-{ports.get('to_port', '?')}"
               if ports else "all ports")
        yield _finding(
            "TF_OPEN_INGRESS", "Security group open to the whole internet", Severity.HIGH,
            name, lineno,
            f"Ingress from {m.group(1)} on {rng} exposes the service to anyone. Remote "
            "admin ports (SSH 22, RDP 3389) and databases are scanned within minutes.",
            "Restrict the CIDR to known ranges, put the service behind a load balancer or "
            "VPN, or use SSM/bastion access.", m.group(0), "CWE-284")

    for i, ln in enumerate(lines, start=1):
        if len(ln) > _MAX_LINE or ln.lstrip().startswith(("#", "//")):
            continue
        a = _TF_ASSIGN.match(ln.split(" #", 1)[0])
        if not a:
            continue
        key, raw = a.group(1), a.group(2)
        val = _clean_value(raw)
        if key == "acl" and val in ("public-read", "public-read-write"):
            yield _finding("TF_PUBLIC_S3_ACL", "Storage bucket ACL is public", Severity.HIGH,
                           name, i, f"`acl = \"{val}\"` makes the bucket's objects readable"
                           f"{' and writable' if val.endswith('write') else ''} by anyone.",
                           "Use a private ACL and grant access through bucket policies.",
                           ln.strip(), "CWE-732")
        elif key == "publicly_accessible" and raw.lower().startswith("true"):
            yield _finding("TF_DB_PUBLIC", "Database is publicly accessible", Severity.HIGH,
                           name, i, "The database endpoint is reachable from the internet.",
                           "Set `publicly_accessible = false` and reach it from inside the VPC.",
                           ln.strip(), "CWE-284")
        elif key in ("storage_encrypted", "encrypted") and raw.lower().startswith("false"):
            yield _finding("TF_UNENCRYPTED_STORAGE", "Storage encryption disabled",
                           Severity.MEDIUM, name, i,
                           f"`{key} = false` leaves data unencrypted at rest.",
                           f"Set `{key} = true` (and a KMS key where required).",
                           ln.strip(), "CWE-311")
        elif _SECRET_KEY.fullmatch(key) or key in ("access_key", "secret_key", "client_secret"):
            if raw.startswith('"') and val and len(val) >= 8 and \
                    not _TEMPLATED.search(val) and not _PLACEHOLDER.match(val):
                yield _finding("TF_HARDCODED_CREDENTIAL", "Credential written into Terraform",
                               Severity.HIGH, name, i,
                               f"`{key}` has a literal value, so it is stored in git and in "
                               "the Terraform state.",
                               "Use a variable marked `sensitive`, a secrets manager data "
                               "source, or environment variables — and rotate this value.",
                               f"{key}={_redact(val)}", "CWE-798")


def scan(ctx) -> Iterator[Finding]:
    from .secrets import _is_ignored      # same policy: tests/fixtures/examples
    for path in ctx.text_files():
        if _is_ignored(ctx.rel(path), getattr(ctx, "scan_tests", False)):
            continue                      # intentionally insecure by design
        low = path.name.lower()
        is_yaml = low.endswith((".yaml", ".yml"))
        is_tf = low.endswith(".tf")
        if not (is_yaml or is_tf):
            continue
        if is_yaml and ".github/workflows" in ctx.rel(path):
            continue
        text = ctx.read_text(path)
        if not text:
            continue
        lines = text.splitlines()
        name = ctx.rel(path)
        if is_tf:
            yield from _scan_terraform(name, lines)
        elif _COMPOSE_NAME.match(path.name):
            yield from _scan_compose(name, lines)
        elif any(ln.startswith("apiVersion:") for ln in lines):
            yield from _scan_k8s(name, lines)
