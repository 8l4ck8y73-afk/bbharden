"""Dockerfile hardening checks."""

from __future__ import annotations

import re
from typing import Iterator

from ..findings import Finding, Severity


# `dockerfile.py`, `dockerfile.md`, ... are source/docs ABOUT Dockerfiles, not
# Dockerfiles. Real variants look like `Dockerfile`, `Dockerfile.prod`,
# `Dockerfile.dev`, or `app.dockerfile`.
_NOT_DOCKERFILE_EXT = {
    "py", "pyc", "md", "txt", "rst", "js", "ts", "json", "yml", "yaml",
    "toml", "cfg", "ini", "sh", "go", "rs", "java", "html", "xml", "lock",
}


def _is_dockerfile(name: str) -> bool:
    base = name.lower()
    if base == "dockerfile":
        return True
    if base.endswith(".dockerfile"):
        return True
    if base.startswith("dockerfile."):
        return base.rsplit(".", 1)[-1] not in _NOT_DOCKERFILE_EXT
    return False


def _dockerfiles(ctx):
    for p in ctx.text_files():
        if _is_dockerfile(p.name):
            yield p


def _parse_from(line: str):
    """Parse `FROM [--platform=x] image[:tag][@digest] [AS stage]`.

    Returns (image, stage_alias_or_None) or None if the line is not parseable.
    """
    toks = line.split()
    if len(toks) < 2 or toks[0].lower() != "from":
        return None
    rest = [t for t in toks[1:] if not t.startswith("--")]
    if not rest:
        return None
    image = rest[0]
    stage = rest[2] if len(rest) >= 3 and rest[1].lower() == "as" else None
    return image, stage


def _base_image_problem(image: str, stages: set, arg_defaults: dict):
    """Return a reason string if the base image is unpinned, else None.

    Never flags: `scratch`, a reference to an earlier build stage, a pinned
    digest, or a variable whose value can't be known statically.
    """
    if image.lower() == "scratch" or image in stages:
        return None
    m = re.fullmatch(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?", image)
    if m:
        default = arg_defaults.get(m.group(1))
        if not default:
            return None  # supplied at build time; can't judge statically
        image = default
    if "$" in image:
        return None  # partially templated; don't guess
    if "@sha256:" in image:
        return None
    # A ':' after the last '/' is a tag; a ':' earlier is a registry port.
    name, _, tag = image.rpartition(":") if ":" in image.rsplit("/", 1)[-1] else (image, "", "")
    if not tag:
        return "has no tag, so it implicitly floats on :latest"
    if tag.lower() == "latest":
        return "uses the mutable :latest tag"
    return None


def scan(ctx) -> Iterator[Finding]:
    for path in _dockerfiles(ctx):
        name = ctx.rel(path)
        text = ctx.read_text(path)
        if not text:
            continue
        lines = text.splitlines()
        has_user = False
        last_from_line = 0
        stages: set = set()
        arg_defaults: dict = {}

        for i, raw in enumerate(lines, start=1):
            line = raw.strip()
            low = line.lower()

            am = re.match(r"(?i)arg\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line)
            if am:
                arg_defaults.setdefault(am.group(1), am.group(2).strip("\"'"))

            if low.startswith("from "):
                last_from_line = i
                parsed = _parse_from(line)
                if parsed:
                    image, stage = parsed
                    why = _base_image_problem(image, stages, arg_defaults)
                    if stage:
                        stages.add(stage)
                    if why:
                        yield Finding(
                            rule_id="DOCKER_LATEST_TAG",
                            title="Base image is not pinned to a version",
                            severity=Severity.MEDIUM,
                            file=name, line=i,
                            message=f"Base image `{image}` {why}. Unpinned images make "
                                    "builds non-reproducible and can silently pull in "
                                    "vulnerable layers.",
                            remediation="Pin the base image to a specific version and, "
                                        "ideally, a digest: `FROM image:1.2.3@sha256:...`.",
                            evidence=line, cwe="CWE-1104",
                        )

            if low.startswith("user "):
                if low.split()[1:2] not in ([], ["root"], ["0"]):
                    has_user = True

            if re.match(r"add\s+https?://", low):
                yield Finding(
                    rule_id="DOCKER_ADD_REMOTE",
                    title="ADD used to fetch a remote URL",
                    severity=Severity.MEDIUM,
                    file=name, line=i,
                    message="ADD with a URL fetches unverified content at build time.",
                    remediation="Use `curl`/`wget` with a pinned URL and verify a "
                                "checksum, or vendor the file and use COPY.",
                    evidence=line, cwe="CWE-494",
                )

            if re.search(r"(curl|wget)\b.*\|\s*(sudo\s+)?(sh|bash)", low):
                yield Finding(
                    rule_id="DOCKER_CURL_PIPE_SHELL",
                    title="Remote script piped into a shell",
                    severity=Severity.HIGH,
                    file=name, line=i,
                    message="Piping a downloaded script straight into a shell runs "
                            "unverified code during the build.",
                    remediation="Download to a file, verify its checksum/signature, "
                                "then execute it.",
                    evidence=line, cwe="CWE-494",
                )

            if re.match(r"(env|arg)\s", low) and re.search(
                r"(?i)(password|secret|token|api[_-]?key|private[_-]?key)\s*=", line
            ):
                yield Finding(
                    rule_id="DOCKER_SECRET_IN_ENV",
                    title="Secret baked into an image layer",
                    severity=Severity.HIGH,
                    file=name, line=i,
                    message="Secrets in ENV/ARG persist in image layers and history.",
                    remediation="Pass secrets at runtime, or use BuildKit "
                                "`--mount=type=secret` which is not persisted.",
                    evidence=line, cwe="CWE-798",
                )

        if last_from_line and not has_user:
            yield Finding(
                rule_id="DOCKER_RUNS_AS_ROOT",
                title="Container runs as root",
                severity=Severity.HIGH,
                file=name, line=last_from_line,
                message="No non-root USER is set, so the container (and anything "
                        "that breaks out of the app) runs as root.",
                remediation="Create and switch to an unprivileged user before the "
                            "entrypoint:\n    RUN useradd --system --uid 10001 app\n"
                            "    USER app",
                evidence="(no USER instruction found)", cwe="CWE-250",
            )
