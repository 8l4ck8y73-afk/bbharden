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
    if image.lower() == "scratch" or image.lower() in stages:
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


def _logical_lines(text: str):
    """Yield (first_line_number, joined_instruction) honouring `\\` continuations.

    Comment lines inside a continued instruction are dropped, as Docker does.
    """
    buf, start = [], 0
    for i, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if buf and stripped.startswith("#"):
            continue
        if not buf:
            if not stripped or stripped.startswith("#"):
                continue
            start = i
        if stripped.endswith("\\"):
            buf.append(stripped[:-1].strip())
            continue
        buf.append(stripped)
        yield start, " ".join(p for p in buf if p)
        buf = []
    if buf:
        yield start, " ".join(p for p in buf if p)


_SECRET_NAME = re.compile(
    r"(?i)(password|secret|token|api[_-]?key|private[_-]?key)\s*=")
_VALUE = re.compile(r"=\s*(\"[^\"]*\"|'[^']*'|\S+)")


def _redact_assignments(line: str) -> str:
    """Hide every value after `=` so a baked-in secret never reaches a report."""
    return _VALUE.sub("=****", line)


def _user_is_root(spec: str) -> bool:
    user = spec.split(":", 1)[0].strip().strip("\"'")
    return user in ("root", "0")


# Directory or file names that indicate a build/CI/test image rather than a
# deployed service.
_TOOLING_PATH = re.compile(
    r"(?i)(^|/)(tests?|testing|ci|\.?devcontainer|builders?|build|tools?|scripts|e2e|fixtures?)/"
    r"|(^|/)Dockerfile[.-](dev|test|tests|ci|build|builder)$"
    r"|(^|/)(dev|test|ci|build)\.Dockerfile$")


def scan(ctx) -> Iterator[Finding]:
    for path in _dockerfiles(ctx):
        name = ctx.rel(path)
        text = ctx.read_text(path)
        if not text:
            continue
        # Only the LAST stage ships, so USER is judged per stage and the verdict
        # comes from the final one (a USER in a throwaway build stage is moot).
        last_from_line = 0
        final_user_root = True        # no USER instruction == root
        stages: set = set()
        arg_defaults: dict = {}

        for i, line in _logical_lines(text):
            low = line.lower()

            am = re.match(r"(?i)arg\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)", line)
            if am:
                arg_defaults.setdefault(am.group(1), am.group(2).strip("\"'"))

            if low.startswith("from "):
                last_from_line = i
                final_user_root = True            # new stage: reset
                parsed = _parse_from(line)
                if parsed:
                    image, stage = parsed
                    why = _base_image_problem(image, stages, arg_defaults)
                    if stage:
                        stages.add(stage.lower())
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
                parts = line.split(None, 1)
                if len(parts) == 2:
                    final_user_root = _user_is_root(parts[1].split()[0])

            if re.match(r"add\s+(--\S+\s+)*https?://", low):
                yield Finding(
                    rule_id="DOCKER_ADD_REMOTE",
                    title="ADD used to fetch a remote URL",
                    severity=Severity.MEDIUM,
                    file=name, line=i,
                    message="ADD with a URL fetches unverified content at build time.",
                    remediation="Use `curl`/`wget` with a pinned URL and verify a "
                                "checksum, or vendor the file and use COPY.",
                    evidence=line[:160], cwe="CWE-494",
                )

            if re.search(r"(curl|wget)\b.*\|\s*(sudo\s+)?(sh|bash)\b", low):
                yield Finding(
                    rule_id="DOCKER_CURL_PIPE_SHELL",
                    title="Remote script piped into a shell",
                    severity=Severity.HIGH,
                    file=name, line=i,
                    message="Piping a downloaded script straight into a shell runs "
                            "unverified code during the build.",
                    remediation="Download to a file, verify its checksum/signature, "
                                "then execute it.",
                    evidence=line[:160], cwe="CWE-494",
                )

            if re.match(r"(env|arg)\s", low) and _SECRET_NAME.search(line):
                yield Finding(
                    rule_id="DOCKER_SECRET_IN_ENV",
                    title="Secret baked into an image layer",
                    severity=Severity.HIGH,
                    file=name, line=i,
                    message="Secrets in ENV/ARG persist in image layers and history.",
                    remediation="Pass secrets at runtime, or use BuildKit "
                                "`--mount=type=secret` which is not persisted.",
                    evidence=_redact_assignments(line)[:160], cwe="CWE-798",
                )

        if last_from_line and final_user_root:
            tooling = bool(_TOOLING_PATH.search(name))
            yield Finding(
                rule_id="DOCKER_RUNS_AS_ROOT",
                title="Container runs as root" + (" (build/test image)" if tooling else ""),
                # Build, CI and test images are rarely deployed; root there is a
                # smaller risk than in a service image, so rate it lower.
                severity=Severity.MEDIUM if tooling else Severity.HIGH,
                file=name, line=last_from_line,
                message="The final stage has no non-root USER, so the container "
                        "(and anything that breaks out of the app) runs as root."
                        + (" Its location suggests a build/CI/test image; confirm it "
                           "is never deployed." if tooling else ""),
                remediation="Create and switch to an unprivileged user before the "
                            "entrypoint:\n    RUN useradd --system --uid 10001 app\n"
                            "    USER app",
                evidence="(no non-root USER in the final stage)", cwe="CWE-250",
            )
