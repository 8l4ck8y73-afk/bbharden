"""Indicative mapping from bbharden rules to well-known frameworks.

Purpose: help a report speak the language of auditors and managers. This is NOT an
assertion of compliance — passing every rule here does not make an organisation
compliant with anything, and a finding does not by itself prove non-compliance.
Controls are cited by identifier and short name only.

  OWASP CI/CD   OWASP Top 10 CI/CD Security Risks (CICD-SEC-1 ... 10)
  ISO 27001     ISO/IEC 27001:2022 Annex A control numbers
  Other         CIS Docker Benchmark, Kubernetes Pod Security Standards,
                OpenSSF Scorecard check names
"""

from __future__ import annotations

from typing import Dict, List

DISCLAIMER = ("Indicative mapping to help discussion with auditors; it is not a "
              "statement of compliance or non-compliance.")

OWASP = {
    "SEC3": "OWASP CI/CD CICD-SEC-3 Dependency Chain Abuse",
    "SEC4": "OWASP CI/CD CICD-SEC-4 Poisoned Pipeline Execution",
    "SEC5": "OWASP CI/CD CICD-SEC-5 Insufficient Pipeline-Based Access Controls",
    "SEC6": "OWASP CI/CD CICD-SEC-6 Insufficient Credential Hygiene",
    "SEC9": "OWASP CI/CD CICD-SEC-9 Improper Artifact Integrity Validation",
}
ISO = {
    "5.15": "ISO 27001:2022 A.5.15 Access control",
    "5.17": "ISO 27001:2022 A.5.17 Authentication information",
    "5.21": "ISO 27001:2022 A.5.21 Managing information security in the ICT supply chain",
    "8.2": "ISO 27001:2022 A.8.2 Privileged access rights",
    "8.3": "ISO 27001:2022 A.8.3 Information access restriction",
    "8.8": "ISO 27001:2022 A.8.8 Management of technical vulnerabilities",
    "8.9": "ISO 27001:2022 A.8.9 Configuration management",
    "8.20": "ISO 27001:2022 A.8.20 Networks security",
    "8.24": "ISO 27001:2022 A.8.24 Use of cryptography",
    "8.28": "ISO 27001:2022 A.8.28 Secure coding",
}
CIS_DOCKER_USER = "CIS Docker Benchmark 4.1 (non-root user)"
PSS_BASELINE = "Kubernetes Pod Security Standards: Baseline"
PSS_RESTRICTED = "Kubernetes Pod Security Standards: Restricted"
SC_PINNED = "OpenSSF Scorecard: Pinned-Dependencies"
SC_TOKEN = "OpenSSF Scorecard: Token-Permissions"
SC_POLICY = "OpenSSF Scorecard: Security-Policy"
SC_UPDATES = "OpenSSF Scorecard: Dependency-Update-Tool"

_SECRET = [OWASP["SEC6"], ISO["5.17"]]
_PIN = [OWASP["SEC3"], ISO["5.21"], SC_PINNED]
_CONTAINER_ROOT = [ISO["8.9"], PSS_RESTRICTED]
_CONTAINER_HOST = [ISO["8.9"], PSS_BASELINE]

_MAP: Dict[str, List[str]] = {
    # secrets
    "SECRET_*": _SECRET, "SECRET_IN_HISTORY": _SECRET,
    "DOCKER_SECRET_IN_ENV": _SECRET, "K8S_SECRET_IN_ENV": _SECRET,
    "COMPOSE_SECRET_IN_ENV": _SECRET, "TF_HARDCODED_CREDENTIAL": _SECRET,
    "HYGIENE_ENV_COMMITTED": _SECRET,
    "HYGIENE_GITIGNORE_SECRETS": _SECRET,
    # CI
    "CI_ACTION_UNPINNED": _PIN, "CI_ACTION_NO_REF": _PIN,
    "CI_SCRIPT_INJECTION": [OWASP["SEC4"], ISO["8.28"]],
    "CI_PR_TARGET_CHECKOUT": [OWASP["SEC4"], ISO["8.28"]],
    "CI_NO_PERMISSIONS": [OWASP["SEC5"], ISO["8.2"], SC_TOKEN],
    "CI_PERMISSIONS_WRITE_ALL": [OWASP["SEC5"], ISO["8.2"], SC_TOKEN],
    # dependencies
    "DEP_KNOWN_VULN": [OWASP["SEC3"], ISO["8.8"]],
    "DEP_UNPINNED_PY": _PIN, "DEP_UNPINNED_NPM": _PIN,
    "DEP_NPM_INSTALL_SCRIPT": [OWASP["SEC3"], ISO["5.21"]],
    # containers
    "DOCKER_RUNS_AS_ROOT": [ISO["8.9"], CIS_DOCKER_USER],
    "DOCKER_LATEST_TAG": [ISO["8.9"], ISO["5.21"], SC_PINNED],
    "DOCKER_CURL_PIPE_SHELL": [OWASP["SEC9"], ISO["5.21"]],
    "DOCKER_ADD_REMOTE": [OWASP["SEC9"], ISO["5.21"]],
    "K8S_PRIVILEGED": _CONTAINER_HOST, "K8S_HOST_NAMESPACE": _CONTAINER_HOST,
    "K8S_HOSTPATH": _CONTAINER_HOST, "K8S_DANGEROUS_CAPABILITY": _CONTAINER_HOST,
    "K8S_RUNS_AS_ROOT": _CONTAINER_ROOT, "K8S_PRIVILEGE_ESCALATION": _CONTAINER_ROOT,
    "K8S_IMAGE_NOT_PINNED": [ISO["8.9"], ISO["5.21"]],
    "COMPOSE_PRIVILEGED": [ISO["8.9"]], "COMPOSE_HOST_NETWORK": [ISO["8.9"]],
    "COMPOSE_HOST_NAMESPACE": [ISO["8.9"]], "COMPOSE_DOCKER_SOCKET": [ISO["8.9"], ISO["8.2"]],
    "COMPOSE_DANGEROUS_CAPABILITY": [ISO["8.9"]],
    "COMPOSE_IMAGE_NOT_PINNED": [ISO["8.9"], ISO["5.21"]],
    # terraform
    "TF_OPEN_INGRESS": [ISO["8.20"], ISO["8.3"]],
    "TF_DB_PUBLIC": [ISO["8.20"], ISO["8.3"]],
    "TF_PUBLIC_S3_ACL": [ISO["8.3"], ISO["5.15"]],
    "TF_UNENCRYPTED_STORAGE": [ISO["8.24"]],
    # hygiene
    "HYGIENE_NO_SECURITY_MD": [SC_POLICY],
    "HYGIENE_NO_DEPENDABOT": [SC_UPDATES, ISO["8.8"]],
}


def references(rule_id: str) -> List[str]:
    """Framework references for a rule (empty for custom/unknown rules)."""
    if rule_id in _MAP:
        return list(_MAP[rule_id])
    if rule_id.startswith("SECRET_"):
        return list(_MAP["SECRET_*"])
    return []
