"""BlackByte Hardener — defensive repository hardening & auto-remediation.

Scans a repository for common security weaknesses (committed secrets,
insecure Dockerfiles, risky CI workflows, unpinned dependencies, missing
security hygiene files) and proposes concrete fixes.

Defensive only: it inspects code you own or are authorized to audit and
suggests remediations. It never attacks, exploits, or contacts third-party
systems.
"""

__version__ = "0.2.0"
__all__ = ["__version__"]
