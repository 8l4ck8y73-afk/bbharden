"""Example config with hardcoded secrets (for scanner testing only)."""

DEBUG = True

# Hardcoded credentials — the scanner should flag these.
# NOTE: these are synthetic, non-functional samples. We deliberately avoid any
# string that matches a real provider's live-secret signature, so this demo file
# does not trip GitHub push protection. The Stripe/private-key rules are covered
# by fixtures generated at test time instead (see tests/test_scanners.py).
DATABASE_PASSWORD = "S3cr3tP@ssw0rd_prod_2026_xyz"
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # AWS's own documented example key
api_key = "placeholder"  # should NOT be flagged (placeholder)
