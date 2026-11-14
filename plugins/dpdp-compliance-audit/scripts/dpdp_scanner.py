#!/usr/bin/env python3
"""
DPDPA Compliance Scanner v2.0
Scans codebases for compliance gaps against the Indian Digital Personal
Data Protection Act (DPDPA) 2023 and DPDP Rules 2025.

Usage:
    python3 dpdp_scanner.py <target_directory> [options]

Options:
    --json              Print results as JSON to stdout (for agent consumption)
    --json-out PATH     Also write the JSON report to PATH (feeds generate_pdf_report.py)
    --markdown-out PATH Write the Markdown report to PATH (default: <target>/dpdpa_compliance_report.md)
    --target-type TYPE  One of: webapp, api, ml-pipeline, mobile, general (default: general)
    --exclude PATTERN   Glob pattern to exclude (can be repeated)
    --company-name NAME Organisation name to print on the report
    --company-uuid UUID Organisation UUID to print on the report

For a properly formatted PDF (real tables, severity colors, grouped findings
with fixes), run generate_pdf_report.py on the --json-out file rather than
converting the Markdown report with md-to-pdf.py.
"""

import os
import re
import sys
import json
import fnmatch
from datetime import datetime, timezone, timedelta

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

IGNORE_DIRS = {
    '.git', 'node_modules', 'venv', 'env', '__pycache__', 'dist', 'build',
    '.next', '.nuxt', '.output', 'coverage', '.nyc_output', '.pytest_cache',
    '.mypy_cache', '.tox', 'egg-info', '.eggs', '.terraform',
    # framework/tooling build output and caches — generated, not product code
    '.mastra', '.turbo', '.vercel', '.cache', '.parcel-cache', '.expo',
    'Pods', '.gradle', '.idea',
    # test code — fixtures/mocks routinely contain fake "secrets" and
    # synthetic PII that aren't real production findings
    'test', 'tests', '__tests__', '__mocks__', 'spec', 'specs', 'cypress',
    'e2e', '__fixtures__', 'fixtures',
    # agent / IDE / local tooling — noise, not product code
    '.agents', '.cursor', '.claude', '.codex', '.gemini', '.vscode',
    'reference-docs', '.DS_Store',
}

IGNORE_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.ico', '.svg', '.webp', '.bmp',
    '.mp4', '.mp3', '.wav', '.ogg', '.webm',
    '.pdf', '.zip', '.tar', '.gz', '.bz2', '.7z', '.rar',
    '.db', '.sqlite', '.sqlite3', '.pyc', '.pyo', '.whl',
    '.woff', '.woff2', '.ttf', '.eot', '.otf',
    '.lock', '.map', '.min.js', '.min.css', '.json',
    # embedded DB files (DuckDB, SQLite WAL/SHM sidecar files) — binary, not source
    '.duckdb', '.wal', '.db-wal', '.db-shm',
}

# Lockfiles and specific files to completely bypass
IGNORE_FILES = {
    'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock',
    'Cargo.lock', 'Gemfile.lock', 'poetry.lock', 'mix.lock',
}

# Files we specifically WANT to scan even though they don't have code extensions
# Note: .env* intentionally NOT scanned (local secrets). Presence vs .gitignore
# is still checked separately in run_scan.
CONFIG_FILES = {
    'docker-compose.yml', 'docker-compose.yaml', 'Dockerfile',
    '.gitignore', 'requirements.txt', 'package.json',
}

# ---------------------------------------------------------------------------
# DPDPA Pillar Definitions
# ---------------------------------------------------------------------------

# Penalty figures below cite THE SCHEDULE (see Section 33), which fixes 8
# specific penalty items — NOT a flat per-pillar amount. Most obligation
# violations (sections 4-12 & 14) fall under Schedule Item 1, capped at
# ₹200 Crores (the Board may halve or double this under Section 33(3), i.e.
# ₹100-400 Crores in practice). Security safeguards specifically (Section
# 8(5)) and breach notification (Section 8(6)) each have their own Item
# (2 and 3 respectively), also capped at ₹200 Crores. Only Item 8 (defying
# a Board direction, Section 34) reaches ₹250 Crores. Verified against
# dpdpa.com's Section 33 commentary (secondary source, not the official
# Gazette) — treat exact figures as directionally correct pending legal
# review, not a substitute for professional advice.
PILLARS = {
    "consent_notice": {
        "name": "Consent & Notice Management",
        "sections": "Sections 5 & 6",
        "max_penalty": "₹200 Crores (Schedule Item 1)",
    },
    "security_safeguards": {
        "name": "Security Safeguards & Encryption",
        "sections": "Section 8",
        "max_penalty": "₹200 Crores (Schedule Item 2 — Section 8(5))",
    },
    "data_retention": {
        "name": "Data Retention & Lifecycle",
        "sections": "Section 8(7) & 12",
        "max_penalty": "₹200 Crores (Schedule Item 1)",
    },
    "minor_protection": {
        "name": "Children's Data Safeguards",
        "sections": "Section 9",
        "max_penalty": "₹200 Crores (Schedule Item 1)",
    },
    "data_principal_rights": {
        "name": "Data Principal Rights",
        "sections": "Sections 11–14",
        "max_penalty": "₹200 Crores (Schedule Item 1 — Sections 11, 12 & 14; Section 13 grievance redressal is not separately listed, see notes)",
    },
    "ai_governance": {
        "name": "AI & ML Governance",
        "sections": "Interpretive — not a distinct DPDPA chapter; grounded in Section 8 general obligations",
        "max_penalty": "₹200 Crores (Schedule Item 1/2, via Section 8)",
    },
    "cross_border": {
        "name": "Cross-Border Data Transfer",
        "sections": "Section 16",
        "max_penalty": "Not directly scheduled; indirect via Board directions (Item 8, ₹250 Crores) if unresolved after notice",
    },
}

# ---------------------------------------------------------------------------
# Secret-value plausibility check
#
# PLAINTEXT_SECRET/ENV_FILE_SECRETS only looked at the variable NAME before —
# any quoted 8+ char string next to a name containing "secret"/"token"/etc.
# counted as a finding. That misses the difference between a real credential
# and a self-referential DI-token constant (`CREDENTIAL_SECRET_REPOSITORY =
# 'CREDENTIAL_SECRET_REPOSITORY'`, a NestJS injection-token pattern) or a
# placeholder (`'changeme'`). A real secret has to actually look like one.
# ---------------------------------------------------------------------------

_SECRET_PLACEHOLDER_MARKERS = (
    'changeme', 'change-me', 'change_me', 'placeholder', 'your_', 'xxxxx',
    'example', 'dummy', 'sample', 'insert_', 'replace_', 'todo', 'fixme',
    '<', '>', '{{', '}}',
)
_SECRET_LITERAL_NON_VALUES = {'none', 'null', 'undefined', 'n/a', 'na', 'false', 'true', ''}


def _is_plausible_secret_value(key: str, value: str) -> bool:
    """True if `value` plausibly looks like a live credential, not an
    identifier/label/placeholder that merely sits next to a secret-sounding
    variable name."""
    norm_key = re.sub(r'[_\-]', '', key).upper()
    norm_val = re.sub(r'[_\-]', '', value).upper()
    if norm_val == norm_key:
        return False  # self-referential token constant, not a secret

    low = value.lower()
    if low in _SECRET_LITERAL_NON_VALUES:
        return False
    if any(marker in low for marker in _SECRET_PLACEHOLDER_MARKERS):
        return False
    if len(value) < 12:
        return False

    has_digit = any(c.isdigit() for c in value)
    has_upper = any(c.isupper() for c in value)
    has_lower = any(c.islower() for c in value)
    has_special = any(c in '-_./+@!#$%' for c in value)
    diversity = sum([has_digit, has_upper, has_lower, has_special])
    # A single-case alphabetic-only string of moderate length reads as an
    # identifier/label (e.g. a constant name or enum value), not a secret —
    # real secrets are essentially always mixed-case, numeric, or symbol-bearing.
    if diversity <= 1 and len(value) < 24:
        return False
    return True


def _validate_key_value_secret(match: re.Match) -> bool:
    return _is_plausible_secret_value(match.group(1), match.group(2))


# ---------------------------------------------------------------------------
# Pattern Definitions — grouped by DPDPA Pillar
# ---------------------------------------------------------------------------

PATTERNS = []

# ---- Pillar: security_safeguards ----

PATTERNS.append({
    "id": "PLAINTEXT_SECRET",
    "pillar": "security_safeguards",
    "severity": "CRITICAL",
    "regex": re.compile(
        r'(?i)\b(\w*(?:api[_-]?key|password|passwd|secret|token|private[_-]?key|'
        r'access[_-]?key|client[_-]?secret|db[_-]?pass|database[_-]?password|'
        r'auth[_-]?token|jwt[_-]?secret|signing[_-]?key)\w*)'
        r'\s*[:=]\s*[\'"]([a-zA-Z0-9_\-\.\/\+\@\!\#\$\%]{8,})[\'"]'
    ),
    "validate": _validate_key_value_secret,
    "description": "Hardcoded plaintext credential or secret detected.",
    "dpdpa_section": "Section 8(5) — Reasonable Security Safeguards",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Move secrets to environment variables or a vault service (AWS Secrets Manager, HashiCorp Vault). Never commit credentials to source control.",
})

PATTERNS.append({
    "id": "ENV_FILE_SECRETS",
    "pillar": "security_safeguards",
    "severity": "CRITICAL",
    "regex": re.compile(
        r'(?i)^(api[_-]?key|password|secret|token|private[_-]?key|'
        r'database[_-]?url|db[_-]?password|aws[_-]?secret|stripe[_-]?key|'
        r'sendgrid|twilio|auth0)\s*=\s*(.{8,})'
    ),
    "validate": _validate_key_value_secret,
    "description": "Secret detected in environment/config file. Verify .env is in .gitignore.",
    "dpdpa_section": "Section 8(5) — Reasonable Security Safeguards",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Add .env* to .gitignore. Use secret managers in production. Rotate any credentials that have been committed.",
    "file_filter": lambda f: os.path.basename(f).startswith('.env') or os.path.basename(f) in ('docker-compose.yml', 'docker-compose.yaml'),
})

PATTERNS.append({
    "id": "INSECURE_HTTP",
    "pillar": "security_safeguards",
    "severity": "HIGH",
    "regex": re.compile(
        r'[\'"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|'
        # XML/XSD/RDF namespace and license/spec URLs — identifiers, not live
        # network calls, and the overwhelming majority of INSECURE_HTTP noise
        # in any real codebase.
        r'www\.w3\.org|schema\.org|json-schema\.org|xmlns\.|purl\.org|'
        r'www\.apache\.org/licenses|opensource\.org/licenses|'
        r'creativecommons\.org)'
        r'[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}'
    ),
    "description": "Insecure plain HTTP URL to an external endpoint — data in transit is unencrypted.",
    "dpdpa_section": "Section 8(5) — reasonable security safeguards (data in transit)",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Replace http:// with https:// for all production endpoints. Enforce TLS 1.3 minimum.",
})

PATTERNS.append({
    "id": "SSL_BYPASS",
    "pillar": "security_safeguards",
    "severity": "CRITICAL",
    "regex": re.compile(
        r'(?i)(verify\s*=\s*False|rejectUnauthorized\s*[=:]\s*false|'
        r'strictSSL\s*[=:]\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\'"]?0|'
        r'InsecureSkipVerify\s*[=:]\s*true|ssl[_-]?verify\s*[=:]\s*false)'
    ),
    "description": "SSL/TLS certificate verification is explicitly disabled.",
    "dpdpa_section": "Section 8(5) — reasonable security safeguards",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Remove SSL verification bypass. Use proper CA certificates. If needed for local dev, gate behind NODE_ENV/FLASK_ENV checks.",
})

PATTERNS.append({
    "id": "WEAK_CRYPTO",
    "pillar": "security_safeguards",
    "severity": "HIGH",
    "regex": re.compile(
        r'(?i)(hashlib\.md5|hashlib\.sha1|MD5\.Create|SHA1\.Create|'
        r'createHash\s*\(\s*[\'"]md5[\'"]|createHash\s*\(\s*[\'"]sha1[\'"]|'
        r'Digest::MD5|Digest::SHA1|md5\s*\(|sha1\s*\()'
    ),
    "description": "Weak/broken hash algorithm (MD5 or SHA1) used — potentially for passwords or PII.",
    "dpdpa_section": "Section 8(5) — Reasonable Security Safeguards",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Use bcrypt/scrypt/argon2 for passwords. Use SHA-256/SHA-3 minimum for data integrity. Use AES-256 for encryption at rest.",
})

PATTERNS.append({
    "id": "PII_IN_LOGS",
    "pillar": "security_safeguards",
    "severity": "MEDIUM",
    "regex": re.compile(
        r'(?i)\b(console\.log|print[f]?|logger\.\w+|logging\.\w+|log\.\w+|'
        r'System\.out\.print|NSLog|Log\.\w)\s*\(.*'
        r'(aadhaar|aadhar|pan[_\s]?number|passport|phone|mobile|'
        r'email|gps|latitude|longitude|biometric|dob|birth[_\s]?date|'
        r'credit[_\s]?card|cvv|ssn|bank[_\s]?account)'
    ),
    "description": "PII field names found inside logging statements — sensitive data may leak into application logs.",
    "dpdpa_section": "Section 8(5) — security safeguards (log exposure)",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Mask or redact PII before logging. Use structured logging with field-level redaction. Never log raw Aadhaar, PAN, location, or biometrics.",
})

PATTERNS.append({
    "id": "RAW_PII_STORAGE",
    "pillar": "security_safeguards",
    "severity": "MEDIUM",
    "regex": re.compile(
        r'(?i)\b(aadhaar|aadhar|pan[_]?number|passport[_]?number|'
        r'gps[_]?coord|biometric[_]?data|fingerprint[_]?hash)\s*[:=]\s*'
        # Skip bare type annotations (`aadhaarNumber: string;`) — not a value
        # assignment, just a TS/interface field declaration.
        r'(?!(string|number|boolean|any|unknown|null|undefined|Date|String|Number|Boolean)\b)[^=\s]'
    ),
    "description": "PII/identity field assigned directly without visible encryption or hashing wrapper.",
    "dpdpa_section": "Section 8(5) — reasonable security safeguards at rest",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Wrap all PII field assignments through an encryption utility (e.g., encrypt_field(value)). Store only encrypted/hashed representations.",
})

PATTERNS.append({
    "id": "NO_BREACH_HANDLER",
    "pillar": "security_safeguards",
    "severity": "HIGH",
    "is_absence_check": True,
    "keywords": ['breach', 'incident', 'security_alert', 'notify_dpbi', 'breach_notification',
                  'incident_response', 'security_incident', 'data_breach'],
    "description": "No breach/incident notification handling code found in the codebase.",
    "dpdpa_section": "Section 8(6) — Mandatory breach notification to the Board and affected Data Principals",
    "penalty": "Up to ₹200 Crores (Schedule Item 3)",
    "remediation": "Implement an incident response module with: (1) automated breach detection, (2) DPBI notification template, (3) affected-user alert system, all within a 72-hour SLA.",
})

PATTERNS.append({
    "id": "MISSING_MFA",
    "pillar": "security_safeguards",
    "severity": "MEDIUM",
    "is_absence_check": True,
    "keywords": ['mfa', 'multi_factor', 'two_factor', '2fa', 'totp',
                  'authenticator_app', 'webauthn', 'one_time_passcode'],
    "description": "No multi-factor authentication code found. Rule 6 expects access controls commensurate with data sensitivity — MFA is the standard baseline for admin/privileged access.",
    "dpdpa_section": "Section 8(4)/(5) — technical and organisational measures, access control (DPDP Rule 6)",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Add MFA (TOTP authenticator app or WebAuthn) for admin and privileged accounts at minimum; OTP-only end-user login is not the same as MFA for staff/admin access.",
})

PATTERNS.append({
    "id": "MISSING_RBAC",
    "pillar": "security_safeguards",
    "severity": "MEDIUM",
    "is_absence_check": True,
    "keywords": ['rbac', 'role_based_access', 'permission_check', 'authorize_role',
                  'require_role', 'access_control_list', 'has_permission', 'can_access',
                  'roles_guard', 'permissions_guard', 'casl', 'ability_factory', '@roles'],
    "description": "No role-based access control code found. Rule 6 expects least-privilege access control for personal data.",
    "dpdpa_section": "Section 8(4)/(5) — technical and organisational measures, access control (DPDP Rule 6)",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Implement role-based access control so each account only reaches the personal data and operations its role requires (least privilege).",
})

PATTERNS.append({
    "id": "MISSING_AUDIT_LOG",
    "pillar": "security_safeguards",
    "severity": "MEDIUM",
    "is_absence_check": True,
    "keywords": ['audit_log', 'audit_trail', 'activity_log', 'access_log',
                  'audit_event', 'change_log', 'audit_logger'],
    "description": "No audit/activity logging code found. Rule 6 expects monitoring and logging as part of reasonable security safeguards, and it's the evidence base for any later breach investigation.",
    "dpdpa_section": "Section 8(4)/(5) — technical and organisational measures, monitoring (DPDP Rule 6)",
    "penalty": "Up to ₹200 Crores (Schedule Item 2)",
    "remediation": "Log who accessed or changed personal data and when (audit trail), separate from general application logs, with access restricted and retention defined.",
})

# ---- Pillar: consent_notice ----

PATTERNS.append({
    "id": "UNCONSENTED_TRACKER",
    "pillar": "consent_notice",
    # Downgraded from HIGH: mere presence of a tracking SDK isn't itself a
    # violation (anonymized analytics is a cited-compliant pattern in
    # DPDPA's own training material) — PII_SENT_TO_ANALYTICS below is the
    # higher-confidence signal for an actual violation (raw PII reaching the
    # vendor). This stays as a lower-severity "worth checking" flag.
    "severity": "MEDIUM",
    "regex": re.compile(
        r'(?i)(google[\-_]?analytics\.com|googletagmanager\.com|'
        r'gtag\s*\(|fbq\s*\(|connect\.facebook\.net|fbevents\.js|'
        r'mixpanel\.init|amplitude\.\w+|hotjar\.com|clarity\.ms|'
        r'segment\.com|heap\.load|plausible\.io|matomo|piwik)'
    ),
    "description": "Third-party analytics/tracking script detected. Confirm it's wrapped in a consent check and doesn't receive raw PII (see PII_SENT_TO_ANALYTICS if it does).",
    "dpdpa_section": "Section 5 & 6 — Valid consent required before tracking",
    "penalty": "Up to ₹200 Crores (Schedule Item 1)",
    "remediation": "Wrap tracker initialization inside a consent check (e.g., if (hasUserConsented('analytics')) { ... }). Load scripts only after explicit opt-in, and send anonymized/pseudonymous identifiers rather than raw PII.",
})

PATTERNS.append({
    "id": "PII_SENT_TO_ANALYTICS",
    "pillar": "consent_notice",
    "severity": "HIGH",
    "multiline": True,
    "regex": re.compile(
        r'(?is)(?:\b(?:gtag|fbq)\s*\([^)]{0,300}?'
        # Word-boundaried so "email" doesn't match inside an unrelated string
        # like 'signup_email_otp_requested' (an event NAME, not a PII field).
        r'\b(?:aadhaar|aadhar|pan[_]?number|passport|phone(?:[_]?number)?|mobile(?:[_]?number)?|'
        r'email(?:[_]?address)?|'
        r'gps|latitude|longitude|biometric|dob|date[_]?of[_]?birth|birth[_]?date|'
        r'credit[_]?card|cvv|ssn|bank[_]?account|street[_]?address|ip[_]?address)\b'
        r'|'
        r'\b\w+\.(?:track|identify|logEvent|capture|people\.set)\s*\([^;]{0,300}?'
        r'\b(?:aadhaar|aadhar|pan[_]?number|passport|phone(?:[_]?number)?|mobile(?:[_]?number)?|'
        r'email(?:[_]?address)?|'
        r'gps|latitude|longitude|biometric|dob|date[_]?of[_]?birth|birth[_]?date|'
        r'credit[_]?card|cvv|ssn|bank[_]?account|street[_]?address|ip[_]?address)\b)'
    ),
    "description": (
        "A personal-data field name appears directly inside a third-party analytics/tracking "
        "call's arguments — the vendor likely receives raw PII, not just anonymized usage data."
    ),
    "dpdpa_section": "Section 5 & 6 — valid, specific consent required before sharing personal data with a third party",
    "penalty": "Up to ₹200 Crores (Schedule Item 1)",
    "remediation": (
        "Strip PII before sending to analytics — use a hashed/anonymized identifier instead of "
        "raw email/phone/etc., or gate the call behind an explicit, specific consent check so the "
        "third-party vendor never receives the raw value."
    ),
})

PATTERNS.append({
    "id": "PRECHECKED_CONSENT",
    "pillar": "consent_notice",
    "severity": "HIGH",
    "regex": re.compile(
        r'(?i)(checked\s*=\s*[\'"]?checked|defaultChecked|checked\s*=\s*\{?\s*true|'
        r'selected\s*=\s*[\'"]?selected|default[_-]?opt[_-]?in\s*[:=]\s*true)'
    ),
    "description": "Pre-checked consent checkbox or default opt-in detected — violates affirmative consent requirement.",
    "dpdpa_section": "Section 5 — Consent must be freely given via clear affirmative action",
    "penalty": "Up to ₹200 Crores (Schedule Item 1)",
    "remediation": "Remove all pre-checked states from consent/marketing checkboxes. Consent must be unchecked by default requiring explicit user action.",
})

# ---- Pillar: data_retention ----

PATTERNS.append({
    "id": "MISSING_RETENTION",
    "pillar": "data_retention",
    "severity": "HIGH",
    "is_absence_check": True,
    # 'cleanup' deliberately excluded — it's a generic test/teardown word
    # (e.g. React Testing Library's `cleanup()`) with no connection to data
    # retention, and would otherwise satisfy this check in almost any test suite.
    "keywords": ['ttl', 'time_to_live', 'expire', 'expiry', 'retention', 'purge', 'prune',
                  'auto_delete', 'data_lifecycle', 'soft_delete', 'hard_delete',
                  'scheduled_deletion', 'anonymize', 'anonymise', 'gdpr_delete',
                  'expireafterseconds', 'delete_after', 'retention_period', 'retention_policy'],
    "description": "No data retention, TTL, expiration, or automated purge logic found in the codebase.",
    "dpdpa_section": "Section 8(7) — Storage limitation; data must be erased when purpose is fulfilled",
    "penalty": "Up to ₹200 Crores (Schedule Item 1)",
    "remediation": "Implement database TTL triggers, scheduled deletion cron jobs, and data lifecycle policies. Purge or anonymize user data within 3 years of last active interaction.",
})

# ---- Pillar: minor_protection ----

PATTERNS.append({
    "id": "MISSING_AGE_GATE",
    "pillar": "minor_protection",
    "severity": "MEDIUM",
    "is_absence_check": True,
    "keywords": ['age_verify', 'age_gate', 'age_check', 'verify_age', 'parental_consent',
                  'guardian_consent', 'is_minor', 'is_child', 'under_18', 'minimum_age',
                  'date_of_birth', 'age_restriction', 'coppa', 'child_safety'],
    "description": "No age verification or parental consent gate logic found. Required if the product may be used by persons under 18.",
    "dpdpa_section": "Section 9 — Verifiable parental consent required for minors",
    "penalty": "Up to ₹200 Crores",
    "remediation": "Implement age verification at signup (DOB field with validation). For users under 18, require verifiable parental consent (OTP to parent, identity verification).",
})

PATTERNS.append({
    "id": "MINOR_TRACKING",
    "pillar": "minor_protection",
    "severity": "HIGH",
    "regex": re.compile(
        r'(?i)(child|minor|kid|teen|student|under[_\s]?18|youth).*'
        r'(track|analytics|pixel|profil|behavio|target|advertis|market)'
        r'|'
        r'(track|analytics|pixel|profil|behavio|target|advertis|market).*'
        r'(child|minor|kid|teen|student|under[_\s]?18|youth)'
    ),
    "description": "Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.",
    "dpdpa_section": "Section 9 — Behavioral tracking and targeted ads are banned for children",
    "penalty": "Up to ₹200 Crores",
    "remediation": "Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.",
})

# ---- Pillar: data_principal_rights ----

PATTERNS.append({
    "id": "MISSING_ERASURE_API",
    "pillar": "data_principal_rights",
    "severity": "HIGH",
    "is_absence_check": True,
    "keywords": ['delete_account', 'erase_data', 'right_to_forget', 'right_to_erasure',
                  'account_deletion', 'purge_user', 'remove_account', 'wipe_data',
                  'delete_user_data', 'data_erasure', 'forget_me', 'gdpr_delete',
                  'destroy_account', 'close_account'],
    "description": "No user data erasure/account deletion endpoint or handler found.",
    "dpdpa_section": "Section 12 — Right to Correction, Completion, Updation & Erasure",
    "penalty": "Up to ₹200 Crores (Schedule Item 1)",
    "remediation": "Implement a 'Delete My Account' API endpoint and UI. Deletion must cascade to all subprocessors, replicas, backups (within reasonable timeframes), and caches.",
})

PATTERNS.append({
    "id": "MISSING_DATA_EXPORT",
    "pillar": "data_principal_rights",
    "severity": "MEDIUM",
    "is_absence_check": True,
    "keywords": ['download_data', 'export_data', 'data_portability', 'my_data',
                  'download_my_data', 'data_export', 'user_data_dump', 'data_request',
                  'access_request', 'subject_access', 'dsar'],
    "description": "No user data export/download endpoint found. Users must be able to access a summary of their stored personal data.",
    "dpdpa_section": "Section 11 — Right to Access Information",
    "penalty": "Up to ₹200 Crores (Schedule Item 1)",
    "remediation": "Implement a 'Download My Data' feature that generates a structured export (JSON/CSV) of all personal data held, processing activities, and third-party data sharing.",
})

PATTERNS.append({
    "id": "MISSING_GRIEVANCE_CHANNEL",
    "pillar": "data_principal_rights",
    "severity": "MEDIUM",
    "is_absence_check": True,
    "keywords": ['grievance', 'privacy@', 'dpo@', 'data_protection_officer',
                  'complaint', 'grievance_redressal', 'privacy_contact',
                  'data_complaint', 'privacy_officer'],
    "description": "No grievance redressal channel (e.g., privacy@company.com) or DPO contact found in the codebase.",
    # Section 13 (grievance redressal right) isn't itself one of the Schedule's
    # 8 named penalty items — the actionable obligation is the internal
    # grievance mechanism at Section 8(10), which IS covered (Schedule Item 1
    # covers sections 4-12 & 14).
    "dpdpa_section": "Section 8(10) — internal grievance redressal mechanism (Section 13 is the related Data Principal right)",
    "penalty": "Up to ₹200 Crores (Schedule Item 1)",
    "remediation": "Establish a dedicated privacy contact (privacy@company.com) and internal ticketing system for data protection grievances. Display it in the app UI and privacy policy.",
})

# ---- Pillar: ai_governance ----

PATTERNS.append({
    "id": "AI_PII_IN_TRAINING",
    "pillar": "ai_governance",
    "severity": "HIGH",
    "regex": re.compile(
        r'(?i)(aadhaar|aadhar|pan[_]?number|passport|biometric|'
        r'phone|mobile|email|credit[_]?card|bank[_]?account).*'
        r'(train|fit|fine[_\s]?tun|embed|vector|tokeniz|featur)'
        r'|'
        r'(train|fit|fine[_\s]?tun|embed|vector|tokeniz|featur).*'
        r'(aadhaar|aadhar|pan[_]?number|passport|biometric|'
        r'phone|mobile|email|credit[_]?card|bank[_]?account)'
    ),
    "description": "PII field names found in ML training/embedding/vectorization code paths.",
    # "AI governance" is this scanner's own interpretive framework, not a
    # distinct DPDPA chapter — it applies Section 8's general obligations
    # (data minimization, security) to ML pipelines specifically.
    "dpdpa_section": "Section 8 (general obligations, applied to ML pipelines) — not a standalone statutory AI chapter",
    "penalty": "Up to ₹200 Crores (Schedule Item 1/2, via Section 8)",
    "remediation": "Remove raw PII from feature vectors and training sets. Anonymize or pseudonymize data before model ingestion. Maintain audit trails of data transformations.",
})

PATTERNS.append({
    "id": "AI_NO_RATE_LIMIT",
    "pillar": "ai_governance",
    "severity": "MEDIUM",
    "is_absence_check": True,
    "keywords": ['rate_limit', 'ratelimit', 'throttle', 'rate_limiting',
                  'request_limit', 'api_quota', 'max_requests'],
    "description": "No rate limiting logic found. ML inference APIs without rate limits are vulnerable to model extraction attacks.",
    "dpdpa_section": "Section 8(4)/(5) (general & security obligations, applied to ML inference endpoints) — not a standalone statutory AI chapter",
    "penalty": "Up to ₹200 Crores (Schedule Item 1/2, via Section 8)",
    "remediation": "Implement API rate limiting on all inference endpoints. Monitor for anomalous query patterns. Add subtle noise to non-critical confidence scores.",
    "target_types": ["ml-pipeline", "api"],
})

PATTERNS.append({
    "id": "AI_LIBRARY_DETECTED",
    "pillar": "ai_governance",
    "severity": "INFO",
    "regex": re.compile(
        r'(?i)\b(sklearn|scikit[_-]learn|torch|pytorch|tensorflow|keras|'
        r'openai|anthropic|langchain|llama[_-]?index|hugging[_-]?face|transformers|'
        r'xgboost|lightgbm|catboost|pandas\.DataFrame|numpy|scipy|'
        r'pinecone|weaviate|chromadb|qdrant|milvus|faiss)\b'
    ),
    "description": "AI/ML library or vector database dependency detected. Triggers AI governance pillar checks.",
    "dpdpa_section": "Section 8 (general obligations, applied to AI/ML lifecycle) — not a standalone statutory AI chapter",
    "penalty": "N/A (informational)",
    "remediation": "Ensure AI lifecycle compliance: verify training data consent, implement fairness audits, add differential privacy, sanitize feedback loops.",
})

# ---- Pillar: cross_border ----

PATTERNS.append({
    "id": "CROSS_BORDER_REGION",
    "pillar": "cross_border",
    "severity": "MEDIUM",
    "regex": re.compile(
        r'(?i)(region\s*[:=]\s*[\'"](?!ap-south|me-south|mumbai|india)'
        r'[a-z]{2,3}[\-][a-z]+[\-]?\d?[\'"]|'
        r'AWS_DEFAULT_REGION\s*=\s*[\'"](?!ap-south)[a-z\-\d]+[\'"]|'
        r'GOOGLE_CLOUD_REGION\s*=\s*[\'"](?!asia-south)[a-z\-\d]+[\'"])'
    ),
    "description": (
        "Cloud infrastructure region configured outside India. Section 16 permits "
        "cross-border transfer by default unless the Central Government has "
        "specifically restricted that country — no country is currently "
        "blacklisted, so this is a lower-urgency flag than other CRITICAL/HIGH "
        "findings. Treat as a 'verify and monitor' item, not an active violation."
    ),
    "dpdpa_section": "Section 16 — Cross-border transfer restrictions (blacklist framework; no country currently restricted)",
    # Section 16 (Chapter IV) is not among the Schedule's 8 named penalty
    # items (Item 1 covers only sections 4-12 & 14) — direct penalty exposure
    # here is unconfirmed; the realistic path is Item 8 (defying a Board
    # direction) if the Board raises this and it's left unresolved.
    "penalty": "Not directly scheduled; indirect via Board directions (Item 8, ₹250 Crores) if unresolved after notice",
    "remediation": "Confirm the target country is not on the government's restricted list (none are currently restricted). Ensure valid DPAs are in place with foreign processors as good practice regardless.",
})

# ---------------------------------------------------------------------------
# Severity Weights (for scoring)
# ---------------------------------------------------------------------------

SEVERITY_WEIGHTS = {
    "CRITICAL": 20,
    "HIGH": 12,
    "MEDIUM": 5,
    "LOW": 2,
    "INFO": 0,
}

# ---------------------------------------------------------------------------
# Target type relevance weights — patterns more relevant to certain project types
# score higher
# ---------------------------------------------------------------------------

TARGET_TYPE_BOOSTS = {
    "webapp": ["consent_notice", "minor_protection", "security_safeguards"],
    "api": ["security_safeguards", "data_principal_rights", "data_retention"],
    "ml-pipeline": ["ai_governance", "security_safeguards", "data_retention"],
    "mobile": ["consent_notice", "minor_protection", "security_safeguards", "cross_border"],
    "general": list(PILLARS.keys()),
}

# ---------------------------------------------------------------------------
# Sector classification
#
# DPDPA has no HIPAA-style "PHI" category — all personal data is treated
# uniformly in the statute. But sector still matters in practice: health data
# needs explicit consent (not implied) and commonly pushes a Data Fiduciary
# toward Significant-Data-Fiduciary status (mandatory DPIA, Rule 13); fintech
# data overlaps with RBI/PCI obligations on top of DPDPA. This is advisory
# context for the report, not a scoring input — it doesn't silently reweight
# findings.
# ---------------------------------------------------------------------------

SECTOR_SIGNALS = {
    "healthcare": [
        'patient', 'diagnosis', 'diagnoses', 'prescription', 'ehr', 'emr',
        'icd10', 'icd_10', 'telemedicine', 'clinical', 'physician',
        'medical_record', 'medical_history', 'health_record', 'hl7', 'fhir',
        'pharmacy', 'symptom', 'treatment_plan', 'patient_id', 'lab_result',
        'vitals', 'allergy', 'immunization',
    ],
    "fintech": [
        'kyc', 'razorpay', 'ifsc', 'upi', 'pan_card', 'credit_score', 'loan',
        'emi', 'ledger', 'nbfc', 'wallet_balance', 'card_number', 'cvv',
        'bank_account', 'payment_gateway', 'transaction_amount',
        'account_number', 'routing_number', 'swift_code', 'disbursement',
    ],
    "ecommerce": [
        'cart', 'checkout', 'sku', 'inventory', 'shipping_address',
        'order_id', 'product_catalog', 'warehouse', 'courier', 'coupon',
        'wishlist', 'add_to_cart', 'order_status', 'delivery_address',
    ],
}

SECTOR_ADVISORY = {
    "healthcare": (
        "This codebase appears to process health-related data. DPDPA treats health "
        "data as high-sensitivity: Section 9-style implied consent is not enough — "
        "explicit, specific consent is expected (Section 6(1)), and this profile "
        "commonly triggers Significant Data Fiduciary status, which requires a "
        "mandatory DPIA (Rule 13) and annual independent audit. Section 33(2)(b) "
        "explicitly treats the sensitivity of affected data as a penalty-severity "
        "factor — the same technical finding carries more risk here than in a "
        "general-purpose app."
    ),
    "fintech": (
        "This codebase appears to process financial/payment data. Beyond DPDPA, "
        "expect overlap with RBI/PCI-DSS obligations (tokenization of card data, "
        "transaction-level audit trails). DPDPA penalty severity (Section 33(2)(b)) "
        "also scales with data sensitivity, and financial data is treated as high-"
        "sensitivity alongside health and biometric data."
    ),
    "ecommerce": (
        "This codebase appears to be an e-commerce platform. Pay particular "
        "attention to third-party data sharing (payment gateways, shipping "
        "partners, marketing/analytics vendors) — each needs a Data Processing "
        "Agreement under Section 8(2), and any PII forwarded to analytics/marketing "
        "tools needs a consent gate, not just a vendor contract."
    ),
    "general": (
        "No dominant sector signal was detected. Standard DPDPA obligations "
        "(Sections 5-14) apply; revisit sector-specific guidance if this changes."
    ),
}

_SECTOR_KEYWORD_REGEX_CACHE = {}


def _count_keyword_hits(keyword, content_lower):
    regex = _SECTOR_KEYWORD_REGEX_CACHE.get(keyword)
    if regex is None:
        pre = r'(?<![a-zA-Z0-9_])'
        post = r'(?![a-zA-Z0-9_])' if re.match(r'.*[a-zA-Z0-9_]$', keyword) else ''
        regex = re.compile(pre + re.escape(keyword) + post)
        _SECTOR_KEYWORD_REGEX_CACHE[keyword] = regex
    return len(regex.findall(content_lower))


def detect_sector(merged_content_lower):
    """Heuristic sector classification from keyword density. Advisory only —
    does not change severity weighting or scores."""
    scores = {}
    hits_by_sector = {}
    for sector, keywords in SECTOR_SIGNALS.items():
        hits = [(kw, _count_keyword_hits(kw, merged_content_lower)) for kw in keywords]
        hits = [(kw, c) for kw, c in hits if c > 0]
        scores[sector] = sum(c for _, c in hits)
        hits_by_sector[sector] = hits

    best_sector = max(scores, key=scores.get) if scores else "general"
    best_score = scores.get(best_sector, 0)

    # Require a minimum signal before committing to a sector classification —
    # a couple of incidental keyword hits in an unrelated codebase shouldn't
    # relabel it. Below the threshold, report as general/unclassified.
    MIN_SIGNAL = 3
    if best_score < MIN_SIGNAL:
        return {
            "sector": "general",
            "confidence": "low",
            "signals_found": [],
            "advisory": SECTOR_ADVISORY["general"],
        }

    distinct_keywords_hit = len(hits_by_sector[best_sector])
    confidence = "high" if best_score >= 8 and distinct_keywords_hit >= 3 else "medium"

    return {
        "sector": best_sector,
        "confidence": confidence,
        "signals_found": [kw for kw, _ in sorted(hits_by_sector[best_sector], key=lambda kv: -kv[1])][:10],
        "advisory": SECTOR_ADVISORY[best_sector],
    }


# ---------------------------------------------------------------------------
# Scanner Engine
# ---------------------------------------------------------------------------

def should_scan_file(filepath, extra_excludes=None):
    """Determine if a file should be scanned."""
    basename = os.path.basename(filepath)
    ext = os.path.splitext(basename)[1].lower()

    # Skip explicitly ignored files (e.g. lockfiles)
    if basename in IGNORE_FILES:
        return False

    # Skip this scanner's own previously generated reports — they quote raw
    # evidence lines (including, for secret findings, the literal matched
    # value), so re-scanning them creates a self-referential feedback loop
    # that re-flags the report's own quoted snippets as new findings.
    if re.match(r'^dpdpa_compliance_report.*\.md$', basename, re.IGNORECASE):
        return False

    # Test files colocated with source (e.g. NestJS/Angular's foo.spec.ts
    # next to foo.ts) aren't caught by excluding test/__tests__ directories —
    # they need a filename-pattern check instead. Mock credentials and
    # synthetic PII in test fixtures are not real production findings.
    if re.search(r'\.(spec|test)\.[a-z0-9]+$', basename, re.IGNORECASE):
        return False
    if re.match(r'^test_.+\.py$', basename) or re.match(r'^.+_test\.py$', basename):
        return False

    # Skip .env* — local secrets / dumps, not product-code findings
    if basename == '.env' or basename.startswith('.env.'):
        return False

    # Always scan known config files
    if basename in CONFIG_FILES:
        return True

    # Skip ignored extensions
    if ext in IGNORE_EXTENSIONS:
        return False

    # Safety net for binaries under an extension we don't know about yet
    # (DB sidecar files, caches, etc.) — cheap enough to run on every file,
    # and the only thing that catches the next one of these we haven't named.
    try:
        with open(filepath, 'rb') as f:
            chunk = f.read(512)
            if b'\x00' in chunk:  # likely binary
                return False
    except Exception:
        return False

    # Apply extra exclude patterns
    if extra_excludes:
        for pattern in extra_excludes:
            if fnmatch.fnmatch(filepath, pattern) or fnmatch.fnmatch(basename, pattern):
                return False

    return True


# Findings whose regex match captures a literal secret/credential value —
# not just a field name or pattern — so the stored finding must never carry
# the real value forward into JSON output or an uploaded report.
SENSITIVE_VALUE_PATTERN_IDS = {"PLAINTEXT_SECRET", "ENV_FILE_SECRETS"}


def _redact_secret_value(line):
    """Mask a literal secret value in a matched line, keeping the key name
    and structure visible (so the finding stays actionable) without
    reproducing the live credential anywhere downstream."""

    def mask(value):
        if len(value) <= 6:
            return '*' * len(value)
        return value[:2] + '*' * (len(value) - 4) + value[-2:]

    m = re.search(r'^(.*?[:=]\s*[\'"])(.+?)([\'"].*)$', line)
    if m:
        return m.group(1) + mask(m.group(2)) + m.group(3)
    m = re.search(r'^(\s*[\w.\-]+\s*=\s*)(.+)$', line)
    if m:
        return m.group(1) + mask(m.group(2))
    return re.sub(r'\S', '*', line)


def scan_file(filepath, target_type="general"):
    """Scan a single file for pattern matches. Returns list of findings."""
    findings = []
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
            lines = content.splitlines()
    except Exception:
        return findings, content if 'content' in dir() else ""

    content_lower = content.lower()

    for pattern in PATTERNS:
        # Skip absence checks here — those are handled globally
        if pattern.get("is_absence_check"):
            continue

        # Check file filter if present
        if "file_filter" in pattern:
            if not pattern["file_filter"](filepath):
                continue

        # Check target type relevance
        if "target_types" in pattern:
            if target_type not in pattern["target_types"] and target_type != "general":
                continue

        regex = pattern["regex"]
        redact = pattern["id"] in SENSITIVE_VALUE_PATTERN_IDS
        validate = pattern.get("validate")

        if pattern.get("multiline"):
            # Real call sites (analytics.track({...}, often span several
            # lines) — match across the whole file instead of one line at a
            # time, bounded by the regex itself so it can't run away across
            # unrelated distant code.
            for match in regex.finditer(content):
                if validate and not validate(match):
                    continue
                line_no = content.count('\n', 0, match.start()) + 1
                snippet = re.sub(r'\s+', ' ', match.group(0)).strip()[:200]
                findings.append({
                    "id": pattern["id"],
                    "pillar": pattern["pillar"],
                    "severity": pattern["severity"],
                    "file": filepath,
                    "line": line_no,
                    "content": snippet,
                    "match_text": snippet,
                    "description": pattern["description"],
                    "dpdpa_section": pattern["dpdpa_section"],
                    "penalty": pattern["penalty"],
                    "remediation": pattern["remediation"],
                })
            continue

        for i, line in enumerate(lines, 1):
            match = regex.search(line)
            if match:
                if validate and not validate(match):
                    continue
                line_stripped = line.strip()
                match_text = match.group(0)
                if redact:
                    line_stripped = _redact_secret_value(line_stripped)
                    match_text = _redact_secret_value(match_text)
                findings.append({
                    "id": pattern["id"],
                    "pillar": pattern["pillar"],
                    "severity": pattern["severity"],
                    "file": filepath,
                    "line": i,
                    "content": line_stripped,
                    "match_text": match_text,
                    "description": pattern["description"],
                    "dpdpa_section": pattern["dpdpa_section"],
                    "penalty": pattern["penalty"],
                    "remediation": pattern["remediation"],
                })

    return findings, content_lower


_KEYWORD_REGEX_CACHE = {}


def _keyword_present(keyword, content_lower):
    """Word-boundary presence check for absence-check keywords.

    A bare substring search (`kw in content`) false-matches constantly —
    e.g. 'ttl' inside 'little'/'bottle'/'throttle', which made MISSING_RETENTION
    silently never fire on real codebases (any file with ordinary English text
    satisfied it). Keywords ending in a non-identifier character (e.g.
    'privacy@') skip the trailing boundary so 'privacy@company.com' still
    matches — the leading boundary alone is enough to avoid collisions there.

    Keyword lists are written in snake_case ('audit_log'), but real code is
    just as often camelCase ('auditLog') or one word ('auditlog') — and since
    absence-check content is lowercased before matching, that case information
    is already gone by the time we see it. Rather than hand-duplicating a
    no-separator variant in every keyword list (easy to forget — it's exactly
    what caused MISSING_RBAC to miss a real `RolesGuard` and MISSING_AUDIT_LOG
    to miss a real `auditLog()`), derive it once here for any keyword with an
    underscore.
    """
    regex = _KEYWORD_REGEX_CACHE.get(keyword)
    if regex is None:
        variants = {keyword}
        if '_' in keyword:
            variants.add(keyword.replace('_', ''))
        alternation = '|'.join(re.escape(v) for v in sorted(variants, key=len, reverse=True))
        pre = r'(?<![a-zA-Z0-9_])'
        post = r'(?![a-zA-Z0-9_])' if re.match(r'.*[a-zA-Z0-9_]$', keyword) else ''
        regex = re.compile(pre + r'(?:' + alternation + r')' + post)
        _KEYWORD_REGEX_CACHE[keyword] = regex
    return bool(regex.search(content_lower))


def check_gitignore_for_env(root_dir):
    """Check if .env is listed in .gitignore."""
    gitignore_path = os.path.join(root_dir, '.gitignore')
    if not os.path.exists(gitignore_path):
        return False
    try:
        with open(gitignore_path, 'r', encoding='utf-8', errors='ignore') as f:
            content = f.read()
        # Check for common .env ignore patterns
        env_patterns = ['.env', '*.env', '.env*', '.env.local', '.env.production']
        return any(p in content for p in env_patterns)
    except Exception:
        return False


def run_scan(root_dir, target_type="general", extra_excludes=None):
    """Execute the full compliance scan."""
    all_findings = []
    file_count = 0
    scanned_files = []

    # Collect all content for absence checks
    all_content_lower = []

    # Check .gitignore coverage
    env_in_gitignore = check_gitignore_for_env(root_dir)
    # Track .env paths without reading their contents
    env_files_on_disk = []

    for dirpath, dirnames, filenames in os.walk(root_dir):
        # Prune ignored directories in-place
        dirnames[:] = [d for d in dirnames if d not in IGNORE_DIRS]

        for filename in filenames:
            filepath = os.path.join(dirpath, filename)
            rel = os.path.relpath(filepath, root_dir)

            if filename == '.env' or filename.startswith('.env.'):
                env_files_on_disk.append(rel)
                continue

            if not should_scan_file(filepath, extra_excludes):
                continue

            file_count += 1
            scanned_files.append(rel)

            file_findings, content_lower = scan_file(filepath, target_type)
            all_findings.extend(file_findings)

            if isinstance(content_lower, str):
                all_content_lower.append(content_lower)

    # Merge all content for absence checks
    merged_content = '\n'.join(all_content_lower)

    # Run absence checks
    global_warnings = []
    for pattern in PATTERNS:
        if not pattern.get("is_absence_check"):
            continue

        # Check target type relevance
        if "target_types" in pattern:
            if target_type not in pattern["target_types"] and target_type != "general":
                continue

        keywords = pattern["keywords"]
        found = any(_keyword_present(kw, merged_content) for kw in keywords)
        if not found:
            global_warnings.append({
                "id": pattern["id"],
                "pillar": pattern["pillar"],
                "severity": pattern["severity"],
                "description": pattern["description"],
                "dpdpa_section": pattern["dpdpa_section"],
                "penalty": pattern["penalty"],
                "remediation": pattern["remediation"],
            })

    # Special check: .env exists but not in .gitignore (no content scan)
    env_files = env_files_on_disk
    if env_files and not env_in_gitignore:
        global_warnings.append({
            "id": "ENV_NOT_GITIGNORED",
            "pillar": "security_safeguards",
            "severity": "CRITICAL",
            "description": f".env file(s) found ({', '.join(env_files)}) but .env is NOT in .gitignore. Secrets may be committed to version control.",
            "dpdpa_section": "Section 8(5) — Reasonable Security Safeguards",
            "penalty": "Up to ₹200 Crores (Schedule Item 2)",
            "remediation": "Add '.env*' to .gitignore immediately. Audit git history for committed secrets and rotate all exposed credentials.",
        })

    # ---------------------------------------------------------------------------
    # Compute per-pillar scores
    # ---------------------------------------------------------------------------
    pillar_scores = {}
    for pillar_id, pillar_meta in PILLARS.items():
        pillar_findings = [f for f in all_findings if f["pillar"] == pillar_id]
        pillar_warnings = [w for w in global_warnings if w["pillar"] == pillar_id]

        total_deduction = 0
        for f in pillar_findings:
            total_deduction += SEVERITY_WEIGHTS.get(f["severity"], 0)
        for w in pillar_warnings:
            total_deduction += SEVERITY_WEIGHTS.get(w["severity"], 0)

        score = max(0, 100 - total_deduction)
        findings_count = len(pillar_findings) + len(pillar_warnings)

        if score >= 90:
            status = "PASS"
        elif score >= 70:
            status = "GOOD"
        elif score >= 50:
            status = "NEEDS_ATTENTION"
        elif score >= 30:
            status = "WARNING"
        else:
            status = "CRITICAL"

        pillar_scores[pillar_id] = {
            "name": pillar_meta["name"],
            "sections": pillar_meta["sections"],
            "max_penalty": pillar_meta["max_penalty"],
            "score": score,
            "status": status,
            "findings_count": findings_count,
        }

    # Overall score — weighted average, boost relevant pillars for target type
    boost_pillars = TARGET_TYPE_BOOSTS.get(target_type, list(PILLARS.keys()))
    total_weight = 0
    weighted_sum = 0
    for pid, pdata in pillar_scores.items():
        weight = 2 if pid in boost_pillars else 1
        weighted_sum += pdata["score"] * weight
        total_weight += weight

    overall_score = round(weighted_sum / total_weight) if total_weight > 0 else 100

    if overall_score >= 90:
        overall_status = "COMPLIANT"
    elif overall_score >= 70:
        overall_status = "MOSTLY_COMPLIANT"
    elif overall_score >= 50:
        overall_status = "NEEDS_ATTENTION"
    elif overall_score >= 30:
        overall_status = "AT_RISK"
    else:
        overall_status = "NON_COMPLIANT"

    ist = timezone(timedelta(hours=5, minutes=30))
    sector = detect_sector(merged_content)

    report = {
        "workspace": os.path.abspath(root_dir),
        "scan_timestamp": datetime.now(ist).replace(microsecond=0).isoformat(),
        "target_type": target_type,
        "sector": sector,
        "total_files_scanned": file_count,
        "scanned_files": scanned_files,
        "overall_score": overall_score,
        "overall_status": overall_status,
        "pillar_scores": pillar_scores,
        "findings": all_findings,
        "global_warnings": global_warnings,
        "summary": {
            "CRITICAL": len([f for f in all_findings if f["severity"] == "CRITICAL"]),
            "HIGH": len([f for f in all_findings if f["severity"] == "HIGH"]) + len([w for w in global_warnings if w["severity"] == "HIGH"]),
            "MEDIUM": len([f for f in all_findings if f["severity"] == "MEDIUM"]) + len([w for w in global_warnings if w["severity"] == "MEDIUM"]),
            "LOW": len([f for f in all_findings if f["severity"] == "LOW"]),
            "INFO": len([f for f in all_findings if f["severity"] == "INFO"]),
        },
    }

    return report


# ---------------------------------------------------------------------------
# Report Generation
# ---------------------------------------------------------------------------

def generate_remediation_diff(pattern_id, match_text, content_line):
    """Generate a realistic diff for remediation evidence."""
    line = content_line.strip()
    if pattern_id == "PLAINTEXT_SECRET":
        # Match pattern: e.g. key = 'value'
        match = re.search(r'(\w*(?:api[_-]?key|password|passwd|secret|token|private[_-]?key|access[_-]?key|client[_-]?secret|db[_-]?pass|database[_-]?password|auth[_-]?token|jwt[_-]?secret|signing[_-]?key)\w*)\s*([:=])\s*([\'"])(.*)([\'"])', line, re.IGNORECASE)
        if match:
            key, op, q_start, val, q_end = match.groups()
            env_var = key.upper().replace('-', '_')
            new_line = f"{key} {op} process.env.{env_var}"
            return f"- {line}\n+ {new_line}"
    elif pattern_id == "ENV_FILE_SECRETS":
        match = re.search(r'^(\w*(?:api[_-]?key|password|secret|token|private[_-]?key|database[_-]?url|db[_-]?password|aws[_-]?secret|stripe[_-]?key|sendgrid|twilio|auth0))\s*=\s*(.*)', line, re.IGNORECASE)
        if match:
            key, val = match.groups()
            return f"- {line}\n+ # {key} should be set in environment at runtime"
    elif pattern_id == "INSECURE_HTTP":
        new_line = line.replace("http://", "https://")
        return f"- {line}\n+ {new_line}"
    elif pattern_id == "SSL_BYPASS":
        new_line = line.replace("False", "True").replace("false", "true").replace("0", "1")
        return f"- {line}\n+ {new_line}"
    elif pattern_id == "WEAK_CRYPTO":
        new_line = line.replace("md5", "sha256").replace("MD5", "SHA256").replace("sha1", "sha256").replace("SHA1", "SHA256")
        return f"- {line}\n+ {new_line}"
    elif pattern_id == "PII_IN_LOGS":
        return f"- {line}\n+ [Redact or mask sensitive PII fields before logging]"
    
    return f"- {line}\n+ [Remediate this security risk]"


def generate_markdown_report(report, company_name=None, company_uuid=None):
    """Generate markdown compliance report from scanner results using the template."""
    plugin_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_path = os.path.join(plugin_root, 'resources', 'audit_report_template.md')
    
    # Try reading the template file, fallback to built-in basic markdown if not found
    if os.path.exists(template_path):
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                template_content = f.read()
        except Exception:
            template_content = None
    else:
        template_content = None

    if not template_content:
        # Fallback template string in case the file doesn't exist
        template_content = """# DPDPA Compliance Audit Report
**Date**: {scan_timestamp}
**Project**: `{workspace_name}`
{organisation_line}**Target Type**: {target_type}
**Overall Compliance Score**: {overall_score} / 100 — {overall_status_icon} **{overall_status}**

## 1. Executive Summary
{executive_summary}

## 2. Critical & High Severity Findings
{critical_high_findings}

## 3. Detailed Audit by DPDPA Pillar
Pillar A: Consent & Notice Management: {consent_notice_score}% ({consent_notice_status})
Pillar B: Security Safeguards: {security_safeguards_score}% ({security_safeguards_status})
Pillar C: Data Retention: {data_retention_score}% ({data_retention_status})
Pillar D: Children's Data Safeguards: {minor_protection_score}% ({minor_protection_status})
Pillar E: Data Principal Rights: {data_principal_rights_score}% ({data_principal_rights_status})
Pillar F: AI & ML Governance: {ai_governance_score}% ({ai_governance_status})
Pillar G: Cross-Border Data Transfer: {cross_border_score}% ({cross_border_status})

## 4. Penalty Risk Matrix
{penalty_risk_matrix}
**Cumulative Penalty Exposure**: {total_exposure}

## 5. Remediation Roadmap
{remediation_roadmap}
"""

    STATUS_ICONS = {
        "COMPLIANT": "✅",
        "MOSTLY_COMPLIANT": "🟢",
        "NEEDS_ATTENTION": "🟡",
        "AT_RISK": "🟠",
        "NON_COMPLIANT": "🔴",
    }

    PILLAR_STATUS_ICONS = {
        "PASS": "✅ PASS",
        "GOOD": "🟢 GOOD",
        "NEEDS_ATTENTION": "🟡 NEEDS ATTENTION",
        "WARNING": "🟠 WARNING",
        "CRITICAL": "🔴 CRITICAL",
    }

    # Generate Organisation block
    organisation_line = ""
    if company_name:
        if company_uuid:
            organisation_line = f"**Organisation**: {company_name} (`{company_uuid}`)  \n"
        else:
            organisation_line = f"**Organisation**: {company_name}  \n"
    elif company_uuid:
        organisation_line = f"**Company UUID**: `{company_uuid}`  \n"

    # Generate Executive Summary
    pillars = report['pillar_scores']
    sorted_pillars = sorted(pillars.items(), key=lambda x: x[1]['score'])
    weakest_id, weakest = sorted_pillars[0]
    strongest_id, strongest = sorted_pillars[-1]

    critical_findings = [f for f in report['findings'] if f['severity'] == 'CRITICAL']
    high_findings = [f for f in report['findings'] if f['severity'] == 'HIGH']
    medium_findings = [f for f in report['findings'] if f['severity'] == 'MEDIUM']

    total_critical_high = len(critical_findings) + len(high_findings)

    executive_summary = (
        f"This compliance audit scanned {report['total_files_scanned']} files in the project. "
        f"The codebase has an overall score of {report['overall_score']}/100, indicating a status of **{report['overall_status']}**. "
        f"The strongest area is **{strongest['name']}** at {strongest['score']}%, while the weakest area is **{weakest['name']}** at {weakest['score']}%. "
        f"A total of {len(critical_findings)} critical and {len(high_findings)} high-severity findings were detected. "
    )
    if total_critical_high > 0:
        most_urgent = (critical_findings + high_findings)[0]
        file_rel = os.path.relpath(most_urgent['file'], report['workspace']) if 'file' in most_urgent else 'architecture'
        line_str = f" on line {most_urgent['line']}" if 'line' in most_urgent else ""
        executive_summary += (
            f"The most urgent issue is `{most_urgent['id']}` found in `{file_rel}`{line_str}, "
            f"which represents a potential statutory penalty risk of {most_urgent['penalty'].removeprefix('Up to ').removeprefix('up to ')}."
        )
    else:
        executive_summary += "No critical or high-severity compliance issues were detected in the codebase."

    # Format Critical & High Findings
    ch_details = []
    ch_findings = [f for f in report['findings'] if f['severity'] in ('CRITICAL', 'HIGH')]
    ch_warnings = [w for w in report['global_warnings'] if w['severity'] in ('CRITICAL', 'HIGH')]

    idx = 1
    for f in ch_findings:
        file_rel = os.path.relpath(f['file'], report['workspace'])
        diff = generate_remediation_diff(f['id'], f['match_text'], f['content'])
        ch_details.append(
            f"### Finding {idx}: [{f['severity']}] {f['id']}\n\n"
            f"- **Pillar**: {PILLARS[f['pillar']]['name']}\n"
            f"- **DPDPA Section**: {f['dpdpa_section']}\n"
            f"- **Statutory Penalty Risk**: {f['penalty']}\n"
            f"- **Location**: `{file_rel}:{f['line']}`\n"
            f"- **Description**: {f['description']}\n\n"
            f"**Evidence** (line {f['line']} of `{file_rel}`):\n"
            f"```\n"
            f"{f['content']}\n"
            f"```\n\n"
            f"**Remediation**:\n"
            f"```diff\n"
            f"{diff}\n"
            f"```\n\n"
            f"> {f['remediation']}\n"
        )
        idx += 1

    for w in ch_warnings:
        ch_details.append(
            f"### Finding {idx}: [{w['severity']}] {w['id']} (Architectural)\n\n"
            f"- **Pillar**: {PILLARS[w['pillar']]['name']}\n"
            f"- **DPDPA Section**: {w['dpdpa_section']}\n"
            f"- **Statutory Penalty Risk**: {w['penalty']}\n"
            f"- **Location**: Project Architecture / Global\n"
            f"- **Description**: {w['description']}\n\n"
            f"**Remediation**:\n"
            f"> {w['remediation']}\n"
        )
        idx += 1

    if not ch_details:
        critical_high_findings = "No critical or high severity findings were detected in this codebase."
    else:
        critical_high_findings = "\n\n---\n\n".join(ch_details)

    # Format Penalty Risk Matrix
    matrix_rows = []
    idx = 1
    all_items = []
    for f in report['findings']:
        all_items.append({
            "id": f['id'],
            "severity": f['severity'],
            "section": f['dpdpa_section'],
            "penalty": f['penalty'],
            "location": f"{os.path.relpath(f['file'], report['workspace'])}:{f['line']}"
        })
    for w in report['global_warnings']:
        all_items.append({
            "id": w['id'],
            "severity": w['severity'],
            "section": w['dpdpa_section'],
            "penalty": w['penalty'],
            "location": "Global / Architecture"
        })

    all_items.sort(key=lambda x: SEVERITY_WEIGHTS.get(x['severity'], 0), reverse=True)

    for item in all_items:
        matrix_rows.append(
            f"| {idx} | {item['id']} | {item['severity']} | {item['section']} | {item['penalty']} | `{item['location']}` |"
        )
        idx += 1

    if not matrix_rows:
        penalty_risk_matrix = "No compliance risks or potential penalties detected."
    else:
        penalty_risk_matrix = (
            "| # | Finding ID | Severity | DPDPA Section | Max Penalty | File:Line |\n"
            "|---|---|---|---|---|---|\n" +
            "\n".join(matrix_rows)
        )

    # Calculate Total Exposure
    penalties = [item['penalty'] for item in all_items if item['penalty'] != 'N/A']
    if not penalties:
        total_exposure = "None"
    else:
        has_250 = any("250" in p for p in penalties)
        has_200 = any("200" in p for p in penalties)
        has_50 = any("50" in p for p in penalties)
        if has_250:
            total_exposure = "Up to ₹250 Crores"
        elif has_200:
            total_exposure = "Up to ₹200 Crores"
        elif has_50:
            total_exposure = "Up to ₹50 Crores"
        else:
            total_exposure = "N/A"

    # Format Remediation Roadmap
    immediate_items = []
    short_term_items = []
    medium_term_items = []

    for f in report['findings']:
        if f['severity'] == 'CRITICAL':
            immediate_items.append(f"- [ ] Fix `{f['id']}` in `{os.path.relpath(f['file'], report['workspace'])}` (line {f['line']})")
    for w in report['global_warnings']:
        if w['severity'] == 'CRITICAL':
            immediate_items.append(f"- [ ] Fix `{w['id']}` (Architectural Gap)")

    for f in report['findings']:
        if f['severity'] == 'HIGH':
            short_term_items.append(f"- [ ] Fix `{f['id']}` in `{os.path.relpath(f['file'], report['workspace'])}` (line {f['line']})")
    for w in report['global_warnings']:
        if w['severity'] == 'HIGH':
            short_term_items.append(f"- [ ] Fix `{w['id']}` (Architectural Gap)")

    for f in report['findings']:
        if f['severity'] in ('MEDIUM', 'LOW'):
            medium_term_items.append(f"- [ ] Address `{f['id']}` in `{os.path.relpath(f['file'], report['workspace'])}` (line {f['line']})")
    for w in report['global_warnings']:
        if w['severity'] in ('MEDIUM', 'LOW'):
            medium_term_items.append(f"- [ ] Address `{w['id']}` (Architectural Gap)")

    if not immediate_items:
        immediate_str = "- [x] No immediate critical findings."
    else:
        immediate_str = "\n".join(immediate_items)

    if not short_term_items:
        short_term_str = "- [x] No short-term high severity findings."
    else:
        short_term_str = "\n".join(short_term_items)

    if not medium_term_items:
        medium_term_str = "- [x] No medium-term findings."
    else:
        medium_term_str = "\n".join(medium_term_items)

    remediation_roadmap = (
        "### Immediate (0–72 hours) — Critical Issues\n"
        f"{immediate_str}\n\n"
        "### Short-Term (1–2 weeks) — High Severity Issues\n"
        f"{short_term_str}\n\n"
        "### Medium-Term (1 month) — Medium Severity & Architecture Gaps\n"
        f"{medium_term_str}\n\n"
        "### Ongoing — Governance & Monitoring\n"
        "- [ ] Schedule quarterly DPDPA compliance scans\n"
        "- [ ] Conduct annual independent security audit (if SDF-designated)\n"
        "- [ ] Maintain immutable consent telemetry logs\n"
        "- [ ] Run DPIA before each major feature release"
    )

    # Format pillar lists and recommendations
    sector = report.get('sector', {})
    sector_name = sector.get('sector', 'general').replace('_', ' ').title()
    sector_line = f"**Detected Sector**: {sector_name} ({sector.get('confidence', 'low')} confidence)\n"
    sector_advisory = sector.get('advisory', '')

    template_data = {
        "scan_timestamp": report['scan_timestamp'],
        "workspace_name": os.path.basename(report['workspace']),
        "organisation_line": organisation_line,
        "sector_line": sector_line,
        "sector_advisory": sector_advisory,
        "target_type": report['target_type'],
        "total_files_scanned": report['total_files_scanned'],
        "overall_score": report['overall_score'],
        "overall_status": report['overall_status'],
        "overall_status_icon": STATUS_ICONS.get(report['overall_status'], '❓'),
        "executive_summary": executive_summary,
        "critical_high_findings": critical_high_findings,
        "penalty_risk_matrix": penalty_risk_matrix,
        "total_exposure": total_exposure,
        "remediation_roadmap": remediation_roadmap,
        "scanned_files_list": "\n".join(report['scanned_files']),
    }

    for pid in PILLARS.keys():
        pdata = report['pillar_scores'][pid]
        template_data[f"{pid}_score"] = pdata['score']
        template_data[f"{pid}_status"] = PILLAR_STATUS_ICONS.get(pdata['status'], '❓')
        template_data[f"{pid}_count"] = pdata['findings_count']
        # Single source of truth: PILLARS[pid]['max_penalty'], not a second
        # hardcoded copy in the template — that drifted out of sync with the
        # actual Schedule citations before.
        template_data[f"{pid}_max_penalty"] = pdata['max_penalty']
        template_data[f"{pid}_sections"] = pdata['sections']

        pillar_findings = [f for f in report['findings'] if f['pillar'] == pid]
        pillar_warnings = [w for w in report['global_warnings'] if w['pillar'] == pid]

        findings_markdown = []
        for f in pillar_findings:
            findings_markdown.append(f"- **[{f['severity']}] {f['id']}** in `{os.path.relpath(f['file'], report['workspace'])}` (line {f['line']}): {f['description']}")
        for w in pillar_warnings:
            findings_markdown.append(f"- **[{w['severity']}] {w['id']}** (Architectural Warning): {w['description']}")

        if not findings_markdown:
            template_data[f"{pid}_findings_list"] = "- No issues detected."
        else:
            template_data[f"{pid}_findings_list"] = "\n".join(findings_markdown)

        remediations = []
        for f in pillar_findings:
            if f['remediation'] not in remediations:
                remediations.append(f['remediation'])
        for w in pillar_warnings:
            if w['remediation'] not in remediations:
                remediations.append(w['remediation'])

        if not remediations:
            template_data[f"{pid}_recommendation"] = "Maintain current safeguards and monitor compliance in future updates."
        else:
            template_data[f"{pid}_recommendation"] = " ".join(remediations)

    return template_content.format(**template_data)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def print_report(report):
    """Human-readable console summary for non-JSON invocations."""
    print(f"DPDPA Compliance Scan — {report['workspace']}")
    print(
        f"Scanned {report['total_files_scanned']} files "
        f"(target type: {report['target_type']}) at {report['scan_timestamp']}"
    )
    print(f"Overall: {report['overall_score']}/100 — {report['overall_status']}")
    print()
    print("Pillar scores:")
    for pdata in report['pillar_scores'].values():
        print(
            f"  {pdata['name']:<35} {pdata['score']:>3}%  {pdata['status']:<15} "
            f"({pdata['findings_count']} findings, max penalty {pdata['max_penalty']})"
        )
    print()
    s = report['summary']
    print(
        f"Findings by severity: CRITICAL={s['CRITICAL']} HIGH={s['HIGH']} "
        f"MEDIUM={s['MEDIUM']} LOW={s['LOW']} INFO={s['INFO']}"
    )


def main():
    target_dir = '.'
    target_type = 'general'
    extra_excludes = []
    markdown_out = None
    json_out = None
    company_name = None
    company_uuid = None

    args = sys.argv[1:]
    positional_set = False

    i = 0
    while i < len(args):
        arg = args[i]
        if arg == '--json':
            pass  # handled after scan
        elif arg == '--target-type' and i + 1 < len(args):
            i += 1
            target_type = args[i]
            if target_type not in TARGET_TYPE_BOOSTS:
                print(f"Error: Unknown target type '{target_type}'. Use one of: {', '.join(TARGET_TYPE_BOOSTS.keys())}")
                sys.exit(1)
        elif arg == '--exclude' and i + 1 < len(args):
            i += 1
            extra_excludes.append(args[i])
        elif arg == '--markdown-out' and i + 1 < len(args):
            i += 1
            markdown_out = args[i]
        elif arg == '--json-out' and i + 1 < len(args):
            i += 1
            json_out = args[i]
        elif (arg == '--company-name' or arg == '--company') and i + 1 < len(args):
            i += 1
            company_name = args[i]
        elif arg == '--company-uuid' and i + 1 < len(args):
            i += 1
            company_uuid = args[i]
        elif arg.startswith('--'):
            pass  # ignore unknown flags
        elif not positional_set:
            target_dir = arg
            positional_set = True
        i += 1

    if not os.path.exists(target_dir):
        print(f"Error: Target path '{target_dir}' does not exist.")
        sys.exit(1)

    if not company_uuid:
        company_uuid = os.environ.get('CORRECT_COMPANY_UUID')

    report = run_scan(target_dir, target_type, extra_excludes)

    # Generate the markdown report
    markdown_report = generate_markdown_report(report, company_name=company_name, company_uuid=company_uuid)

    # Save the markdown report to file for reference
    if not markdown_out:
        markdown_out = os.path.join(target_dir, 'dpdpa_compliance_report.md')

    try:
        with open(markdown_out, 'w', encoding='utf-8') as f:
            f.write(markdown_report)
    except Exception as e:
        print(f"Warning: Could not write markdown report to {markdown_out}: {e}", file=sys.stderr)

    # Add the markdown report inside the JSON report
    report['markdown_report'] = markdown_report

    if json_out:
        try:
            with open(json_out, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, default=str)
            print(f"JSON report written to: {json_out}")
        except Exception as e:
            print(f"Warning: Could not write JSON report to {json_out}: {e}", file=sys.stderr)

    if '--json' in sys.argv:
        # Remove non-serializable items (file_filter lambdas are not in output)
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report)
        print(f"Markdown report generated for reference: {markdown_out}")


if __name__ == "__main__":
    main()
