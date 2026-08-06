#!/usr/bin/env python3
"""
DPDPA Compliance Scanner v2.0
Scans codebases for compliance gaps against the Indian Digital Personal
Data Protection Act (DPDPA) 2023 and DPDP Rules 2025.

Usage:
    python3 dpdp_scanner.py <target_directory> [options]

Options:
    --json              Output results as JSON (for agent consumption)
    --target-type TYPE  One of: webapp, api, ml-pipeline, mobile, general (default: general)
    --exclude PATTERN   Glob pattern to exclude (can be repeated)
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

PILLARS = {
    "consent_notice": {
        "name": "Consent & Notice Management",
        "sections": "Sections 5 & 6",
        "max_penalty": "₹50 Crores",
    },
    "security_safeguards": {
        "name": "Security Safeguards & Encryption",
        "sections": "Section 8",
        "max_penalty": "₹250 Crores",
    },
    "data_retention": {
        "name": "Data Retention & Lifecycle",
        "sections": "Section 8(7) & 12",
        "max_penalty": "₹250 Crores",
    },
    "minor_protection": {
        "name": "Children's Data Safeguards",
        "sections": "Section 9",
        "max_penalty": "₹200 Crores",
    },
    "data_principal_rights": {
        "name": "Data Principal Rights",
        "sections": "Sections 11–14",
        "max_penalty": "₹250 Crores",
    },
    "ai_governance": {
        "name": "AI & ML Governance",
        "sections": "Module 6 / DPDPA AI Lifecycle",
        "max_penalty": "₹250 Crores",
    },
    "cross_border": {
        "name": "Cross-Border Data Transfer",
        "sections": "Section 16",
        "max_penalty": "₹250 Crores",
    },
}

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
        r'(?i)\b\w*(api[_-]?key|password|passwd|secret|token|private[_-]?key|'
        r'access[_-]?key|client[_-]?secret|db[_-]?pass|database[_-]?password|'
        r'auth[_-]?token|jwt[_-]?secret|signing[_-]?key)\w*'
        r'\s*[:=]\s*[\'"][a-zA-Z0-9_\-\.\/\+\@\!\#\$\%]{8,}[\'"]'
    ),
    "description": "Hardcoded plaintext credential or secret detected.",
    "dpdpa_section": "Section 8 — Reasonable Security Safeguards",
    "penalty": "Up to ₹250 Crores",
    "remediation": "Move secrets to environment variables or a vault service (AWS Secrets Manager, HashiCorp Vault). Never commit credentials to source control.",
})

PATTERNS.append({
    "id": "ENV_FILE_SECRETS",
    "pillar": "security_safeguards",
    "severity": "CRITICAL",
    "regex": re.compile(
        r'(?i)^(api[_-]?key|password|secret|token|private[_-]?key|'
        r'database[_-]?url|db[_-]?password|aws[_-]?secret|stripe[_-]?key|'
        r'sendgrid|twilio|auth0)\s*=\s*.{8,}'
    ),
    "description": "Secret detected in environment/config file. Verify .env is in .gitignore.",
    "dpdpa_section": "Section 8 — Reasonable Security Safeguards",
    "penalty": "Up to ₹250 Crores",
    "remediation": "Add .env* to .gitignore. Use secret managers in production. Rotate any credentials that have been committed.",
    "file_filter": lambda f: os.path.basename(f).startswith('.env') or os.path.basename(f) in ('docker-compose.yml', 'docker-compose.yaml'),
})

PATTERNS.append({
    "id": "INSECURE_HTTP",
    "pillar": "security_safeguards",
    "severity": "HIGH",
    "regex": re.compile(
        r'[\'"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|10\.\d|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)'
        r'[a-zA-Z0-9_\-\.]+\.[a-zA-Z]{2,}'
    ),
    "description": "Insecure plain HTTP URL to an external endpoint — data in transit is unencrypted.",
    "dpdpa_section": "Section 8 — TLS 1.3 enforcement for data in transit",
    "penalty": "Up to ₹250 Crores",
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
    "dpdpa_section": "Section 8 — Severe security safeguard bypass",
    "penalty": "Up to ₹250 Crores",
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
    "dpdpa_section": "Section 8 — Reasonable Security Safeguards",
    "penalty": "Up to ₹250 Crores",
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
    "dpdpa_section": "Section 8 — Security Safeguards (log exposure)",
    "penalty": "Up to ₹250 Crores",
    "remediation": "Mask or redact PII before logging. Use structured logging with field-level redaction. Never log raw Aadhaar, PAN, location, or biometrics.",
})

PATTERNS.append({
    "id": "RAW_PII_STORAGE",
    "pillar": "security_safeguards",
    "severity": "MEDIUM",
    "regex": re.compile(
        r'(?i)\b(aadhaar|aadhar|pan[_]?number|passport[_]?number|'
        r'gps[_]?coord|biometric[_]?data|fingerprint[_]?hash)\s*[:=]\s*[^=\s]'
    ),
    "description": "PII/identity field assigned directly without visible encryption or hashing wrapper.",
    "dpdpa_section": "Section 8 — AES-256 field-level encryption required at rest",
    "penalty": "Up to ₹250 Crores",
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
    "dpdpa_section": "Section 8(6) — Mandatory breach notification to DPBI within 72 hours",
    "penalty": "Up to ₹200 Crores",
    "remediation": "Implement an incident response module with: (1) automated breach detection, (2) DPBI notification template, (3) affected-user alert system, all within a 72-hour SLA.",
})

# ---- Pillar: consent_notice ----

PATTERNS.append({
    "id": "UNCONSENTED_TRACKER",
    "pillar": "consent_notice",
    "severity": "HIGH",
    "regex": re.compile(
        r'(?i)(google[\-_]?analytics\.com|googletagmanager\.com|'
        r'gtag\s*\(|fbq\s*\(|connect\.facebook\.net|fbevents\.js|'
        r'mixpanel\.init|amplitude\.\w+|hotjar\.com|clarity\.ms|'
        r'segment\.com|heap\.load|plausible\.io|matomo|piwik)'
    ),
    "description": "Third-party analytics/tracking script detected. Must be wrapped in a consent verification check.",
    "dpdpa_section": "Section 5 & 6 — Valid consent required before tracking",
    "penalty": "Up to ₹50 Crores",
    "remediation": "Wrap tracker initialization inside a consent check (e.g., if (hasUserConsented('analytics')) { ... }). Load scripts only after explicit opt-in.",
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
    "penalty": "Up to ₹50 Crores",
    "remediation": "Remove all pre-checked states from consent/marketing checkboxes. Consent must be unchecked by default requiring explicit user action.",
})

# ---- Pillar: data_retention ----

PATTERNS.append({
    "id": "MISSING_RETENTION",
    "pillar": "data_retention",
    "severity": "HIGH",
    "is_absence_check": True,
    "keywords": ['ttl', 'time_to_live', 'expire', 'expiry', 'retention', 'purge', 'prune',
                  'auto_delete', 'cleanup', 'data_lifecycle', 'soft_delete', 'hard_delete',
                  'scheduled_deletion', 'anonymize', 'anonymise', 'gdpr_delete'],
    "description": "No data retention, TTL, expiration, or automated purge logic found in the codebase.",
    "dpdpa_section": "Section 8(7) — Storage limitation; data must be erased when purpose is fulfilled",
    "penalty": "Up to ₹250 Crores",
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
    "penalty": "Up to ₹250 Crores",
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
    "penalty": "Up to ₹250 Crores",
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
    "dpdpa_section": "Section 13 — Right to Grievance Redressal",
    "penalty": "Up to ₹50 Crores",
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
    "dpdpa_section": "Module 6 — Data minimization: strip PII from training datasets",
    "penalty": "Up to ₹250 Crores",
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
    "dpdpa_section": "Module 6 — Model extraction attack defense",
    "penalty": "Up to ₹250 Crores",
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
    "dpdpa_section": "Module 6 — AI Lifecycle compliance required",
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
    "description": "Cloud infrastructure region configured outside India. Verify compliance with cross-border data transfer rules.",
    "dpdpa_section": "Section 16 — Cross-border transfer restrictions (blacklist framework)",
    "penalty": "Up to ₹250 Crores",
    "remediation": "Verify the target country is not on the government's restricted list. Ensure valid consent and DPAs are in place. Plan for data localization contingency (e.g., AWS ap-south-1).",
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
# Scanner Engine
# ---------------------------------------------------------------------------

def should_scan_file(filepath, extra_excludes=None):
    """Determine if a file should be scanned."""
    basename = os.path.basename(filepath)
    ext = os.path.splitext(basename)[1].lower()

    # Skip explicitly ignored files (e.g. lockfiles)
    if basename in IGNORE_FILES:
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

    # Skip files without extensions that are not config files (likely binaries)
    if not ext and basename not in CONFIG_FILES:
        # Check if it looks like a text file by reading first bytes
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
        for i, line in enumerate(lines, 1):
            match = regex.search(line)
            if match:
                findings.append({
                    "id": pattern["id"],
                    "pillar": pattern["pillar"],
                    "severity": pattern["severity"],
                    "file": filepath,
                    "line": i,
                    "content": line.strip(),
                    "match_text": match.group(0),
                    "description": pattern["description"],
                    "dpdpa_section": pattern["dpdpa_section"],
                    "penalty": pattern["penalty"],
                    "remediation": pattern["remediation"],
                })

    return findings, content_lower


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
        found = any(kw in merged_content for kw in keywords)
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
            "dpdpa_section": "Section 8 — Reasonable Security Safeguards",
            "penalty": "Up to ₹250 Crores",
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

    report = {
        "workspace": os.path.abspath(root_dir),
        "scan_timestamp": datetime.now(ist).replace(microsecond=0).isoformat(),
        "target_type": target_type,
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
            f"which represents a potential statutory penalty risk of up to {most_urgent['penalty']}."
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
    template_data = {
        "scan_timestamp": report['scan_timestamp'],
        "workspace_name": os.path.basename(report['workspace']),
        "organisation_line": organisation_line,
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

def main():
    target_dir = '.'
    target_type = 'general'
    extra_excludes = []
    markdown_out = None
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

    if '--json' in sys.argv:
        # Remove non-serializable items (file_filter lambdas are not in output)
        print(json.dumps(report, indent=2, default=str))
    else:
        print_report(report)
        print(f"Markdown report generated for reference: {markdown_out}")


if __name__ == "__main__":
    main()
