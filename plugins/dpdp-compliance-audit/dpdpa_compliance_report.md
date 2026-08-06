# DPDPA Compliance Audit Report

**Date**: 2026-07-17T00:55:21+05:30
**Project**: `dpdp-compliance-audit`
**Target Type**: general
**Files Scanned**: 35
**Overall Compliance Score**: 67 / 100 — 🟡 **NEEDS_ATTENTION**

---

## 1. Executive Summary

This compliance audit scanned 35 files in the project. The codebase has an overall score of 67/100, indicating a status of **NEEDS_ATTENTION**. The strongest area is **Cross-Border Data Transfer** at 100%, while the weakest area is **Children's Data Safeguards** at 0%. A total of 3 critical and 15 high-severity findings were detected. The most urgent issue is `SSL_BYPASS` found in `references/dpdp_compliance_notes.md` on line 62, which represents a potential statutory penalty risk of up to Up to ₹250 Crores.

### Compliance Score Matrix

| DPDPA Pillar | Score | Status | Findings | Statutory Sections | Max Penalty |
|---|---|---|---|---|---|
| Consent & Notice Management | 64% | 🟡 NEEDS ATTENTION | 3 | Sections 5 & 6 | ₹50 Crores |
| Security Safeguards & Encryption | 8% | 🔴 CRITICAL | 5 | Section 8 | ₹250 Crores |
| Data Retention & Lifecycle | 100% | ✅ PASS | 0 | Section 8(7) & 12 | ₹250 Crores |
| Children's Data Safeguards | 0% | 🔴 CRITICAL | 11 | Section 9 | ₹200 Crores |
| Data Principal Rights | 100% | ✅ PASS | 0 | Sections 11–14 | ₹250 Crores |
| AI & ML Governance | 100% | ✅ PASS | 4 | Module 6 | ₹250 Crores |
| Cross-Border Data Transfer | 100% | ✅ PASS | 0 | Section 16 | ₹250 Crores |

---

## 2. Critical & High Severity Findings

### Finding 1: [CRITICAL] SSL_BYPASS

- **Pillar**: Security Safeguards & Encryption
- **DPDPA Section**: Section 8 — Severe security safeguard bypass
- **Statutory Penalty Risk**: Up to ₹250 Crores
- **Location**: `references/dpdp_compliance_notes.md:62`
- **Description**: SSL/TLS certificate verification is explicitly disabled.

**Evidence** (line 62 of `references/dpdp_compliance_notes.md`):
```
| `verify=False` / `rejectUnauthorized: false` | ✅ SSL/TLS bypass |
```

**Remediation**:
```diff
- | `verify=False` / `rejectUnauthorized: false` | ✅ SSL/TLS bypass |
+ | `verify=True` / `rejectUnauthorized: true` | ✅ SSL/TLS bypass |
```

> Remove SSL verification bypass. Use proper CA certificates. If needed for local dev, gate behind NODE_ENV/FLASK_ENV checks.


---

### Finding 2: [HIGH] PRECHECKED_CONSENT

- **Pillar**: Consent & Notice Management
- **DPDPA Section**: Section 5 — Consent must be freely given via clear affirmative action
- **Statutory Penalty Risk**: Up to ₹50 Crores
- **Location**: `references/dpdp_compliance_notes.md:29`
- **Description**: Pre-checked consent checkbox or default opt-in detected — violates affirmative consent requirement.

**Evidence** (line 29 of `references/dpdp_compliance_notes.md`):
```
| Pre-checked consent boxes (`checked="checked"`, `defaultChecked={true}`) | ✅ Violates Section 5 |
```

**Remediation**:
```diff
- | Pre-checked consent boxes (`checked="checked"`, `defaultChecked={true}`) | ✅ Violates Section 5 |
+ [Remediate this security risk]
```

> Remove all pre-checked states from consent/marketing checkboxes. Consent must be unchecked by default requiring explicit user action.


---

### Finding 3: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `references/dpdp_compliance_notes.md:77`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 77 of `references/dpdp_compliance_notes.md`):
```
- Behavioral tracking of minors
```

**Remediation**:
```diff
- - Behavioral tracking of minors
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 4: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `references/dpdp_compliance_notes.md:78`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 78 of `references/dpdp_compliance_notes.md`):
```
- Targeted advertising to minors
```

**Remediation**:
```diff
- - Targeted advertising to minors
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 5: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `references/dpdp_compliance_notes.md:79`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 79 of `references/dpdp_compliance_notes.md`):
```
- Profiling or detailed monitoring of minors
```

**Remediation**:
```diff
- - Profiling or detailed monitoring of minors
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 6: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `references/dpdp_compliance_notes.md:86`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 86 of `references/dpdp_compliance_notes.md`):
```
| Analytics/tracking active for minor user paths | ✅ Behavioral tracking ban |
```

**Remediation**:
```diff
- | Analytics/tracking active for minor user paths | ✅ Behavioral tracking ban |
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 7: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `references/dpdp_compliance_notes.md:87`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 87 of `references/dpdp_compliance_notes.md`):
```
| Advertising SDK loaded for child accounts | ✅ Targeted ad ban |
```

**Remediation**:
```diff
- | Advertising SDK loaded for child accounts | ✅ Targeted ad ban |
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 8: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `references/dpdp_compliance_notes.md:219`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 219 of `references/dpdp_compliance_notes.md`):
```
| Violation of Minor Protections | **₹200 Crores** | Tracking pixels on child accounts, no age gate |
```

**Remediation**:
```diff
- | Violation of Minor Protections | **₹200 Crores** | Tracking pixels on child accounts, no age gate |
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 9: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `resources/audit_report_template.md:87`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 87 of `resources/audit_report_template.md`):
```
- Tracking/profiling/advertising disabled for minor user code paths
```

**Remediation**:
```diff
- - Tracking/profiling/advertising disabled for minor user code paths
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 10: [HIGH] WEAK_CRYPTO

- **Pillar**: Security Safeguards & Encryption
- **DPDPA Section**: Section 8 — Reasonable Security Safeguards
- **Statutory Penalty Risk**: Up to ₹250 Crores
- **Location**: `scripts/dpdp_scanner.py:177`
- **Description**: Weak/broken hash algorithm (MD5 or SHA1) used — potentially for passwords or PII.

**Evidence** (line 177 of `scripts/dpdp_scanner.py`):
```
r'Digest::MD5|Digest::SHA1|md5\s*\(|sha1\s*\()'
```

**Remediation**:
```diff
- r'Digest::MD5|Digest::SHA1|md5\s*\(|sha1\s*\()'
+ r'Digest::SHA256|Digest::SHA256|sha256\s*\(|sha256\s*\()'
```

> Use bcrypt/scrypt/argon2 for passwords. Use SHA-256/SHA-3 minimum for data integrity. Use AES-256 for encryption at rest.


---

### Finding 11: [HIGH] UNCONSENTED_TRACKER

- **Pillar**: Consent & Notice Management
- **DPDPA Section**: Section 5 & 6 — Valid consent required before tracking
- **Statutory Penalty Risk**: Up to ₹50 Crores
- **Location**: `scripts/dpdp_scanner.py:239`
- **Description**: Third-party analytics/tracking script detected. Must be wrapped in a consent verification check.

**Evidence** (line 239 of `scripts/dpdp_scanner.py`):
```
r'segment\.com|heap\.load|plausible\.io|matomo|piwik)'
```

**Remediation**:
```diff
- r'segment\.com|heap\.load|plausible\.io|matomo|piwik)'
+ [Remediate this security risk]
```

> Wrap tracker initialization inside a consent check (e.g., if (hasUserConsented('analytics')) { ... }). Load scripts only after explicit opt-in.


---

### Finding 12: [HIGH] PRECHECKED_CONSENT

- **Pillar**: Consent & Notice Management
- **DPDPA Section**: Section 5 — Consent must be freely given via clear affirmative action
- **Statutory Penalty Risk**: Up to ₹50 Crores
- **Location**: `scripts/dpdp_scanner.py:252`
- **Description**: Pre-checked consent checkbox or default opt-in detected — violates affirmative consent requirement.

**Evidence** (line 252 of `scripts/dpdp_scanner.py`):
```
r'(?i)(checked\s*=\s*[\'"]?checked|defaultChecked|checked\s*=\s*\{?\s*true|'
```

**Remediation**:
```diff
- r'(?i)(checked\s*=\s*[\'"]?checked|defaultChecked|checked\s*=\s*\{?\s*true|'
+ [Remediate this security risk]
```

> Remove all pre-checked states from consent/marketing checkboxes. Consent must be unchecked by default requiring explicit user action.


---

### Finding 13: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `scripts/dpdp_scanner.py:294`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 294 of `scripts/dpdp_scanner.py`):
```
"id": "MINOR_TRACKING",
```

**Remediation**:
```diff
- "id": "MINOR_TRACKING",
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 14: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `scripts/dpdp_scanner.py:304`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 304 of `scripts/dpdp_scanner.py`):
```
"description": "Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.",
```

**Remediation**:
```diff
- "description": "Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.",
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 15: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `scripts/dpdp_scanner.py:305`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 305 of `scripts/dpdp_scanner.py`):
```
"dpdpa_section": "Section 9 — Behavioral tracking and targeted ads are banned for children",
```

**Remediation**:
```diff
- "dpdpa_section": "Section 9 — Behavioral tracking and targeted ads are banned for children",
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 16: [HIGH] MINOR_TRACKING

- **Pillar**: Children's Data Safeguards
- **DPDPA Section**: Section 9 — Behavioral tracking and targeted ads are banned for children
- **Statutory Penalty Risk**: Up to ₹200 Crores
- **Location**: `scripts/dpdp_scanner.py:307`
- **Description**: Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.

**Evidence** (line 307 of `scripts/dpdp_scanner.py`):
```
"remediation": "Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.",
```

**Remediation**:
```diff
- "remediation": "Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.",
+ [Remediate this security risk]
```

> Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.


---

### Finding 17: [CRITICAL] SSL_BYPASS

- **Pillar**: Security Safeguards & Encryption
- **DPDPA Section**: Section 8 — Severe security safeguard bypass
- **Statutory Penalty Risk**: Up to ₹250 Crores
- **Location**: `rules/dpdp_compliance.mdc:23`
- **Description**: SSL/TLS certificate verification is explicitly disabled.

**Evidence** (line 23 of `rules/dpdp_compliance.mdc`):
```
- **SSL Verification**: Do not disable SSL validation (`verify=False`,
```

**Remediation**:
```diff
- - **SSL Verification**: Do not disable SSL validation (`verify=False`,
+ - **SSL Verification**: Do not disable SSL validation (`verify=True`,
```

> Remove SSL verification bypass. Use proper CA certificates. If needed for local dev, gate behind NODE_ENV/FLASK_ENV checks.


---

### Finding 18: [CRITICAL] SSL_BYPASS

- **Pillar**: Security Safeguards & Encryption
- **DPDPA Section**: Section 8 — Severe security safeguard bypass
- **Statutory Penalty Risk**: Up to ₹250 Crores
- **Location**: `rules/dpdp_compliance.mdc:24`
- **Description**: SSL/TLS certificate verification is explicitly disabled.

**Evidence** (line 24 of `rules/dpdp_compliance.mdc`):
```
`rejectUnauthorized: false`).
```

**Remediation**:
```diff
- `rejectUnauthorized: false`).
+ `rejectUnauthorized: true`).
```

> Remove SSL verification bypass. Use proper CA certificates. If needed for local dev, gate behind NODE_ENV/FLASK_ENV checks.


---

### Finding 19: [CRITICAL] ENV_NOT_GITIGNORED (Architectural)

- **Pillar**: Security Safeguards & Encryption
- **DPDPA Section**: Section 8 — Reasonable Security Safeguards
- **Statutory Penalty Risk**: Up to ₹250 Crores
- **Location**: Project Architecture / Global
- **Description**: .env file(s) found (mcp/.env.example) but .env is NOT in .gitignore. Secrets may be committed to version control.

**Remediation**:
> Add '.env*' to .gitignore immediately. Audit git history for committed secrets and rotate all exposed credentials.


---

## 3. Detailed Audit by DPDPA Pillar

### Pillar A: Consent & Notice Management (Sections 5 & 6)
- **Score**: 64%
- **Status**: 🟡 NEEDS ATTENTION
- **What was checked**:
  - Presence of third-party tracking scripts (GA, FB Pixel, Mixpanel, Amplitude, Hotjar) and whether they are wrapped inside consent verification gates
  - Pre-checked consent checkboxes or default opt-in patterns
  - Consent withdrawal mechanisms
- **Findings**:
- **[HIGH] PRECHECKED_CONSENT** in `references/dpdp_compliance_notes.md` (line 29): Pre-checked consent checkbox or default opt-in detected — violates affirmative consent requirement.
- **[HIGH] UNCONSENTED_TRACKER** in `scripts/dpdp_scanner.py` (line 239): Third-party analytics/tracking script detected. Must be wrapped in a consent verification check.
- **[HIGH] PRECHECKED_CONSENT** in `scripts/dpdp_scanner.py` (line 252): Pre-checked consent checkbox or default opt-in detected — violates affirmative consent requirement.
- **Recommendation**: Remove all pre-checked states from consent/marketing checkboxes. Consent must be unchecked by default requiring explicit user action. Wrap tracker initialization inside a consent check (e.g., if (hasUserConsented('analytics')) { ... }). Load scripts only after explicit opt-in.

---

### Pillar B: Security Safeguards & Encryption (Section 8)
- **Score**: 8%
- **Status**: 🔴 CRITICAL
- **What was checked**:
  - Hardcoded secrets (API keys, passwords, tokens, database credentials)
  - `.env` files committed to VCS without `.gitignore` coverage
  - Insecure HTTP connections to external endpoints
  - SSL/TLS verification bypass
  - Weak cryptography (MD5/SHA1 for sensitive data)
  - PII exposed in application logs
  - Raw PII stored without encryption wrappers
  - Breach notification handler presence
- **Findings**:
- **[CRITICAL] SSL_BYPASS** in `references/dpdp_compliance_notes.md` (line 62): SSL/TLS certificate verification is explicitly disabled.
- **[HIGH] WEAK_CRYPTO** in `scripts/dpdp_scanner.py` (line 177): Weak/broken hash algorithm (MD5 or SHA1) used — potentially for passwords or PII.
- **[CRITICAL] SSL_BYPASS** in `rules/dpdp_compliance.mdc` (line 23): SSL/TLS certificate verification is explicitly disabled.
- **[CRITICAL] SSL_BYPASS** in `rules/dpdp_compliance.mdc` (line 24): SSL/TLS certificate verification is explicitly disabled.
- **[CRITICAL] ENV_NOT_GITIGNORED** (Architectural Warning): .env file(s) found (mcp/.env.example) but .env is NOT in .gitignore. Secrets may be committed to version control.
- **Recommendation**: Remove SSL verification bypass. Use proper CA certificates. If needed for local dev, gate behind NODE_ENV/FLASK_ENV checks. Use bcrypt/scrypt/argon2 for passwords. Use SHA-256/SHA-3 minimum for data integrity. Use AES-256 for encryption at rest. Add '.env*' to .gitignore immediately. Audit git history for committed secrets and rotate all exposed credentials.

---

### Pillar C: Data Retention & Lifecycle (Section 8(7) & 12)
- **Score**: 100%
- **Status**: ✅ PASS
- **What was checked**:
  - Presence of TTL triggers, auto-deletion cron jobs, database purge scripts
  - Data lifecycle management logic
  - User-initiated data erasure cascading to subprocessors
- **Findings**:
- No issues detected.
- **Recommendation**: Maintain current safeguards and monitor compliance in future updates.

---

### Pillar D: Children's Data Safeguards (Section 9)
- **Score**: 0%
- **Status**: 🔴 CRITICAL
- **What was checked**:
  - Age verification or DOB collection at signup
  - Parental/guardian consent flows for users under 18
  - Tracking/profiling/advertising disabled for minor user code paths
- **Findings**:
- **[HIGH] MINOR_TRACKING** in `references/dpdp_compliance_notes.md` (line 77): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `references/dpdp_compliance_notes.md` (line 78): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `references/dpdp_compliance_notes.md` (line 79): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `references/dpdp_compliance_notes.md` (line 86): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `references/dpdp_compliance_notes.md` (line 87): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `references/dpdp_compliance_notes.md` (line 219): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `resources/audit_report_template.md` (line 87): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `scripts/dpdp_scanner.py` (line 294): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `scripts/dpdp_scanner.py` (line 304): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `scripts/dpdp_scanner.py` (line 305): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **[HIGH] MINOR_TRACKING** in `scripts/dpdp_scanner.py` (line 307): Tracking, profiling, or targeted advertising logic found in code paths related to minors/children.
- **Recommendation**: Completely disable analytics, tracking pixels, and behavioral profiling for users identified as minors. Only contextual, non-personalized content is allowed.

---

### Pillar E: Data Principal Rights (Sections 11–14)
- **Score**: 100%
- **Status**: ✅ PASS
- **What was checked**:
  - Data export / "Download My Data" endpoint (Section 11)
  - Account deletion / data erasure handler (Section 12)
  - Grievance redressal channel — privacy@, DPO contact (Section 13)
  - Nominee / legacy contact feature (Section 14)
- **Findings**:
- No issues detected.
- **Recommendation**: Maintain current safeguards and monitor compliance in future updates.

---

### Pillar F: AI & ML Governance (Module 6)
- **Score**: 100%
- **Status**: ✅ PASS
- **What was checked**:
  - PII fields in training/embedding/vectorization pipelines
  - Rate limiting on inference API endpoints
  - AI/ML library and vector DB dependencies detected
  - Fairness audit logging
  - Feedback loop input sanitization
- **Findings**:
- **[INFO] AI_LIBRARY_DETECTED** in `scripts/dpdp_scanner.py` (line 395): AI/ML library or vector database dependency detected. Triggers AI governance pillar checks.
- **[INFO] AI_LIBRARY_DETECTED** in `scripts/dpdp_scanner.py` (line 396): AI/ML library or vector database dependency detected. Triggers AI governance pillar checks.
- **[INFO] AI_LIBRARY_DETECTED** in `scripts/dpdp_scanner.py` (line 397): AI/ML library or vector database dependency detected. Triggers AI governance pillar checks.
- **[INFO] AI_LIBRARY_DETECTED** in `scripts/dpdp_scanner.py` (line 398): AI/ML library or vector database dependency detected. Triggers AI governance pillar checks.
- **Recommendation**: Ensure AI lifecycle compliance: verify training data consent, implement fairness audits, add differential privacy, sanitize feedback loops.

---

### Pillar G: Cross-Border Data Transfer (Section 16)
- **Score**: 100%
- **Status**: ✅ PASS
- **What was checked**:
  - Cloud infrastructure region configurations (AWS, GCP, Azure)
  - Third-party APIs/services hosted outside India
  - Data Processing Agreements (DPAs) coverage
  - Data localization contingency planning
- **Findings**:
- No issues detected.
- **Recommendation**: Maintain current safeguards and monitor compliance in future updates.

---

## 4. Penalty Risk Matrix

| # | Finding ID | Severity | DPDPA Section | Max Penalty | File:Line |
|---|---|---|---|---|---|
| 1 | SSL_BYPASS | CRITICAL | Section 8 — Severe security safeguard bypass | Up to ₹250 Crores | `references/dpdp_compliance_notes.md:62` |
| 2 | SSL_BYPASS | CRITICAL | Section 8 — Severe security safeguard bypass | Up to ₹250 Crores | `rules/dpdp_compliance.mdc:23` |
| 3 | SSL_BYPASS | CRITICAL | Section 8 — Severe security safeguard bypass | Up to ₹250 Crores | `rules/dpdp_compliance.mdc:24` |
| 4 | ENV_NOT_GITIGNORED | CRITICAL | Section 8 — Reasonable Security Safeguards | Up to ₹250 Crores | `Global / Architecture` |
| 5 | PRECHECKED_CONSENT | HIGH | Section 5 — Consent must be freely given via clear affirmative action | Up to ₹50 Crores | `references/dpdp_compliance_notes.md:29` |
| 6 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `references/dpdp_compliance_notes.md:77` |
| 7 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `references/dpdp_compliance_notes.md:78` |
| 8 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `references/dpdp_compliance_notes.md:79` |
| 9 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `references/dpdp_compliance_notes.md:86` |
| 10 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `references/dpdp_compliance_notes.md:87` |
| 11 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `references/dpdp_compliance_notes.md:219` |
| 12 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `resources/audit_report_template.md:87` |
| 13 | WEAK_CRYPTO | HIGH | Section 8 — Reasonable Security Safeguards | Up to ₹250 Crores | `scripts/dpdp_scanner.py:177` |
| 14 | UNCONSENTED_TRACKER | HIGH | Section 5 & 6 — Valid consent required before tracking | Up to ₹50 Crores | `scripts/dpdp_scanner.py:239` |
| 15 | PRECHECKED_CONSENT | HIGH | Section 5 — Consent must be freely given via clear affirmative action | Up to ₹50 Crores | `scripts/dpdp_scanner.py:252` |
| 16 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `scripts/dpdp_scanner.py:294` |
| 17 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `scripts/dpdp_scanner.py:304` |
| 18 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `scripts/dpdp_scanner.py:305` |
| 19 | MINOR_TRACKING | HIGH | Section 9 — Behavioral tracking and targeted ads are banned for children | Up to ₹200 Crores | `scripts/dpdp_scanner.py:307` |
| 20 | AI_LIBRARY_DETECTED | INFO | Module 6 — AI Lifecycle compliance required | N/A (informational) | `scripts/dpdp_scanner.py:395` |
| 21 | AI_LIBRARY_DETECTED | INFO | Module 6 — AI Lifecycle compliance required | N/A (informational) | `scripts/dpdp_scanner.py:396` |
| 22 | AI_LIBRARY_DETECTED | INFO | Module 6 — AI Lifecycle compliance required | N/A (informational) | `scripts/dpdp_scanner.py:397` |
| 23 | AI_LIBRARY_DETECTED | INFO | Module 6 — AI Lifecycle compliance required | N/A (informational) | `scripts/dpdp_scanner.py:398` |

**Cumulative Penalty Exposure**: Up to ₹250 Crores

> [!CAUTION]
> Under Section 33, each offense is penalized independently. Multiple violations
> in the same codebase can result in cumulative penalties.

---

## 5. Remediation Roadmap

### Immediate (0–72 hours) — Critical Issues
- [ ] Fix `SSL_BYPASS` in `references/dpdp_compliance_notes.md` (line 62)
- [ ] Fix `SSL_BYPASS` in `rules/dpdp_compliance.mdc` (line 23)
- [ ] Fix `SSL_BYPASS` in `rules/dpdp_compliance.mdc` (line 24)
- [ ] Fix `ENV_NOT_GITIGNORED` (Architectural Gap)

### Short-Term (1–2 weeks) — High Severity Issues
- [ ] Fix `PRECHECKED_CONSENT` in `references/dpdp_compliance_notes.md` (line 29)
- [ ] Fix `MINOR_TRACKING` in `references/dpdp_compliance_notes.md` (line 77)
- [ ] Fix `MINOR_TRACKING` in `references/dpdp_compliance_notes.md` (line 78)
- [ ] Fix `MINOR_TRACKING` in `references/dpdp_compliance_notes.md` (line 79)
- [ ] Fix `MINOR_TRACKING` in `references/dpdp_compliance_notes.md` (line 86)
- [ ] Fix `MINOR_TRACKING` in `references/dpdp_compliance_notes.md` (line 87)
- [ ] Fix `MINOR_TRACKING` in `references/dpdp_compliance_notes.md` (line 219)
- [ ] Fix `MINOR_TRACKING` in `resources/audit_report_template.md` (line 87)
- [ ] Fix `WEAK_CRYPTO` in `scripts/dpdp_scanner.py` (line 177)
- [ ] Fix `UNCONSENTED_TRACKER` in `scripts/dpdp_scanner.py` (line 239)
- [ ] Fix `PRECHECKED_CONSENT` in `scripts/dpdp_scanner.py` (line 252)
- [ ] Fix `MINOR_TRACKING` in `scripts/dpdp_scanner.py` (line 294)
- [ ] Fix `MINOR_TRACKING` in `scripts/dpdp_scanner.py` (line 304)
- [ ] Fix `MINOR_TRACKING` in `scripts/dpdp_scanner.py` (line 305)
- [ ] Fix `MINOR_TRACKING` in `scripts/dpdp_scanner.py` (line 307)

### Medium-Term (1 month) — Medium Severity & Architecture Gaps
- [x] No medium-term findings.

### Ongoing — Governance & Monitoring
- [ ] Schedule quarterly DPDPA compliance scans
- [ ] Conduct annual independent security audit (if SDF-designated)
- [ ] Maintain immutable consent telemetry logs
- [ ] Run DPIA before each major feature release

---

## Appendix A: Scanned Files & Coverage

**Total Files Scanned**: 35

<details>
<summary>Click to expand full file list</summary>

```
references/dpdp_compliance_notes.md
resources/audit_report_template.md
mcp/LEARN.md
mcp/README.md
mcp/.gitignore
mcp/package.json
mcp/ecosystem.config.cjs
mcp/deploy/nginx.conf.example
mcp/deploy/ec2-setup.sh
mcp/src/create-server.ts
mcp/src/http.ts
mcp/src/session.ts
mcp/src/session-store.ts
mcp/src/index.ts
mcp/src/config.ts
mcp/src/session-context.ts
mcp/src/correct-client.ts
mcp/src/tools/helpers.ts
mcp/src/tools/companies.ts
mcp/src/tools/vault.ts
mcp/src/tools/index.ts
mcp/src/tools/auth.ts
scripts/md-to-pdf.py
scripts/dpdp_scanner.py
rules/dpdp_compliance.mdc
rules/correct-login-first.mdc
commands/whoami.md
commands/login.md
commands/companies.md
commands/audit.md
commands/md-to-pdf.md
commands/vault-upload-dpdp.md
commands/_auth-conventions.md
commands/profile.md
skills/SKILL.md
```

</details>

**Excluded Directories**: `.git`, `node_modules`, `venv`, `dist`, `build`, `__pycache__`, `.agents`

---

*Report generated by the DPDPA Compliance Scanner v2.0*
*Reference: Digital Personal Data Protection Act, 2023 (India) & DPDP Rules, 2025*
