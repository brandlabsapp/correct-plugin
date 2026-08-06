# DPDPA Compliance Audit Report

**Date**: {scan_timestamp}
**Project**: `{workspace_name}`
{organisation_line}**Target Type**: {target_type}
**Files Scanned**: {total_files_scanned}
**Overall Compliance Score**: {overall_score} / 100 — {overall_status_icon} **{overall_status}**

---

## 1. Executive Summary

{executive_summary}

### Compliance Score Matrix

| DPDPA Pillar | Score | Status | Findings | Statutory Sections | Max Penalty |
|---|---|---|---|---|---|
| Consent & Notice Management | {consent_notice_score}% | {consent_notice_status} | {consent_notice_count} | Sections 5 & 6 | ₹50 Crores |
| Security Safeguards & Encryption | {security_safeguards_score}% | {security_safeguards_status} | {security_safeguards_count} | Section 8 | ₹250 Crores |
| Data Retention & Lifecycle | {data_retention_score}% | {data_retention_status} | {data_retention_count} | Section 8(7) & 12 | ₹250 Crores |
| Children's Data Safeguards | {minor_protection_score}% | {minor_protection_status} | {minor_protection_count} | Section 9 | ₹200 Crores |
| Data Principal Rights | {data_principal_rights_score}% | {data_principal_rights_status} | {data_principal_rights_count} | Sections 11–14 | ₹250 Crores |
| AI & ML Governance | {ai_governance_score}% | {ai_governance_status} | {ai_governance_count} | Module 6 | ₹250 Crores |
| Cross-Border Data Transfer | {cross_border_score}% | {cross_border_status} | {cross_border_count} | Section 16 | ₹250 Crores |

---

## 2. Critical & High Severity Findings

{critical_high_findings}

---

## 3. Detailed Audit by DPDPA Pillar

### Pillar A: Consent & Notice Management (Sections 5 & 6)
- **Score**: {consent_notice_score}%
- **Status**: {consent_notice_status}
- **What was checked**:
  - Presence of third-party tracking scripts (GA, FB Pixel, Mixpanel, Amplitude, Hotjar) and whether they are wrapped inside consent verification gates
  - Pre-checked consent checkboxes or default opt-in patterns
  - Consent withdrawal mechanisms
- **Findings**:
{consent_notice_findings_list}
- **Recommendation**: {consent_notice_recommendation}

---

### Pillar B: Security Safeguards & Encryption (Section 8)
- **Score**: {security_safeguards_score}%
- **Status**: {security_safeguards_status}
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
{security_safeguards_findings_list}
- **Recommendation**: {security_safeguards_recommendation}

---

### Pillar C: Data Retention & Lifecycle (Section 8(7) & 12)
- **Score**: {data_retention_score}%
- **Status**: {data_retention_status}
- **What was checked**:
  - Presence of TTL triggers, auto-deletion cron jobs, database purge scripts
  - Data lifecycle management logic
  - User-initiated data erasure cascading to subprocessors
- **Findings**:
{data_retention_findings_list}
- **Recommendation**: {data_retention_recommendation}

---

### Pillar D: Children's Data Safeguards (Section 9)
- **Score**: {minor_protection_score}%
- **Status**: {minor_protection_status}
- **What was checked**:
  - Age verification or DOB collection at signup
  - Parental/guardian consent flows for users under 18
  - Tracking/profiling/advertising disabled for minor user code paths
- **Findings**:
{minor_protection_findings_list}
- **Recommendation**: {minor_protection_recommendation}

---

### Pillar E: Data Principal Rights (Sections 11–14)
- **Score**: {data_principal_rights_score}%
- **Status**: {data_principal_rights_status}
- **What was checked**:
  - Data export / "Download My Data" endpoint (Section 11)
  - Account deletion / data erasure handler (Section 12)
  - Grievance redressal channel — privacy@, DPO contact (Section 13)
  - Nominee / legacy contact feature (Section 14)
- **Findings**:
{data_principal_rights_findings_list}
- **Recommendation**: {data_principal_rights_recommendation}

---

### Pillar F: AI & ML Governance (Module 6)
- **Score**: {ai_governance_score}%
- **Status**: {ai_governance_status}
- **What was checked**:
  - PII fields in training/embedding/vectorization pipelines
  - Rate limiting on inference API endpoints
  - AI/ML library and vector DB dependencies detected
  - Fairness audit logging
  - Feedback loop input sanitization
- **Findings**:
{ai_governance_findings_list}
- **Recommendation**: {ai_governance_recommendation}

---

### Pillar G: Cross-Border Data Transfer (Section 16)
- **Score**: {cross_border_score}%
- **Status**: {cross_border_status}
- **What was checked**:
  - Cloud infrastructure region configurations (AWS, GCP, Azure)
  - Third-party APIs/services hosted outside India
  - Data Processing Agreements (DPAs) coverage
  - Data localization contingency planning
- **Findings**:
{cross_border_findings_list}
- **Recommendation**: {cross_border_recommendation}

---

## 4. Penalty Risk Matrix

{penalty_risk_matrix}

**Cumulative Penalty Exposure**: {total_exposure}

> [!CAUTION]
> Under Section 33, each offense is penalized independently. Multiple violations
> in the same codebase can result in cumulative penalties.

---

## 5. Remediation Roadmap

{remediation_roadmap}

---

## Appendix A: Scanned Files & Coverage

**Total Files Scanned**: {total_files_scanned}

<details>
<summary>Click to expand full file list</summary>

```
{scanned_files_list}
```

</details>

**Excluded Directories**: `.git`, `node_modules`, `venv`, `dist`, `build`, `__pycache__`, `.agents`

---

*Report generated by the DPDPA Compliance Scanner v2.0*
*Reference: Digital Personal Data Protection Act, 2023 (India) & DPDP Rules, 2025*
