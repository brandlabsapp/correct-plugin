# DPDPA Compliance Reference Notes (v2)

Engineering-focused reference mapping every DPDPA legal provision to its corresponding
cloud architecture, API, and codebase requirements.

---

## 1. Notice & Consent (Sections 5 & 6)

### Legal Requirements
- Consent must be **freely given, specific, informed, unconditional, and unambiguous**
  through a clear affirmative action (Section 5(2)).
- A notice must be served **before or at the time** of collecting data, specifying:
  - What personal data is being collected.
  - The specific purpose of processing.
- Consent can be withdrawn at any time with the **same ease** as it was given (Section 5(4)).

### Consent Manager Interoperability (Section 6)
- The law introduces registered third-party **Consent Managers** — apps that centralize
  a user's consent preferences across platforms.
- SaaS platforms must expose **interoperable APIs/webhooks** that:
  - Receive real-time consent revocation signals from external Consent Managers.
  - Automatically freeze or delete data tables when a user revokes via their centralized dashboard.
- Consent Managers must be registered with the DPBI and meet prescribed standards.

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| Pre-checked consent boxes (`checked="checked"`, `defaultChecked={true}`) | ✅ Violates Section 5 |
| Analytics/tracker scripts loaded before consent check | ✅ Violates Section 5 & 6 |
| No consent withdrawal endpoint or UI toggle | ✅ Violates Section 5(4) |
| Cookie banner with only "Accept" (no "Reject") | ✅ Violates free consent |
| Consent text bundled inside EULA without isolation | ✅ Violates specificity |

---

## 2. General Obligations of Data Fiduciary (Section 8)

### Security Safeguards (Section 8(4))
- **Data at Rest**: AES-256 field-level encryption for PII, tokens, location logs, biometrics.
- **Data in Transit**: Enforce TLS 1.3 across all API endpoints, microservice links, and webhooks.
- **Access Barriers**: Multi-Factor Authentication (MFA) + Role-Based Access Control (RBAC)
  for all cloud IAM users, staging, and production instances.

### Breach Notification (Section 8(6))
- In the event of a personal data breach:
  - Notify the **DPBI** — mandatory, no discretion.
  - Notify **every affected Data Principal** — mandatory.
  - Timeline: Initial alert immediately, comprehensive report within **72 hours**.
- Failure to notify: penalty up to **₹200 Crores**.

### Purpose Limitation & Storage Limitation (Section 8(7))
- Personal data must be erased once the purpose is fulfilled or consent is withdrawn.
- For high-volume platforms (20M+ users): hard purge within **3 years** of last active interaction.
- Send automated notification to user **48 hours before** scheduled deletion.

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| Hardcoded API keys, passwords, tokens in source | ✅ Security safeguard failure |
| `.env` files committed without `.gitignore` coverage | ✅ Credential exposure |
| `verify=False` / `rejectUnauthorized: false` | ✅ SSL/TLS bypass |
| MD5/SHA1 used for hashing passwords or PII | ✅ Weak cryptography |
| PII fields in `console.log()` / `print()` / `logger.*()` | ✅ Log exposure |
| Raw PII assignment without encryption wrapper | ✅ Unencrypted storage |
| No breach notification handler code | ✅ Missing Section 8(6) compliance |
| No TTL, cron-job, or auto-deletion scripts | ✅ Missing storage limitation |

---

## 3. Children's Data Mandates (Section 9)

### Legal Requirements
- A **child** = anyone under **18 years old**.
- Must implement **verifiable parental consent** (OTP to parent, Aadhaar validation, identity verification).
- **Absolute ban** on:
  - Behavioral tracking of minors
  - Targeted advertising to minors
  - Profiling or detailed monitoring of minors
- Only contextual, non-personalized content is permitted.

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| No age verification / DOB field at signup | ✅ Missing age gate |
| Analytics/tracking active for minor user paths | ✅ Behavioral tracking ban |
| Advertising SDK loaded for child accounts | ✅ Targeted ad ban |
| No parental consent flow for under-18 users | ✅ Missing guardian consent |

---

## 4. Significant Data Fiduciaries (SDF) (Section 10)

### Trigger Criteria
- Designated by the Central Government based on: volume of data processed, risk to sovereignty,
  risk to public order, risk to electoral democracy, potential impact on state security.

### Compliance Burden
- Appoint a resident **Data Protection Officer (DPO)** based in India, reporting to Board/C-Suite.
- Conduct **Data Protection Impact Assessments (DPIA)** before any high-risk feature deployment.
- Commission **annual independent external security audits**.
- Publish and submit DPIA and audit reports to the DPBI.

---

## 5. Rights of Data Principals (Sections 11–14)

### Right to Access Information (Section 11)
- Users can request a summary of: personal data held, processing activities, third-party
  data sharing (all APIs/subprocessors receiving data).
- Must provide a **"Download My Data"** feature or API endpoint.

### Right to Correction, Completion, Updation & Erasure (Section 12)
- Users can correct outdated records via profile settings.
- **Right to Erasure**: permanent deletion of account and data on request.
  - Exception: retention required by other laws (tax invoices, financial records).
  - Deletion must cascade to all subprocessors, replicas, and caches.

### Right to Grievance Redressal (Section 13)
- Must provide accessible privacy contact (e.g., `privacy@company.com`).
- Internal ticketing system for data protection complaints.
- Users **must exhaust internal remediation** before escalating to DPBI.

### Right to Nominate (Section 14)
- Users can designate a secondary individual to manage/delete their account upon
  death or incapacity.

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| No data export / download endpoint | ✅ Missing Right to Access |
| No account deletion / erasure handler | ✅ Missing Right to Erasure |
| No privacy@/dpo@ contact or grievance UI | ✅ Missing Grievance Redressal |
| No nomination/legacy contact feature | ⚠️ Should be planned |

---

## 6. AI & Machine Learning Compliance (Module 6)

### AI Lifecycle Under DPDPA
- **Training Phase**: Verify historical data was gathered via valid consent.
- **Data Preparation**: Enforce data minimization — strip PII from feature vectors.
- **Inference Phase**: Honor consent withdrawal instantly; stop personalization.
- **Feedback Loops**: Clear architectural boundaries; support consent withdrawal retroactively.
- **Automated Decisions**: Explainability — users must understand what parameters the AI evaluated.

### Algorithmic Fairness
- **Demographic Parity**: Equal positive outcome rates across demographic groups.
- **Equalized Odds**: Equal TPR and FPR across groups.
- **Predictive Parity**: Equal precision across groups.
- **Individual Fairness**: Similar individuals receive similar predictions.

### ML Security Threats
| Attack Vector | Defense |
|---|---|
| **Model Extraction** | API rate limiting, query monitoring, confidence score noise |
| **Membership Inference** | Differential Privacy (DP) during training, dropout optimization |
| **Data Poisoning** | Input sanitization, anomaly detection on feedback loops, golden-dataset validation |

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| PII fields in training/embedding/vectorization code | ✅ Data minimization failure |
| No rate limiting on inference endpoints | ✅ Model extraction vulnerability |
| Raw user feedback fed directly into retraining | ✅ Data poisoning risk |
| No fairness metrics logging | ⚠️ Governance gap |

---

## 7. Cross-Border Data Transfer (Section 16)

### Blacklist Framework
- **Default**: Transfer of personal data outside India is **permitted** unless the
  Central Government explicitly restricts a specific country/territory.
- If a country is blacklisted, all data flows must be rerouted to Indian infrastructure.

### Architectural Requirements
- Design cloud architecture for **portability** — ability to spin up Indian-region
  infrastructure (e.g., AWS `ap-south-1`, GCP `asia-south1`) rapidly.
- Maintain valid **Data Processing Agreements (DPAs)** with all third-party processors.
- For critical sectors (healthcare, fintech), prepare for potential **data localization** mandates.

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| Cloud region configs pointing to non-India regions | ⚠️ Verify DPA coverage |
| Third-party APIs hosted in restricted territories | ✅ Potential violation |
| No region failover/migration capability | ⚠️ Contingency risk |

---

## 8. Voluntary Undertaking (Section 32)

### What It Is
- A formal, legally binding contract where the company **admits an operational loophole**
  and commits to a time-bound remediation plan.
- Submitted directly to the DPBI during an inquiry.

### Business Benefit
- If accepted, the DPBI can **suspend or completely waive** the financial penalties.
- The company must:
  1. Immediately halt the non-compliant processing
  2. Implement targeted structural corrections
  3. Deploy verifiable monitoring tools

### Relevance to Compliance Reports
When generating remediation roadmaps, recommend the Voluntary Undertaking pathway
for organizations that discover violations proactively through audits — this demonstrates
good faith and can significantly reduce penalty exposure.

---

## 9. Penalty Framework (Section 33)

| Offense Category | Maximum Penalty | Common Code-Level Triggers |
|---|---|---|
| Failure to Take Security Safeguards | **₹250 Crores** | Plaintext passwords in Git, unpatched zero-days, no encryption |
| Failure to Report a Data Breach | **₹200 Crores** | Suppressing breach logs, no DPBI notification handler |
| Violation of Minor Protections | **₹200 Crores** | Tracking pixels on child accounts, no age gate |
| Breach of General Obligations | **₹50 Crores** | Processing without consent, no privacy notice |
| Violation of Principal Duties | **₹10,000** | Users filing fake complaints, fabricating identity |

### Judicial Determination Factors (Section 33(2))
1. **Nature, Gravity, Duration**: Transient API glitch vs. months-long structural leak.
2. **Type of Data Impacted**: Analytics metadata vs. unencrypted Aadhaar/KYC/biometrics.
3. **Repetitive Nature**: First-time vs. recurring pattern of infrastructure neglect.
4. **Unjust Enrichment**: Did the company profit from avoiding security investments?
5. **Mitigation Velocity**: How quickly did the team isolate, patch, and alert?
