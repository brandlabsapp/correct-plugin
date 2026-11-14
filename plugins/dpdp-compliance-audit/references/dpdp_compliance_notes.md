# DPDPA Compliance Reference Notes (v3)

Engineering-focused reference mapping every DPDPA legal provision to its corresponding
cloud architecture, API, and codebase requirements.

> **Sourcing & verification status.** Statutory text and the penalty Schedule below
> were pulled directly from dpdpa.com's reproduction of the Act and Section 33's
> commentary (a secondary legal-reference site, not the official Gazette). Treat
> exact penalty figures and section cross-references as directionally correct
> pending confirmation against the official Gazette text — **this is not legal
> advice**, and a qualified counsel should review any customer-facing compliance
> report before it is relied on for a real risk decision. One specific citation
> (Schedule Item 5, below) could not be verified and is flagged inline.

---

## 0. The Penalty Schedule (see Section 33)

DPDPA penalties are **not** a flat amount per topic — Section 33 ties every penalty
to one of **8 specific items** in the Schedule. Most pillars below map to **Item 1**
(₹200 Cr), not a bespoke number per pillar.

| Item | Contravention | Penalty |
|---|---|---|
| 1 | Contravention of sections 4–12 and section 14 (the bulk of consent, security, children's data, and rights obligations) | Up to ₹200 Crores |
| 2 | Failure to take reasonable security safeguards — Section 8(5) | Up to ₹200 Crores |
| 3 | Failure to notify the Board and affected Data Principals of a breach — Section 8(6) | Up to ₹200 Crores |
| 4 | Failure to appoint a DPO / publish contact info — Section 10 (Significant Data Fiduciaries) | Up to ₹10 Crores |
| 5 | Failure to publish business contact information — cited by the source as "Section 9(1)(c)" ⚠️ **unverified**: Section 9 is entirely about children's consent and has no (1)(c) sub-clause; this obligation reads as Section 8(9) in the Act text we have. Confirm against the official Gazette before quoting this item by section number. | Up to ₹10 Crores |
| 6 | Failure to conduct a DPIA or Data Protection Audit — Section 10(1)(b)/(c) (SDFs only) | Up to ₹50 Crores |
| 7 | Failure to provide information to the Board — Section 32(2) | Up to ₹10 Crores |
| 8 | Failure to comply with Board directions — Section 34 | Up to ₹250 Crores |

**The 2× multiplier (Section 33(3)):** the Board may reduce a penalty to as little as
50% of its determined base, or enhance it up to 200% — e.g. a ₹200 Cr base penalty
under Item 1 can land anywhere from ₹100 Cr (strong remediation, self-reported) to
₹400 Cr (egregious, repeat, profited from the violation).

**Who can be penalized:** only Data Fiduciaries. Data Processors cannot be penalized
directly (the Fiduciary is liable for the processor's failures); Data Principals face
no penalties for violating their own duties (Section 15), beyond a token ₹10,000 under
a different schedule.

**Liability is non-delegable (Section 8(1)):** a Data Fiduciary is responsible for
compliance "irrespective of any agreement to the contrary" — contract clauses that try
to shift DPDPA liability onto a processor are void. Indemnification between the two is
commercially valid, but doesn't change who the Board penalizes first.

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
- Consent Managers must be registered with the Board and meet prescribed standards
  (net worth ≥ ₹2 Cr, independent certification of their platform, fiduciary duty to
  the Data Principal, 7-year consent record retention — see DPDP Rules 2025, First
  Schedule).

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| Pre-checked consent boxes (`checked="checked"`, `defaultChecked={true}`) | ✅ Violates Section 5 |
| Analytics/tracker scripts loaded before consent check | ✅ Violates Section 5 & 6 |
| No consent withdrawal endpoint or UI toggle | ✅ Violates Section 5(4) |
| Cookie banner with only "Accept" (no "Reject") | ✅ Violates free consent |
| Consent text bundled inside EULA without isolation | ✅ Violates specificity |

**Penalty:** Schedule Item 1 — up to ₹200 Crores (not a separate, lower consent-specific
figure; consent violations fall under the same umbrella as most Chapter II obligations).

---

## 2. General Obligations of Data Fiduciary (Section 8)

### Security Safeguards (Section 8(5))
The statutory text only requires **"reasonable security safeguards"** — it does not
mandate a specific algorithm or protocol (no literal "AES-256" or "TLS 1.3" requirement
in the Act itself). Treat those as *industry-standard ways to satisfy* "reasonable,"
not direct quotes from the law:
- **Data at Rest**: field-level encryption for PII, tokens, location logs, biometrics.
- **Data in Transit**: TLS for all API endpoints, microservice links, and webhooks.
- **Access Barriers**: MFA + RBAC for cloud IAM users, staging, and production instances.

### Breach Notification (Section 8(6), DPDP Rule 7)
- In the event of a personal data breach:
  - Notify the **Board** — mandatory, no discretion.
  - Notify **every affected Data Principal** — mandatory.
  - Timeline per Rule 7: notify the Board **without delay**, with a detailed report
    following **within 72 hours** of becoming aware of the breach. The "72 hours"
    figure some guides quote is the detailed-report deadline, not the first alert.
  - Failure to notify: penalty up to **₹200 Crores** (Schedule Item 3).

### Purpose Limitation & Storage Limitation (Section 8(7))
- Personal data must be erased once the purpose is fulfilled or consent is withdrawn,
  unless retention is required by another law.
- DPDP Rule 8 and the Rules' Third Schedule set a **3-year** inactivity-based retention
  default specifically for large e-commerce, online gaming, and social media platforms
  (above government-notified user thresholds) — this is a sector-specific default, not
  a universal rule for every Data Fiduciary. Smaller or differently-classed fiduciaries
  may have different or no prescribed timeline yet.

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

**Penalty:** Section 8(5) failures are Schedule Item 2 (up to ₹200 Cr); Section 8(6)
breach-notification failures are Item 3 (up to ₹200 Cr); most other Section 8 failures
fall under the general Item 1 (up to ₹200 Cr).

---

## 3. Children's Data Mandates (Section 9)

### Legal Requirements
- A **child** = anyone under **18 years old**.
- Must implement **verifiable parental consent** (DPDP Rule 10 specifies acceptable
  methods — identity and age verification of the parent/guardian).
- **Absolute ban (Section 9(3))** on:
  - Behavioral tracking or monitoring of children
  - Targeted advertising directed at children
- Section 9(2) separately bars processing likely to cause detrimental effect on a
  child's well-being — broader than just tracking/ads.
- Section 9(4)/(5) allow narrow, rule-specified exemptions (e.g. certain classes of
  fiduciary, or a government-notified "verifiably safe" age threshold) — these are the
  exception, not the default; don't assume an exemption applies without checking Rule 11.

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| No age verification / DOB field at signup | ✅ Missing age gate |
| Analytics/tracking active for minor user paths | ✅ Behavioral tracking ban (9(3)) |
| Advertising SDK loaded for child accounts | ✅ Targeted ad ban (9(3)) |
| No parental consent flow for under-18 users | ✅ Missing guardian consent (9(1)) |

**Penalty:** Schedule Item 1 — up to ₹200 Crores. Children's data is explicitly called
out by regulators as the aggravating factor most likely to push the Board toward the
2× enhancement under Section 33(3).

---

## 4. Significant Data Fiduciaries (SDF) (Section 10)

### Trigger Criteria
- Designated by the Central Government based on: volume of data processed, risk to
  sovereignty, risk to public order, risk to electoral democracy, potential impact on
  state security.

### Compliance Burden
- Appoint a resident **Data Protection Officer (DPO)** based in India, reporting to
  Board/C-Suite (Section 10(2)(a)).
- Conduct **Data Protection Impact Assessments (DPIA)** before high-risk processing,
  and an **annual independent audit** (Section 10(1)(b)/(c)).

**Penalty:** DPO/contact-info failure is Schedule Item 4 (up to ₹10 Cr — an
administrative-tier penalty, not a core-rights one); DPIA/audit failure is Item 6 (up
to ₹50 Cr).

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

### Right to Grievance Redressal (Section 13 and Section 8(10))
- Must provide accessible privacy contact (e.g., `privacy@company.com`).
- Internal ticketing system for data protection complaints — Section 8(10) requires
  Data Fiduciaries to maintain this mechanism, and DPDP Rule 14(3) requires a response
  within 90 days.
- Users **must exhaust internal remediation** before escalating to the Board (Section 13(3)).
- **Note:** Section 13 itself is not one of the Schedule's 8 named items; the
  actionable obligation that IS scheduled is the Section 8(10) grievance mechanism
  (under Item 1). Treat a missing grievance channel as an Item 1 finding, not a direct
  "Section 13 penalty."

### Right to Nominate (Section 14)
- Users can designate a secondary individual to manage/delete their account upon
  death or incapacity.

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| No data export / download endpoint | ✅ Missing Right to Access (§11) |
| No account deletion / erasure handler | ✅ Missing Right to Erasure (§12) |
| No privacy@/dpo@ contact or grievance UI | ✅ Missing grievance mechanism (§8(10)) |
| No nomination/legacy contact feature | ⚠️ Should be planned (§14) |

**Penalty:** Schedule Item 1 — up to ₹200 Crores for all of Sections 11, 12, 14, and
the Section 8(10) grievance mechanism.

---

## 6. AI & Machine Learning Compliance (interpretive, not a distinct DPDPA chapter)

DPDPA has **no dedicated AI/ML chapter or "module"** — this pillar is this scanner's
own synthesis of how Section 8's general obligations (data minimization, security,
purpose limitation) apply when the processing happens inside a training or inference
pipeline. Any "Module 6" label in older versions of this plugin was borrowed from
dpdpa.com's own certificate-course page numbering, not a statutory citation — it has
been removed.

### AI Lifecycle Under Section 8
- **Training Phase**: verify historical data was gathered via valid consent (Section 6).
- **Data Preparation**: enforce data minimization — strip PII from feature vectors
  (Section 8(4)'s "appropriate technical and organisational measures").
- **Inference Phase**: honor consent withdrawal instantly; stop personalization
  (Section 6(4)/8(7)).
- **Feedback Loops**: clear architectural boundaries; support consent withdrawal
  retroactively.

### ML Security Threats (industry practice, not statutory text)
| Attack Vector | Defense |
|---|---|
| **Model Extraction** | API rate limiting, query monitoring, confidence score noise |
| **Membership Inference** | Differential Privacy (DP) during training, dropout optimization |
| **Data Poisoning** | Input sanitization, anomaly detection on feedback loops, golden-dataset validation |

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| PII fields in training/embedding/vectorization code | ✅ Data minimization failure (§8) |
| No rate limiting on inference endpoints | ⚠️ Security-safeguard gap (§8(5)), not a named ML provision |
| Raw user feedback fed directly into retraining | ⚠️ Governance gap, not directly scheduled |
| No fairness metrics logging | ⚠️ Governance gap, not directly scheduled |

**Penalty:** where an AI-pipeline finding is really a Section 8(5) security gap, it's
Schedule Item 2 (₹200 Cr). Where it's a general Section 8 obligation gap, it's Item 1
(₹200 Cr). Don't cite an "AI module" penalty — there isn't one.

---

## 7. Cross-Border Data Transfer (Section 16)

### Blacklist Framework
- **Default**: Transfer of personal data outside India is **permitted** unless the
  Central Government explicitly restricts a specific country/territory.
- **As of this writing, no country has been blacklisted** — Section 16's restriction
  power exists but is currently dormant. A finding here is a "verify and monitor" item,
  not evidence of an active violation.
- If a country is later blacklisted, data flows involving it must be rerouted to
  compliant infrastructure.

### Why this pillar carries lower direct penalty exposure
Section 16 sits in Chapter IV, outside the Schedule's Item 1 list ("sections 4 to 12
and section 14"). None of the Schedule's 8 items name Section 16 directly. The
realistic penalty path for an unresolved cross-border issue is **Item 8** (up to ₹250
Cr) — triggered only if the Board specifically directs remediation and it's ignored —
not a direct per-violation figure. Don't present this pillar's exposure as equivalent
to a core Chapter II (Items 1–3) finding.

### Architectural Requirements (good practice regardless of current blacklist status)
- Design cloud architecture for **portability** — ability to spin up Indian-region
  infrastructure (e.g., AWS `ap-south-1`, GCP `asia-south1`) rapidly, in case a
  relevant country is blacklisted later.
- Maintain valid **Data Processing Agreements (DPAs)** with all third-party processors
  regardless of region — this is good practice under Section 8(2), independent of §16.
- For critical sectors (healthcare, fintech), watch for sector-specific data
  localization mandates from other regulators (RBI, IRDAI) — those are separate from
  DPDPA §16 and often stricter.

### Code-Level Patterns to Check
| Pattern | Violation? |
|---|---|
| Cloud region configs pointing to non-India regions | ⚠️ Monitor — not currently restricted |
| Third-party APIs hosted in restricted territories | ⚠️ Would only apply once a territory is actually blacklisted |
| No region failover/migration capability | ⚠️ Contingency risk, not a current violation |

---

## 8. Voluntary Undertaking (Section 32)

### What It Is
- A formal, legally binding contract where the company **admits an operational loophole**
  and commits to a time-bound remediation plan.
- Submitted directly to the Board during an inquiry.

### Business Benefit
- If accepted, the Board can **suspend or completely waive** the financial penalties.
- The company must:
  1. Immediately halt the non-compliant processing
  2. Implement targeted structural corrections
  3. Deploy verifiable monitoring tools

### Relevance to Compliance Reports
When generating remediation roadmaps, recommend the Voluntary Undertaking pathway
for organizations that discover violations proactively through audits — this demonstrates
good faith and, per Section 33(2)(e) and 33(3), can significantly reduce penalty exposure
(the Board explicitly weighs self-reporting and swift remediation when setting the final
amount, and can halve the base penalty).

---

## 9. Penalty Framework — Worked Example

Section 33(2) requires the Board to weigh six factors when setting the final penalty
within a Schedule item's range: (a) nature, gravity, duration; (b) type/sensitivity of
data affected; (c) repetitive nature; (d) gains made or loss avoided; (e) remediation
speed and effectiveness; (f) any other factor the Board considers relevant.

| Scenario | Base (Schedule Item) | Multiplier (§33(3)) | Illustrative Final |
|---|---|---|---|
| First-time consent violation, self-reported, fixed within days | Item 1, ₹200 Cr | 0.25× (strong mitigation) | ~₹50 Cr |
| Security breach, sensitive data, swift remediation & cooperation | Item 2/3, ₹200 Cr | 0.5–0.75× | ₹100–150 Cr |
| Systematic children's-data violation, profited, ignored Board direction | Item 1 + Item 8 | 2× on each | Up to ₹900 Cr combined |

These are illustrative only — the Board's actual determinations are case-specific and
no India-specific enforcement precedent yet exists to calibrate against (the Act's
penalty provisions are new). Don't present illustrative figures as a prediction of a
specific company's outcome.

### Judicial Determination Factors (Section 33(2))
1. **Nature, Gravity, Duration**: transient API glitch vs. months-long structural leak.
2. **Type of Data Impacted**: analytics metadata vs. unencrypted Aadhaar/KYC/biometrics.
3. **Repetitive Nature**: first-time vs. recurring pattern of infrastructure neglect.
4. **Unjust Enrichment**: did the company profit from avoiding security investments?
5. **Mitigation Velocity**: how quickly did the team isolate, patch, and alert?
