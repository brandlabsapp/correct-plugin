---
name: dpdp-compliance-audit
description: >-
 Full DPDPA audit via Correct MCP: login, company pick, static scan, report,
 PDF, vault upload. Never call Correct HTTP APIs directly — use MCP tools only.
---

# DPDPA Compliance Audit Skill

One plugin. **Correct MCP tools** for auth/vault. Local scripts only for scan +
PDF.

## Hard rules

1. **Never** `curl` Correct backend. **Never** mention or invent Nest routes
   (`/api/v1/...`).
2. Auth/vault **only** via MCP tools: `correct_*`.
3. Login before scan. Do not invent OTP codes.
4. Phone = **10 digits** (no `91`).

If Correct MCP is disconnected, tell the user to enable the **correct** MCP
server (plugin `.mcp.json`) and stop.

---

## Local paths (this plugin)

```bash
PLUGIN="<this-plugin-root>"
SCANNER="$PLUGIN/scripts/dpdp_scanner.py"
MD2PDF="$PLUGIN/scripts/md-to-pdf.py"
chmod +x "$SCANNER" "$MD2PDF"
```

---

## Execution workflow

### Step 1: Login (MCP)

```
correct_whoami
```

If `logged_out`:

1. Ask for 10-digit phone.
2. `correct_send_otp` { phone }
3. Ask user for SMS OTP (never invent).
4. `correct_verify_otp` { phone, otp }
5. `correct_whoami` again → must be `logged_in`.

Optional: `correct_resend_otp` once; `correct_logout` to clear session.

### Step 2: Company (MCP)

```
correct_companies
```

- 0 → stop (register company in Correct app).
- 1 → use that `companyUuid`.
- many → ask user which `companyUuid`.

### Step 3: Discover project

Target type: `webapp` | `api` | `ml-pipeline` | `mobile` | `general`.  
If user names a package (e.g. `correct-app`), scan that path only.

### Step 4: Scanner (local script — not Correct API)

```bash
python3 "$SCANNER" <target_directory> --target-type <type> --json
```

### Step 5–6: Confirm findings + legal notes

Dismiss noise (placeholders, localhost). Scanner already skips `.agents/`, `.cursor/`, `.claude/`, `.env*`, `node_modules/`.  
Enrich from `$PLUGIN/references/dpdp_compliance_notes.md`.

### Step 7: Write report

Template: `$PLUGIN/resources/audit_report_template.md`  
Write `dpdpa_compliance_report.md` (include company name/uuid).

### Step 8: PDF (local) + vault upload (MCP)

```bash
python3 "$MD2PDF" "<abs>/dpdpa_compliance_report.md"
# → sibling .pdf
```

Then MCP:

- **Hosted HTTP MCP** (EC2): server cannot read laptop paths — base64 the PDF,
  then:

```
correct_upload_dpdp_report
  reportBase64: "<base64 of pdf>"
  displayName: "dpdpa_compliance_report.pdf"
  companyUuid: "<from step 2>"
```

- **Local stdio MCP:**

```
correct_upload_dpdp_report
  reportPath: "<abs>/dpdpa_compliance_report.pdf"
  companyUuid: "<from step 2>"
```

Confirm tool result has `documentId` / `folderId`. Never print full JWT.

---

## MCP tools (Correct)

| Tool                         | Purpose                     |
| ---------------------------- | --------------------------- |
| `correct_whoami`             | Session check               |
| `correct_send_otp`           | Send SMS OTP                |
| `correct_verify_otp`         | Save session                |
| `correct_resend_otp`         | Resend SMS                  |
| `correct_logout`             | Clear session               |
| `correct_companies`          | List companies              |
| `correct_upload_dpdp_report` | Folder `dpdp` + upload file |

## Local scripts only

| Script                    | Purpose            |
| ------------------------- | ------------------ |
| `scripts/dpdp_scanner.py` | Static DPDPA scan  |
| `scripts/md-to-pdf.py`    | MD → PDF (`fpdf2`) |

## Slash commands

`/audit` `/login` `/whoami` `/companies` `/md-to-pdf` `/vault-upload-dpdp` — all
instruct MCP tools, not curl.
