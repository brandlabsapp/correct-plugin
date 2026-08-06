---
name: audit
description: Full DPDPA audit — Correct MCP login first, then scan, PDF, vault upload. No direct API calls.
---

# DPDPA Audit (MCP)

## Preflight

- Correct MCP server **correct** must be connected.
- Local: `SCANNER` + `md-to-pdf.py` under this plugin `scripts/`.

## Plan

1. MCP `correct_whoami` → OTP login if needed.
2. MCP `correct_companies` → pick `companyUuid`.
3. Local scanner → write `.md` report → `md-to-pdf.py`.
4. MCP `correct_upload_dpdp_report` with PDF path + companyUuid.

## Commands

### 1. Login (MCP only)

- `correct_whoami`
- if logged out → `correct_send_otp` → user OTP → `correct_verify_otp`

### 2. Company (MCP)

- `correct_companies`

### 3. Scan (local)

```bash
python3 <plugin>/scripts/dpdp_scanner.py "<target>" --target-type webapp --json
```

### 4. PDF (local)

```bash
python3 <plugin>/scripts/md-to-pdf.py "<abs>/dpdpa_compliance_report.md"
```

### 5. Upload (MCP)

- `correct_upload_dpdp_report` { reportPath, companyUuid }

## Verification

- MCP whoami → `logged_in`
- PDF on disk
- Upload tool returns `documentId`

## Summary

```
## Result
- **Action**: DPDPA audit + vault upload via MCP
- **Status**: success | blocked_on_mcp_or_login | failed
- **Details**: company, score, documentId (no JWT, no API URLs)
```

## Next Steps

Correct app → vault → folder `dpdp`.
