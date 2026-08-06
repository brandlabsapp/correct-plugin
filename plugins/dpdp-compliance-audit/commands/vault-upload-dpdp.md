---
name: vault-upload-dpdp
description: Upload DPDP report to Correct vault via MCP (MD→PDF local, then correct_upload_dpdp_report).
---

# Vault Upload DPDP (MCP)

## Preflight

1. `correct_whoami` → logged_in
2. Report `.md` exists on disk
3. Correct MCP connected

## Plan

1. Convert MD → PDF with local `scripts/md-to-pdf.py` (not Correct API).
2. `correct_companies` if company unknown.
3. `correct_upload_dpdp_report`:
   - **Hosted HTTP MCP:** pass `reportBase64` + `displayName` (server cannot read laptop paths).
   - **Local stdio MCP:** `reportPath` absolute path is fine.

## Commands

### PDF (local only)

```bash
python3 <plugin>/scripts/md-to-pdf.py "/abs/path/dpdpa_compliance_report.md"
```

### Base64 for hosted upload

```bash
base64 -i "/abs/path/dpdpa_compliance_report.pdf" | tr -d '\n'
```

### Upload (MCP only)

- Tool: `correct_upload_dpdp_report`
- Hosted: `reportBase64`, `displayName` (e.g. `dpdpa_compliance_report.pdf`), `companyUuid`
- Local: `reportPath`, `companyUuid`

## Rules

- No curl / Nest routes / vault shell scripts.
- Prefer uploading `.pdf`.

## Verification

Tool returns `status: uploaded`, `folderId`, `documentId`.

## Summary

```
## Result
- **Action**: vault upload via MCP
- **Status**: success | failed
- **Details**: companyUuid, folderId, documentId, fileName
```

## Next Steps

Open Correct app → company vault → `dpdp`.
