---
name: md-to-pdf
description: Convert markdown report to PDF locally (not a Correct API call).
---

# MD → PDF (local)

## Preflight

```bash
python3 -c "import fpdf" || pip3 install --user fpdf2
```

## Plan

Run plugin converter on an existing `.md` report.

## Commands

```bash
python3 <plugin>/scripts/md-to-pdf.py "/abs/path/report.md"
# optional second arg for output path
```

## Verification

Prints `pdf:` path and `bytes:` > 0.

## Summary

```
## Result
- **Action**: md → pdf
- **Status**: success | failed
```

## Next Steps

`correct_upload_dpdp_report` with the PDF path (MCP).
