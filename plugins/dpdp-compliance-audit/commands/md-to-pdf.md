---
name: md-to-pdf
description: Convert markdown report to PDF locally (not a Correct API call).
---

# MD → PDF (local)

> For the DPDPA audit report specifically, use `generate_pdf_report.py` on the
> scanner's `--json-out` file instead (`/audit` already does this) — it
> renders real tables, severity colors, and grouped fixes that this generic
> converter can't (Markdown tables become flattened plain text here). Use
> this command for any other Markdown file.

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
