---
name: auth-conventions
description: Auth and vault command conventions for the DPDP compliance audit plugin
---

# Auth / vault command conventions (MCP)

- All Correct auth & vault actions go through **correct** MCP tools (`correct_*`).
- Never document Nest URLs, `/api/v1/...`, or curl examples in command files.
- Local scripts allowed only for: `dpdp_scanner.py`, `generate_pdf_report.py`, `md-to-pdf.py`.
- Required command sections: Preflight, Plan, Commands, Verification, Summary, Next Steps.
