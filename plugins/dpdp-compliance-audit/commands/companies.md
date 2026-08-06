---
name: companies
description: List Correct companies via MCP correct_companies.
---

# Correct Companies (MCP)

## Preflight

`correct_whoami` → must be logged_in (else `/login`).

## Plan

Call `correct_companies`. If multiple, ask which `companyUuid`.

## Commands

- Tool: `correct_companies`

## Verification

At least one company with `companyId` + `companyUuid`, or empty with clear hint.

## Summary

```
## Result
- **Action**: list companies
- **Status**: success | empty | failed
- **Details**: names + uuids
```

## Next Steps

`/vault-upload-dpdp` or continue `/audit` with chosen uuid.
