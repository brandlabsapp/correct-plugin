---
name: profile
description: Show Correct profile via MCP whoami (session check).
---

# Correct Profile (MCP)

## Preflight

`correct_whoami`. If logged out → `/login`.

## Plan

Use `correct_whoami` as the safe profile summary (id, phone, email, name).

## Commands

- `correct_whoami`

## Verification

`status: logged_in` with user fields.

## Summary

```
## Result
- **Action**: profile
- **Status**: success | failed
- **Details**: id, phone, email, name
```

## Next Steps

`/companies` or vault upload after report.
