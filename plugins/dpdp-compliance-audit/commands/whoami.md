---
name: whoami
description: Check Correct session via MCP correct_whoami (no API URLs).
---

# Correct Whoami (MCP)

## Preflight

Correct MCP connected.

## Plan

Call `correct_whoami` only. Do not send OTP from this command.

## Commands

- Tool: `correct_whoami`

## Verification

- `logged_in` → show id/phone
- `logged_out` → tell user to run `/login`

## Summary

```
## Result
- **Action**: whoami
- **Status**: logged_in | logged_out
```

## Next Steps

Logged out → `/login`. Logged in → `/companies` or `/audit`.
