---
name: login
description: Log in to Correct via MCP OTP tools (no direct API/curl).
---

# Correct Login (MCP)

## Preflight

Confirm **correct** MCP is connected. Do not use shell auth scripts or curl.

## Plan

1. `correct_whoami`
2. If logged out → ask 10-digit phone → `correct_send_otp` → wait for SMS → `correct_verify_otp`
3. `correct_whoami` again

## Commands

Use MCP tools only:

| Step | Tool | Args |
|------|------|------|
| Check | `correct_whoami` | — |
| Send OTP | `correct_send_otp` | `phone` (10 digits, no 91) |
| Verify | `correct_verify_otp` | `phone`, `otp` |
| Resend | `correct_resend_otp` | `phone` |
| Logout | `correct_logout` | — |

## Rules

- Never invent OTP.
- Never print full JWT (tools already mask).
- Never call Correct HTTP APIs from the terminal.

## Verification

`correct_whoami` → `status: logged_in`

## Summary

```
## Result
- **Action**: Correct OTP login via MCP
- **Status**: success | failed
- **Details**: user id / phone (no token)
```

## Next Steps

`correct_companies` or `/audit` scan steps.
