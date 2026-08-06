# DPDPA Compliance Audit — Cursor plugin

Install this plugin locally, keep Cursor in sync when you edit it, run an audit,
and extend it (commands, skills, scripts, MCP tools).

Cursor background: [Plugins docs](https://cursor.com/docs/plugins).

---

## What you get

| Piece                        | Role                                                |
| ---------------------------- | --------------------------------------------------- |
| `.cursor-plugin/plugin.json` | Manifest (name, version, folder paths)              |
| `skills/`                    | Main agent workflow (`SKILL.md`)                    |
| `commands/`                  | Slash / chat commands (`/audit`, `/login`, …)       |
| `rules/`                     | Always-on guidance (Correct MCP only, no Nest curl) |
| `scripts/`                   | Local Python: scanner + md→PDF                      |
| `mcp/`                       | Correct MCP server (`correct_*` tools)              |
| `.mcp.json`                  | MCP config Cursor loads with the plugin             |

**Hard rule:** skills/commands never call Nest HTTP (`curl`, `/api/v1/...`).
Auth and vault go only through `correct_*` MCP tools.

---

## 1. Install locally

Cursor loads **user-local** plugins only from:

```text
~/.cursor/plugins/local/<plugin-name>/
```

Required layout:

```text
~/.cursor/plugins/local/dpdp-compliance-audit/.cursor-plugin/plugin.json
```

Do **not** install under `~/.cursor/plugins/cache/` (marketplace cache).

### Option A — Symlink (recommended while developing)

Repo edits apply after a window reload. No re-copy.

```bash
mkdir -p ~/.cursor/plugins/local

# Drop old copy/symlink if present
rm -rf ~/.cursor/plugins/local/dpdp-compliance-audit

# From repo root (or use your absolute path)
ln -s "$(pwd)/plugins/dpdp-compliance-audit" \
  ~/.cursor/plugins/local/dpdp-compliance-audit

# Sanity check
ls ~/.cursor/plugins/local/dpdp-compliance-audit/.cursor-plugin/plugin.json
```

### Option B — Copy (frozen snapshot)

```bash
mkdir -p ~/.cursor/plugins/local
rm -rf ~/.cursor/plugins/local/dpdp-compliance-audit

cp -R /path/to/correct-organisation/plugins/dpdp-compliance-audit \
  ~/.cursor/plugins/local/dpdp-compliance-audit
```

After each meaningful change in the repo: re-copy, then reload. Prefer Option A
for day-to-day work.

### Enable + reload

1. Cursor Settings → enable **Include third-party Plugins, Skills, and other
   configs** (if shown).
2. `Cmd+Shift+P` → **Developer: Reload Window** (or quit and reopen Cursor).
3. **Settings → Plugins** — **DPDPA Compliance Audit** should list under
   Installed.

Team/Enterprise: if local plugins never appear, org policy may set
`userLocal=false`. Ask an admin to allow user-local plugins.

---

## 2. Use it (MCP must be green)

Skills alone are not enough. The **correct** MCP server must show connected in
**Settings → MCP**.

### A. Hosted MCP (default)

Repo `.mcp.json` already points at production:

```json
{
	"mcpServers": {
		"correct": {
			"type": "http",
			"url": "https://mcp.correctapp.ai/mcp"
		}
	}
}
```

After install + reload: **Settings → MCP** → **correct** green. No local Node
needed.

### B. Local stdio MCP (hack on MCP against Nest)

Use when you change `mcp/src/` or need `localhost:8000`.

```bash
cd plugins/dpdp-compliance-audit/mcp
cp -n .env.example .env
# Set:
#   CORRECT_API_URL=http://localhost:8000
#   SESSION_STORE=file
npm install
```

Point the plugin MCP at local stdio. Edit
`~/.cursor/plugins/local/dpdp-compliance-audit/.mcp.json` (with a symlink, that
is the same file as in the repo):

```json
{
	"mcpServers": {
		"correct": {
			"command": "${userHome}/.cursor/plugins/local/dpdp-compliance-audit/mcp/node_modules/.bin/tsx",
			"args": [
				"${userHome}/.cursor/plugins/local/dpdp-compliance-audit/mcp/src/index.ts"
			],
			"env": {
				"CORRECT_API_URL": "http://localhost:8000",
				"SESSION_STORE": "file"
			}
		}
	}
}
```

Template: [`mcp/cursor.mcp.example.json`](./mcp/cursor.mcp.example.json).

**Important:** use `${userHome}/.cursor/plugins/local/...`, **not**
`${workspaceFolder}/plugins/...`. Other workspaces hang with “Timed out waiting
for connection”.

1. Start Correct backend on `:8000` if using local API.
2. Reload Window → **Settings → MCP** → **correct** green.
3. In chat: ask the agent to call `correct_whoami`.

Optional local HTTP MCP: `npm run dev:http` — see
[`mcp/cursor.mcp.http.example.json`](./mcp/cursor.mcp.http.example.json). More
detail: [`mcp/README.md`](./mcp/README.md).

### Day-one smoke test

1. Chat: `correct_whoami` → OTP login if needed (`correct_send_otp` → your SMS
   code → `correct_verify_otp`). Phone = **10 digits**, no `91`. Never invent
   OTP.
2. `correct_companies` → pick a company.
3. Run `/audit` (or ask for a DPDPA audit on a path).
4. Flow: local scanner → markdown report → PDF → `correct_upload_dpdp_report`.

---

## 3. Update the plugin after you change it

| What you changed                                 | What to do                                                                         |
| ------------------------------------------------ | ---------------------------------------------------------------------------------- |
| Skills / commands / rules / scripts / references | Save. Symlink → **Developer: Reload Window**. Copy install → re-copy, then reload. |
| `plugin.json` (name, paths, version)             | Reload Window. Bump `version` for user-visible ships.                              |
| MCP tools under `mcp/src/` (stdio + `tsx`)       | Restart MCP: toggle off/on in Settings → MCP, or Reload Window. No `tsc` needed.   |
| MCP deps (`package.json` / lockfile)             | `cd mcp && npm install`, then restart MCP.                                         |
| Hosted MCP server only                           | Deploy `mcp/` on the host separately; plugin URL in `.mcp.json` usually unchanged. |

### Quick checklist

```bash
ls ~/.cursor/plugins/local/dpdp-compliance-audit/.cursor-plugin/plugin.json

# If local MCP and lockfile changed:
cd ~/.cursor/plugins/local/dpdp-compliance-audit/mcp && npm install
```

Then in Cursor: **Developer: Reload Window** → MCP green → try `correct_whoami`.

### Confirm Agent sees your work

- Slash commands from `commands/` appear.
- Skill `dpdp-compliance-audit` is available.
- New/changed `correct_*` tools show under Settings → MCP → correct → tools.
- Scanner/PDF paths resolve under the plugin `scripts/` root.

---

## 4. Add new features

Pick the smallest surface that fits.

### A. New slash command

1. Add `commands/my-feature.md`:

```markdown
---
description: Short what/when for the agent.
---

# My feature

Steps the agent should follow. Name MCP tools (`correct_*`), not Nest URLs.
```

2. Reload Window.
3. Invoke from command palette / chat.

### B. Change the main audit workflow

Edit [`skills/SKILL.md`](./skills/SKILL.md) (and matching `commands/*.md` if
steps are duplicated).

Keep:

- No `curl` / Nest routes in skill text.
- Auth/vault only via `correct_*`.

### C. New or tighter rules

Add/edit `.mdc` under `rules/`. Manifest already points at `./rules/`.

### D. New local script (scan / PDF / helpers)

1. Add under `scripts/`.
2. Document the exact `python3 ...` invocation in `skills/SKILL.md` and/or a
   command.
3. Scripts stay offline — they must not call Correct HTTP.

### E. New Correct MCP tool (anything that talks to Nest)

1. Private HTTP helpers in `mcp/src/correct-client.ts` (routes stay
   server-side).
2. Register the tool in `mcp/src/tools/<area>.ts`:

```ts
server.registerTool(
	'correct_my_feature',
	{
		title: 'Correct my feature',
		description: 'When to call this. Never put hosts or /api/v1 paths here.',
		inputSchema: {
			// zod fields
		},
	},
	async (args) => {
		// call correct-client helpers
		return { content: [{ type: 'text', text: '...' }] };
	},
);
```

3. Wire it in `mcp/src/tools/index.ts` → `registerAllTools`.
4. Name the tool in `skills/SKILL.md` / relevant `commands/*.md`.
5. Restart MCP (Reload Window or toggle MCP).
6. Confirm under Settings → MCP → correct → tools.

Full checklist lives at the top of
[`mcp/src/tools/index.ts`](./mcp/src/tools/index.ts).

**Stdio note:** never `console.log` in MCP handlers — it corrupts the protocol.
Use `console.error` for logs.

### F. Bump plugin version

For a user-visible change, edit `.cursor-plugin/plugin.json`:

```json
"version": "2.3.0"
```

---

## 5. Folder map

```text
plugins/dpdp-compliance-audit/
├── .cursor-plugin/plugin.json   # Cursor plugin manifest
├── .mcp.json                    # MCP servers bundled with plugin
├── README.md                    # this file
├── commands/                    # slash / agent commands
├── skills/SKILL.md              # main DPDPA workflow
├── rules/                       # always-on guidance
├── scripts/                     # scanner + md-to-pdf
├── references/                  # legal / enrichment notes
├── resources/                   # report template
├── examples/                    # sample findings
└── mcp/                         # Correct MCP (TypeScript)
    ├── src/index.ts             # stdio entry
    ├── src/http.ts              # HTTP entry
    ├── src/tools/               # correct_* tools
    ├── cursor.mcp.example.json  # local stdio template
    ├── README.md                # MCP ops / deploy
    └── LEARN.md                 # transports + tool anatomy
```

---

## 6. Common failures

| Symptom                                                            | Fix                                                                                               |
| ------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------- |
| Plugin missing in Settings                                         | Path must be `~/.cursor/plugins/local/dpdp-compliance-audit/`; reload; enable third-party plugins |
| Nested folder (`.../dpdp-compliance-audit/dpdp-compliance-audit/`) | Flatten so `.cursor-plugin` is one level under `local/<name>/`                                    |
| MCP red / timeout                                                  | Use `${userHome}/.../local/...` paths; `npm install` in `mcp/`; check MCP Logs                    |
| `Not logged in`                                                    | `correct_send_otp` → user OTP → `correct_verify_otp`                                              |
| Copy install feels “stale”                                         | Re-copy or switch to symlink                                                                      |
| Org blocks local plugins                                           | Admin must allow user-local / third-party plugins                                                 |

---

## 7. Copy-paste day-one

```bash
# From correct-organisation repo root
mkdir -p ~/.cursor/plugins/local
rm -rf ~/.cursor/plugins/local/dpdp-compliance-audit
ln -s "$(pwd)/plugins/dpdp-compliance-audit" \
  ~/.cursor/plugins/local/dpdp-compliance-audit

# Optional: local MCP against Nest
cd plugins/dpdp-compliance-audit/mcp
cp -n .env.example .env
# edit .env → CORRECT_API_URL=http://localhost:8000, SESSION_STORE=file
npm install
# then set .mcp.json from mcp/cursor.mcp.example.json (see §2B)
```

Cursor: **Developer: Reload Window** → MCP **correct** green → chat
`correct_whoami` → `/audit`.
