# Correct Cursor plugins

Marketplace repo for Correct plugins.

- **dpdp-compliance-audit**: DPDPA audit. Hosted Correct MCP for login and vault upload. Local scanner and PDF report.

Install from the Cursor Marketplace, or from this repo via a team marketplace import.

Plugin source: `plugins/dpdp-compliance-audit`. Registry: `.cursor-plugin/marketplace.json`.

To add another plugin, see `docs/add-a-plugin.md`.

## Single plugin vs multi-plugin

This template defaults to **multi-plugin** (multiple plugins in one repo).

For a **single plugin**, move your plugin folder contents to the repository root, keep one `.cursor-plugin/plugin.json`, and remove `.cursor-plugin/marketplace.json`.

## Submission checklist

- Each plugin has a valid `.cursor-plugin/plugin.json`.
- Plugin names are unique, lowercase, and kebab-case.
- `.cursor-plugin/marketplace.json` entries map to real plugin folders.
- All frontmatter metadata is present in rule, skill, agent, and command files.
- Logos are committed and referenced with relative paths.
- `node scripts/validate-template.mjs` passes.
- Repository link is ready for submission to the Cursor team (Slack or `kniparko@anysphere.com`).
