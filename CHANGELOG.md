# Changelog

## 0.13.1 — the good guardian

- **The good guardian:** the new tagline and welcome text, in all 20 languages. The word "daemon" is gone from the app, the README and the website.
- **A window sent to the tray stays there**, and its release no longer depends on the system's hide event.
- **A Claude Code OAuth token is named as an Anthropic key.** A `claude setup-token` value was reported as "OpenAI / DeepSeek", which sent people to the wrong provider to revoke it (#22).
- **MCP servers in a project's `.gemini/settings.json` and `.qwen/settings.json` reach the Gatekeeper**, and risky settings in those files are still reported (#27).
- **The command line is packaged for npm** as `agathos-os` (the command stays `agathos`).
- **Website, `llms.txt`, CONTRIBUTING and issue forms** so people, search engines and AI assistants can find and describe AgathOS, and newcomers know how to help.
- **Updated dependencies:** Electron 45 and the GitHub Actions used by the builds.

### Thanks

- @bfs2021 for naming Claude Code OAuth tokens correctly (#22).
