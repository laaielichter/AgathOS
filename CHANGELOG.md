# Changelog

## Unreleased

- **An MCP server running from a temp or download folder is noticed on a Mac too:** the `mcp.oddPath` check now accepts both kinds of path separator and knows `/tmp`, `/var/folders` and `/private/var/folders`, so `/Users/me/Downloads/x/server.sh`, `node /tmp/x/index.js` and `C:/Users/me/Downloads/x.exe` are flagged while an ordinary folder such as `/projects/tmpl` is not. Thanks to @17302513901yh-lang! (#17, #50)
- **UTF-16 text files are read, not called binary:** a file saved as UTF-16 with a byte order mark (what PowerShell 5.1 writes with `>`) is now decoded before it is checked, by `check-file` and by `check-text FILE`, so an instruction hidden in it is found. A UTF-32 file or a file full of zero bytes stays `unknown` (binary, not read). Thanks to @17302513901yh-lang! (#30, #40)
- **Look-alike addresses for five more providers are caught:** SambaNova, Novita, DeepInfra, SiliconFlow and MiniMax are now in the brand list the homoglyph and typo checks watch, so `samban0va.ai` and friends are `lookalike` instead of merely `unknown`. Thanks to @17302513901yh-lang! (#34, #46)
- **Names eight more key formats** in scans: SendGrid, DigitalOcean, Databricks, PyPI, Slack webhook, Tavily, Supabase and Pinecone keys. Thanks to @tnalbant! (#33, #39)
- **A download is refused only when a program runs it.** `curl ... | sha256sum`, `| shasum` and `| node-jq` are no longer refused as "runs downloaded code", and `| sudo bash`, `bash <(curl ...)`, `eval "$(curl ...)"`, `| zsh`, `| ruby` and `tee f | sh` now are. Thanks to @tnalbant! (#31, #32, #43)

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
