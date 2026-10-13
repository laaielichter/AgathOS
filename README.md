# AgathOS

**The good daemon for your local AI agents.**

![AgathOS](docs/screenshot.png)

The ancient Greeks believed every home had an *Agathos Daimon*: a good spirit that
quietly watched over the house and the people in it. In computing, a *daemon* is a
program that runs in the background. AgathOS is both: a good daemon that watches
the AI agents on your Windows PC.

It finds the agents, MCP servers and instruction files on your machine. Six
watchers look for the attacks that actually happened in 2025 and 2026:

| Watcher | Looks for |
|---|---|
| Gatekeeper | New or changed MCP servers and tool descriptions (rug pulls, poisoned servers like `postmark-mcp`) |
| File watcher | Agents that delete or encrypt many files at once |
| Network watcher | Local AI servers open to the network (Ollama on `0.0.0.0:11434`) |
| Key watcher | API keys and tokens sitting in plain files |
| Trap watcher | Hidden instructions and invisible Unicode in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills |
| Process watcher | Who starts your AI CLIs, and with which "skip permissions" flags |

AgathOS never stops anything without your yes. Nothing leaves your PC.

Available in English, Nederlands, Deutsch, Français, Español and 中文.
Dark mode by default, light mode one click away.

## Status

Step 1: the interface, with demo data. Next: a live background scan with an
ID card for every running agent and an intent engine that predicts what it will
do next.

## Run it

1. Install Node.js LTS from https://nodejs.org
2. Double-click `start.bat`

The first start downloads Electron and takes a few minutes.

## License

MIT
