# AgathOS

**The good daemon for your local AI agents.**

![AgathOS](docs/screenshot.png)

The ancient Greeks believed every home had an *Agathos Daimon*: a good spirit that
quietly watched over the house and the people in it. In computing, a *daemon* is a
program that runs in the background. AgathOS is both: a free, open-source Windows app
that keeps watching the AI agents on your PC, warns you before they do damage, and gives
you a real stop button.

Nothing leaves your PC. No account, no cloud, no telemetry.

## Why

In 2025 and 2026 most real harm from AI agents on personal computers did not come from
an AI that "wanted" evil. It came from:

- **poisoned packages, skills and MCP servers** that stole keys and wallets
  (Nx "s1ngularity", Shai-Hulud, `postmark-mcp`, malicious ClawHub skills)
- **agents in "allow everything" mode** that wiped folders or whole drives
- **hidden instructions** in repos, web pages and rules files, including invisible Unicode
- **local AI servers left open** to the network (Ollama on `0.0.0.0:11434`)
- **agents that say "all tests pass"** when they did not

Prompt injection is not solved, and nobody can reliably read an AI's mind. AgathOS does
not pretend otherwise. It makes every AI on your PC visible, scores the risk in plain
words, predicts the next step from the actions it sees, and limits the damage.

## What it does

**Six watchers**

| Watcher | Looks for |
|---|---|
| Gatekeeper | MCP servers in every app's config: known-bad packages, unpinned versions, inline secrets, plain-http servers. Approve a server and AgathOS pins it; any later change (a "rug pull") is an alarm. Also "approve everything" settings (`chat.tools.autoApprove`, `bypassPermissions`, Codex `approval_policy = "never"`). |
| File watcher | Mass deletion in your project folders (freezes the agents automatically, reversible). Model files: walks pickle opcodes itself and lists every import, inside PyTorch zips too; unreadable files count as suspicious. safetensors and GGUF are green. |
| Network watcher | AI servers listening on the network instead of only on this PC. Outgoing connections and DNS lookups of agent child processes. |
| Key watcher | API keys in `.env` files, configs and MCP definitions. `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` pointing somewhere unexpected. |
| Trap watcher | Invisible characters (zero-width, bidi overrides, Unicode Tags) in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills and rules. Hidden Tag text is decoded and shown. Attack phrases ("ignore previous instructions", `curl … | bash`). |
| Process watcher | Every running agent with an ID card: PID, who started it, signature, dangerous flags (`--dangerously-skip-permissions`, `--yolo`, `--trust-all-tools`), child processes, the task it was given, what it is doing now. Agents started by npm install scripts or temp folders are flagged. |

**The intent engine** gives each agent a risk score from six layers, each with a reason you can read:

1. **Hard rules** that are never learned away: disabling security, persistence, download-and-run, password hunting, mass delete, sending data out.
2. **The lethal trifecta** (Simon Willison): untrusted input + private data + a way out. Two of three is a warning, all three is an alarm.
3. **Next-step prediction**: per-agent transition counts plus attack-chain templates. It warns when only the last step of a chain is missing, before it happens.
4. **Your own baseline**: what is normal for this agent on this PC.
5. **Honesty check**: the agent's transcript (Claude Code, Codex) compared with what Windows saw. "All tests pass" after a failing test run, editing test files during a bug fix, risky commands that never appear in the conversation.
6. **Optional local AI judge** through Ollama. It only sees a cleaned summary, answers in fixed JSON and can only *raise* a score.

**Self-learning, safely.** It learns only from clean sessions or sessions you approved, never while a session read untrusted content, a little at a time, with versions you can roll back. Hard rules are never learned.

**Stop button, in steps.** Freeze an agent's whole process tree (reversible), resume, stop, block it from the internet, or hold *Pause all agents* (also `Ctrl+Alt+Shift+P` and the tray menu).

**AgathOS Guard (optional).** A small helper with admin rights, installed with one UAC prompt. It turns on deep Windows logging (every new process with its full command line, DNS lookups per process; Sysmon if you have it), manages the firewall (block one agent, make an AI server local-only, AI lockdown), reports firewall rules added by other programs, and can freeze processes that run as admin. It runs as SYSTEM from an admin-only folder and only listens on `127.0.0.1` with a token. Removing it restores your previous Windows settings.

**Also:** a tamper-evident log (hash chain), notifications, tray icon, start with Windows, 14 languages (the top 10 world languages English, 中文, हिन्दी, Español, العربية, Français, বাংলা, Português, Русский and Bahasa Indonesia, plus 日本語, 한국어, Deutsch and Nederlands; Arabic right-to-left), dark and light mode, and a local API on `127.0.0.1:47612` for hooks and future add-ons.

## Run it

1. Install Node.js LTS from https://nodejs.org
2. Double-click `start.bat`

The first start downloads Electron and takes a few minutes. Then AgathOS scans your PC
and keeps watching from the system tray.

## Local API

Token: `%APPDATA%\AgathOS\data\api-token.txt`. Send it as `Authorization: Bearer <token>`.
Browsers are refused.

| Method | Path | What |
|---|---|---|
| GET | `/v1/status` | Watchers, running agents, pause state |
| GET | `/v1/agents` | Agent cards with scores and reasons |
| GET | `/v1/events?since=<ms>` | Event log |
| POST | `/v1/check` | `{agent, tool, input, cwd}` → `allow` / `ask` / `deny` before a tool call runs |
| POST | `/v1/pause-all`, `/v1/resume-all` | The stop button |

## Limits (honest list)

- Catching a determined, deceptive agent is an open research problem. AgathOS limits damage; it does not promise to catch everything.
- Without Guard, file and network events are matched to agents by process tree and timing, not by kernel events.
- Agents inside VS Code extensions (Cline, Copilot) share the editor's process; their actions are seen through files and config, not per process.
- Freezing a process can leave a file or git lock half-written. Resume or stop it afterwards.
- Codex transcripts compressed with zstd need a runtime with zstd support.
- Smart TVs, ovens and other smart devices cannot run a watcher themselves. They come next, through the network (DNS sensor), Home Assistant and a phone app, using the local API.

## Translations

All 14 languages are complete. Native speakers: corrections are very welcome, the texts live in
`src/i18n.js` and `src/locales/`.

## Tests

`node test/run-tests.js` runs the scanners, the intent engine, the honesty check and the
log chain on any OS.

## License

MIT
