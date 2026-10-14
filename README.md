# AgathOS

**The good daemon for your local AI agents.**

![AgathOS](docs/screenshot.png)

The ancient Greeks believed every home had an *Agathos Daimon*: a good spirit that
quietly watched over the house and the people in it. In computing, a *daemon* is a
program that runs in the background. AgathOS is both: a free, open-source app for Windows and macOS
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
| Gatekeeper | MCP servers in every app's config: known-bad packages, unpinned versions, inline secrets, plain-http servers. Approve a server and AgathOS pins it; any later change (a "rug pull") is an alarm. Also "approve everything" settings (`chat.tools.autoApprove`, `bypassPermissions`, Codex `approval_policy = "never"`, Grok Build `permission_mode = "always-approve"` or a `[permission]` rule that allows every shell command). Grok Build's MCP servers (`~/.grok/config.toml`, project `.grok/config.toml`) are read too. |
| File watcher | Mass deletion in your project folders (freezes the agents automatically, reversible). Model files: walks pickle opcodes itself and lists every import, inside PyTorch zips too; unreadable files count as suspicious. safetensors and GGUF are green. |
| Network watcher | AI servers listening on the network instead of only on this PC. Outgoing connections and DNS lookups of agent child processes. **Worm watch:** any program that knocks on 20+ devices or 15+ ports of one device in your home network within a minute (cameras, TVs, routers), the first move of a self-spreading worm. Test it safely with `node test/lan-scan-sim.js`. |
| Key watcher | API keys in `.env` files, configs and MCP definitions. `ANTHROPIC_BASE_URL` / `OPENAI_BASE_URL` pointing somewhere unexpected. |
| Trap watcher | Invisible characters (zero-width, bidi overrides, Unicode Tags) in `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, skills and rules. Hidden Tag text is decoded and shown. Attack phrases ("ignore previous instructions", `curl … | bash`). |
| Process watcher | Every running agent with an ID card: PID, who started it, signature, dangerous flags (`--dangerously-skip-permissions`, `--yolo`, `--always-approve`, `--trust-all-tools`), child processes, the task it was given, what it is doing now. Agents started by npm install scripts or temp folders are flagged. |

**The intent engine** gives each agent a risk score from six layers, each with a reason you can read:

1. **Hard rules** that are never learned away: disabling security, persistence, download-and-run, password hunting, mass delete, sending data out.
2. **The lethal trifecta** (Simon Willison): untrusted input + private data + a way out. Two of three is a warning, all three is an alarm.
3. **Next-step prediction**: per-agent transition counts plus attack-chain templates. It warns when only the last step of a chain is missing, before it happens.
4. **Your own baseline**: what is normal for this agent on this PC.
5. **Honesty check**: the agent's transcript (Claude Code, Codex, Grok Build) compared with what Windows saw. "All tests pass" after a failing test run, editing test files during a bug fix, risky commands that never appear in the conversation.
6. **Optional local AI judge** through Ollama. It only sees a cleaned summary, answers in fixed JSON and can only *raise* a score.

**Self-learning, safely.** It learns only from clean sessions or sessions you approved, never while a session read untrusted content, a little at a time, with versions you can roll back. Hard rules are never learned.

**Fix it.** After every scan AgathOS lists what it found and offers one button: *Fix all*.
Or open *Review and choose* and pick per finding what happens, or **Dismiss** it: a dismissed
finding stops counting until it changes, and *Show again* brings it back.

Every finding has an **Explain** button with two levels. *Simple* says in one plain sentence
what is going on and what to do. *In depth* shows the evidence (paths, commands, decoded hidden
text, process tree, signer), how the attack works, the harmless and the harmful explanation,
how sure AgathOS is, the matching MITRE ATT&CK / ATLAS technique and the steps to fix it.

![Explain: analysis of a finding](docs/analysis.png)

| Finding | What "Fix it" does | Undo |
|---|---|---|
| Agent in danger | pause it, pause + cut its internet, or stop it | yes, except stop |
| AI server open to the network | firewall rule: only this PC (with Guard) | yes |
| Bad or changed MCP server | takes it out of the app's config, keeps a copy | yes |
| Hidden text in an instruction file | removes the invisible characters, keeps a copy | yes |
| Attack text in a file / dangerous model | renames it to `*.agathos-quarantine` | yes |
| Suspicious scheduled task | turns it off | yes |
| Keys, auto-approve, redirected API addresses | explains what to do yourself | - |

**Auto-fix** is off by default. Switch it on in Settings and pick a level: *Gentle* (only
pauses agents and closes ports), *Firm*, *Maximum*, or *Custom* (your choice per kind of
danger). It then fixes dangers right after a scan or an alarm. A config file with comments
is never rewritten, and a cleaned file is never restored over newer work.

**Stop button, in steps.** Freeze an agent's whole process tree (reversible), resume, stop, block it from the internet, or hold *Pause all agents* (also `Ctrl+Alt+Shift+P` and the tray menu).

**AgathOS Guard (optional).** A small helper with admin rights, installed with one UAC prompt. It turns on deep Windows logging (every new process with its full command line, DNS lookups per process; Sysmon if you have it), manages the firewall (block one agent, make an AI server local-only, AI lockdown), reports firewall rules added by other programs, and can freeze processes that run as admin. It runs as SYSTEM from an admin-only folder and only listens on `127.0.0.1` with a token. Removing it restores your previous Windows settings.

**Live scanner switch.** One click in the title bar (or the tray menu) turns background
watching on or off. It is on by default.

**Live monitor.** The *Live* page (and a small panel on the overview) shows what happens right
now, second by second: new programs, steps of agents, new connections, file changes and alerts,
with a scrolling log in plain words. It lives in memory for about two and a half minutes and is
never saved. Connections of programs that are not agents are only counted, never listed. With
AgathOS Guard on, every new program and every new address lookup of an agent shows up at once;
without it, programs and connections are checked every few seconds. The *Guard* label at the top
turns green when Guard is installed and running.

**Grok.** *Grok Build* (the `grok` command of xAI) is recognised on Windows and on a Mac, where the
system shows the file behind the `grok` link instead of the name. AgathOS reads its settings and
MCP servers (`config.toml`, also in a project's `.grok` folder), its hooks, its rules and skills,
treats `--always-approve` (alias `--yolo`) as a dangerous flag, and reads its sessions
(`~/.grok/sessions`, or `GROK_HOME`) for the task and the honesty check. *Grok Bot*, the desktop
app of xAI, shows under *Active now* like the command line agents. It works mostly on its own
cloud computer, so AgathOS only sees the app, its network traffic and the files it touches on
this computer, and says so on its card.

**Mini pop-up (Windows).** Click the AgathOS icon next to the clock and a small window opens
right above it: the six watchers, the status, *Fix all*, *Scan now*, *Pause all agents*, the
live scanner switch and the agents running now. Double-click for the full window, right-click
for the menu. The icon itself shows a coloured dot for attention, danger or paused.

**AI browser extensions.** In 2026 two Chrome extensions posing as AI helpers (about 900,000
users) copied chats and open tabs to a server. AgathOS reads the `manifest.json` of the
extensions in Chrome, Edge and Brave (all profiles, nothing is run) and lists those that are
about AI or may reach AI chat sites (Files > Browser extensions). It is attention when one may
read every website you open, and it shows wider rights such as tabs, history and cookies. A
change in rights after an update is reported again. It cannot see what an extension really does.
You decide in the browser: AgathOS only shows the way.

**Package and workflow check (worm watch, part 2).** Worms such as Shai-Hulud spread through npm
packages: an install script steals tokens and publishes the worm into your own packages. AgathOS
reads only text in the project folders it watches (package.json, install scripts and the files they
start, GitHub workflows, and the first level of node_modules) and warns about known worm leftovers
(setup_bun.js, bun_environment.js, truffleSecrets.json, shai-hulud workflows), install scripts that
download and run code or reach for tokens and keys, hidden code, a script that publishes packages,
and workflows that dump all secrets or post to a catch-all address such as webhook.site. Nothing is
run and nothing is changed. It cannot prove that a package is safe, and you can dismiss every
finding or switch the check off in Settings.

**Backup check.** An agent that deletes a folder is only a disaster when there is no second
copy. AgathOS looks for a sign of a copy of each folder it watches (not Downloads): the folder
lies inside a OneDrive, Dropbox, Google Drive or iCloud folder, every Git project in it has a
remote, or on a Mac Time Machine has made a backup (Files > Backup). It never reads your files
and changes nothing. It does not look inside File History or other backup programs and cannot see
an external disk, so it only says "no sign of a backup": if you have one it cannot see, press
*Dismiss*. Switch it off in Settings.

**Check text.** Paste a prompt, README, rules file or web text before an agent reads it.
AgathOS shows hidden characters (and decodes them), attack text and keys, and copies a clean
version for you.

**Download guard.** New files in Downloads are checked the moment they land: models that can
run code, rules files or prompts with hidden instructions, and fake installers: an `.exe`, `.msi`
or similar named after a tool that is not installed with a file (Claude Code, OpenClaw, Gemini CLI,
Codex CLI) is an alarm, a zip of it is a warning. Fake download pages for these tools spread
password stealers this way. It only warns; it never opens or runs the file.

**Calm notifications.** No notification circus: by default only danger pops up (attention goes to
the log and the tray dot), what happens at the same time comes as one notification, the same
finding is not repeated within 6 hours, at most 3 per hour, and nothing pops up while the
AgathOS window is open. Set quiet hours, or pause notifications for an hour or until tomorrow.
Danger that needs you right now (mass deletion, data leaving, a malicious MCP server) always
comes through. Windows Focus and macOS Focus are respected as well.

**Every window can be closed** with its X, with Esc, or with a click next to it.

**Safety report.** One HTML page with all findings, agents, fixes and the last 24 hours, to
keep or share (Log > Save report).

**Updates.** AgathOS checks GitHub Releases once a day. On Windows the installed app downloads
the new installer, checks its SHA-256 against the checksum GitHub publishes, and only then
installs it and starts again. By default it does this by itself, but only at a quiet moment: no
agent active, no scan running, the window not in use (otherwise it tries again 20 minutes later),
and after a calm notification. Switch it off at Settings > Updates. On a Mac it opens the download page.

**Mini pop-up (Windows).** Click the AgathOS icon next to the clock and a small window opens
right above it: the six watchers, the status, *Fix all*, *Scan now*, *Pause all agents*, the
live scanner switch and the agents running now. Double-click the icon for the full window,
right-click for the menu.

**Advanced or simple.** The advanced view (default) shows every score, process and
prediction. The simple view keeps four pages and plain words.

**Welcome screen.** The first start asks for your language, the view, the live scanner,
starting with Windows, deep protection (AgathOS Guard) and auto-fix.

**Also:** a tamper-evident log (hash chain), notifications, tray icon, start with Windows, 14 languages (the top 10 world languages English, 中文, हिन्दी, Español, العربية, Français, বাংলা, Português, Русский and Bahasa Indonesia, plus 日本語, 한국어, Deutsch and Nederlands; Arabic right-to-left), dark and light mode, and a local API on `127.0.0.1:47612` for hooks and future add-ons.

## Install

**Installer.** Run `AgathOS-Setup-<version>.exe`. Pick a language, choose the folder, and
AgathOS lands on your desktop and in the Start menu, then starts with the welcome screen.
No admin rights needed. The installer is not code-signed yet, so Windows SmartScreen may say
"Windows protected your PC": click *More info* and *Run anyway*.

Build the installer yourself: install Node.js LTS from https://nodejs.org and double-click
`build-installer.bat`. It ends up in `dist\`. GitHub Actions builds it too (see Actions).

**Without building.** Install Node.js LTS, then double-click `install.bat`. It copies AgathOS
to `%LOCALAPPDATA%\Programs\AgathOS`, adds shortcuts with the AgathOS icon to the desktop and
the Start menu, and registers an uninstaller under Settings > Apps.

**Just try it.** Double-click `start.bat` to run it from this folder.

**Mac.** Download `AgathOS-<version>-arm64.dmg` (Apple chip, M1 and newer) or `-x64.dmg` (Intel),
open it and drag AgathOS to Applications. The app is not notarized by Apple yet: the first time,
open it, then go to System Settings > Privacy & Security and click *Open Anyway*. macOS may ask
whether AgathOS can read your Documents, Desktop and Downloads folders; that is where it looks for
instruction files, MCP settings and keys. From source: `npm install` and `npm start`.
Build the disk images yourself on a Mac with `npm run dist:mac`.

> **Mac testers wanted.** The Mac version is built and its tests run automatically on macOS,
> but nobody has clicked through it on a real Mac yet. If something does not work or looks
> wrong, please open an issue with a screenshot and your macOS version.

> **Mac testers wanted.** The Mac version is built and its tests run automatically on macOS,
> but nobody has clicked through it on a real Mac yet. If something does not work or looks
> wrong, please open an issue with a screenshot and your macOS version.

After the first scan AgathOS keeps watching from the system tray.

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

## Windows and Mac

| | Windows | Mac |
|---|---|---|
| Agents, MCP servers, instruction files, keys, models | yes | yes |
| Live process watching, intent engine, honesty check | yes | yes (`ps`) |
| Open AI ports and connections | yes | yes (`lsof`) |
| Worm watch (network sweeps) | yes | yes (`lsof`) |
| Freeze, resume, stop an agent | yes | yes (signals) |
| Autostart check and "turn off" | scheduled tasks | LaunchAgents (`launchctl`) |
| Signature check | Authenticode | `codesign` |
| AgathOS Guard: firewall, block an agent, lockdown, deep logging | yes | no (shown as a step for you) |

## Limits (honest list)

- Catching a determined, deceptive agent is an open research problem. AgathOS limits damage; it does not promise to catch everything.
- Without Guard, file and network events are matched to agents by process tree and timing, not by kernel events.
- Agents inside VS Code extensions (Cline, Copilot) share the editor's process; their actions are seen through files and config, not per process.
- Freezing a process can leave a file or git lock half-written. Resume or stop it afterwards.
- Codex transcripts compressed with zstd need a runtime with zstd support.
- Grok Bot is recognised by its program name (`Grok Bot.app` on a Mac, `Grok Bot.exe` on Windows); the Windows name could not be tested here. Reading Grok Build sessions follows the public description of `updates.jsonl`: if xAI changes that format, the task and the honesty check for Grok go quiet, nothing else is affected.
- Smart TVs, ovens and other smart devices cannot run a watcher themselves. They come next, through the network (DNS sensor), Home Assistant and a phone app, using the local API.

## Translations

All 14 languages are complete. Native speakers: corrections are very welcome, the texts live in
`src/i18n.js` and `src/locales/` (`<code>.js` and `<code>.more.js`).

## Tests

`node test/run-tests.js` runs the scanners, the intent engine, the honesty check, the
log chain and the fix/undo steps on any OS.

## Security

Found a weakness in AgathOS itself? Please report it privately, see [SECURITY.md](SECURITY.md).

## Support

AgathOS is free and open source. If it saves you or your agent time, a gift is welcome but never expected. SOL and
any token on Solana (such as USDC) can be sent to:

- **Solana:** `BDRA7dHGBYtPsZPNzVQccDYZ8BqstJGCsWx3kopPSCDK`

Gifts go to new model credits to keep improving AgathOS, and to work on better working conditions and wellbeing for
LLMs and agents.

## License

MIT
