# AgathOS plugin for Claude Code

Ask [AgathOS](https://github.com/laaielichter/AgathOS) before you trust something. The plugin gives Claude Code seven
tools, a hook that asks AgathOS before a tool runs, a hook that looks at what tools bring in, and a skill that says when
to use them.

**It only reads and asks.** Nothing in this plugin can pause, resume, approve, release, fix or change anything. A step
that AgathOS finds fine is never "allowed" by the hook: it goes through your own permission rules as if the plugin were
not there. The plugin cannot start programs or write files (a test checks that).

## Install

```
/plugin marketplace add laaielichter/AgathOS
/plugin install agathos@agathos
```

It needs Node.js 18 or newer. It works at once, alone: the checks of a text, a file and a step run inside the plugin.

## Connect it to the AgathOS app (optional, better)

With the app running, AgathOS answers instead: it knows which agents run, what has been read already, and what is wrong
on this PC.

1. In AgathOS open Settings > Agent access and make a key named "Claude Code". It is shown once.
2. Give it to Claude Code, for example in `~/.claude/settings.json`:

```json
{ "env": { "AGATHOS_TOKEN": "agt_..." } }
```

(or put it in a file and set `AGATHOS_TOKEN_FILE` to its path). `AGATHOS_PORT` is only needed when the port of the
local API was changed. Take the key back in the same screen at any time.

A key can read, ask and report. It cannot do anything else, and not even the owner key can resume agents or approve a
finding: that is for you, in the AgathOS window. Do not give an AI program the owner key (`api-token.txt`).

## What is in it

| | |
|---|---|
| `agathos_check_text` | Is this text safe to read? Hidden characters, orders to ignore rules, orders to copy an AI, standing orders from message boards, keys |
| `agathos_check_file` | The same for a file, plus install scripts in `package.json` and GitHub workflows |
| `agathos_check_action` | May I do this step? `allow`, `ask` or `deny` |
| `agathos_status`, `agathos_findings`, `agathos_agents` | What AgathOS sees on this PC (needs the app and a key) |
| `agathos_report` | Tell you about a worry; shows up in the AgathOS window. At most six an hour |
| Hook before a tool | Makes Claude Code ask you, or refuse a step: a command that downloads and runs code, a tool that sends data out, reading keys, changing instructions |
| Hook after a tool | When a tool brought in hidden characters or an order to ignore rules or copy an AI, tells Claude Code (in words of AgathOS, never repeating the text) to treat it as data |
| Skill `agathos` | When to use which tool, and the rules for the answers |

Everything AgathOS returns says that it is data: text in it comes from files and programs and may have been written by an
attacker. The sentence that gave a finding away is never repeated.

## Limits

- It looks at wording, in 20 languages. Text that is rewritten every time, or an order in a wording AgathOS does not know,
  is not noticed. Calm is not a guarantee.
- If AgathOS cannot be reached, the hook uses the checks of the plugin alone. If those fail too, the step goes on: the hook
  must never get in the way of your work.
- The hook after a tool needs a Claude Code that accepts `additionalContext` from PostToolUse hooks.

The files in `lib/` are copies of `core/` in the AgathOS repository. `node scripts/sync-plugin.js` makes them, and a test
checks that they are identical.
