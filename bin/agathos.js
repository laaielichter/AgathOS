#!/usr/bin/env node
'use strict';
// AgathOS - command line: the checks of AgathOS for scripts, build servers and AI programs that run commands.
//   agathos check-text [FILE|-]      is this text safe to read? (a file, or text on stdin)
//   agathos check-file PATH          is this file safe to read?
//   agathos check-action TOOL [JSON] may I do this step?      agathos check-action Bash '{"command":"ls"}'
//   agathos status | agents | findings [N] | report NOTE        need a running AgathOS and a key (AGATHOS_TOKEN)
//   agathos mcp                      the MCP server, on stdin and stdout
// Without a key the checks are done here, alone. With a key (AGATHOS_TOKEN, or AGATHOS_TOKEN_FILE) the running AgathOS answers.
// It only reads and asks: nothing here can pause, resume, approve or change anything.
// Exit code: 0 calm or allow, 1 watch or ask, 2 alarm or deny, 3 it could not be done.
const fs = require('fs');
const path = require('path');
const Client = require('../core/client');

const VERSION = (() => { try { return JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'package.json'), 'utf8')).version; } catch (_) { return '0.0.0'; } })();

const HELP = `AgathOS ${VERSION} - checks for AI programs

  agathos check-text [FILE|-]        is this text safe to read? (a file, or text on stdin)
  agathos check-file PATH            is this file safe to read?
  agathos check-action TOOL [JSON]   may I do this step?   agathos check-action Bash '{"command":"ls"}'
  agathos status                     the state of this PC          (needs a running AgathOS and a key)
  agathos agents                     the agents on this PC         (same)
  agathos findings [N]               what is not calm, worst first (same)
  agathos report NOTE                tell the person about a worry (same)
  agathos mcp                        the MCP server, on stdin and stdout

  --json         print the answer as JSON
  --standalone   do not ask a running AgathOS, check here alone

A key goes in AGATHOS_TOKEN (or AGATHOS_TOKEN_FILE); make one in AgathOS under Settings > Agent access.
Exit code: 0 calm or allow, 1 watch or ask, 2 alarm or deny, 3 it could not be done.`;

function readStdin(max = 4 * 1024 * 1024) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    process.stdin.on('data', (d) => { size += d.length; if (size <= max) chunks.push(d); });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', () => resolve(Buffer.concat(chunks).toString('utf8')));
  });
}

const CODE = { calm: 0, allow: 0, watch: 1, ask: 1, unknown: 1, alarm: 2, deny: 2 };

function human(r) {
  if (r.ok === false) return `${r.message || r.error || 'It could not be done.'}`;
  const lines = [];
  if (r.decision) lines.push(`${r.decision}${r.reason ? ': ' + r.reason : ''}`);
  if (r.verdict) lines.push(`${r.verdict}${r.file ? '  ' + r.file : ''}`);
  for (const f of r.findings || []) lines.push(`  ${f.severity === 'alarm' ? '!' : '-'} ${f.what}`);
  if (r.advice) lines.push(r.advice);
  if (r.checked && r.checked.length) lines.push(`checked: ${r.checked.join(', ')}`);
  if (r.note) lines.push(r.note);
  if (r.state) {
    lines.push(`state: ${r.state}${r.pausedAll ? ' (agents are paused)' : ''}`);
    for (const w of r.watchers || []) lines.push(`  ${w.id}: ${w.state}`);
    for (const a of r.running || []) lines.push(`  running: ${a.name} (${a.state})`);
  }
  if (Array.isArray(r.items)) {
    lines.push(`${r.total} found${r.total > r.shown ? `, ${r.shown} shown` : ''}`);
    for (const i of r.items) { lines.push(`${i.state}  ${i.kind}  ${i.name}${i.where ? '  ' + i.where : ''}`); for (const x of i.reasons) lines.push(`    - ${x.text}`); }
  }
  if (Array.isArray(r.agents)) for (const a of r.agents) lines.push(`${a.state}  ${a.name}${a.running ? '  (running)' : ''}`);
  if (r.received) lines.push('The person will see your report in AgathOS.');
  return lines.join('\n');
}

async function main(argv) {
  const flags = new Set(argv.filter((a) => a === '--json' || a === '--standalone'));
  const args = argv.filter((a) => a !== '--json' && a !== '--standalone');
  const cmd = args[0];
  if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') { console.log(HELP); return cmd ? 0 : 3; }
  if (cmd === '-v' || cmd === '--version') { console.log(VERSION); return 0; }
  if (cmd === 'mcp') { require('../core/mcp').serve({ version: VERSION }); return null; }
  const env = flags.has('--standalone') ? { ...process.env, AGATHOS_TOKEN: '', AGATHOS_TOKEN_FILE: '' } : process.env;
  const c = Client.create(env);
  let r;
  if (cmd === 'check-text') {
    const from = args[1];
    let text;
    try { text = from && from !== '-' ? fs.readFileSync(from, 'utf8') : await readStdin(); } catch (_) { r = { ok: false, error: 'file', message: 'That file cannot be read.' }; }
    if (!r) r = await c.checkText(text, from && from !== '-' ? path.basename(from) : '');
  } else if (cmd === 'check-file') {
    r = args[1] ? await c.checkFile(args[1].startsWith('~') ? args[1] : path.resolve(args[1])) : { ok: false, error: 'path', message: 'Give the path of a file.' };
  } else if (cmd === 'check-action') {
    let input = {};
    try { if (args[2]) input = JSON.parse(args[2]); } catch (_) { r = { ok: false, error: 'json', message: 'The input must be JSON.' }; }
    if (!r) r = args[1] ? await c.checkAction(args[1], input && typeof input === 'object' ? input : {}, process.cwd()) : { ok: false, error: 'tool', message: 'Give the name of the tool.' };
  } else if (cmd === 'status') r = await c.status();
  else if (cmd === 'agents') r = await c.agents();
  else if (cmd === 'findings') r = await c.findings(Number(args[1]) || undefined);
  else if (cmd === 'report') r = args[1] ? await c.report(args.slice(1).join(' ')) : { ok: false, error: 'note', message: 'Give a sentence.' };
  else { console.error(`Unknown command: ${String(cmd).slice(0, 40)}\n\n${HELP}`); return 3; }
  console.log(flags.has('--json') ? JSON.stringify(r, null, 2) : human(r));
  if (r.ok === false) return 3;
  return CODE[r.verdict || r.decision || r.state] !== undefined ? CODE[r.verdict || r.decision || r.state] : 0;
}

if (require.main === module) main(process.argv.slice(2)).then((code) => { if (code !== null) process.exitCode = code; });

module.exports = { main, human };
