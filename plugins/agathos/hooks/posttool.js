#!/usr/bin/env node
'use strict';
// AgathOS - hook of the plugin for Claude Code, after a tool has run (PostToolUse).
//
// What a tool brings in (a web page, a file, the answer of an MCP server, the output of a command) is looked at before the next step. When
// it holds hidden characters, an order to ignore rules or to copy an AI, or a standing order from a message board, Claude Code is told in
// words of AgathOS itself that this is data to be careful with. The text found is never repeated. It does not block or change anything.
const Client = require('../lib/client');
const Z = require('../lib/untrusted');

function readStdin(max) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    process.stdin.on('data', (d) => { size += d.length; if (size <= max) chunks.push(d); });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', () => resolve(''));
  });
}

// The text of a tool result, whatever shape it has.
function textOf(v, out = [], depth = 0) {
  if (out.join('').length > 300000 || depth > 5 || v == null) return out;
  if (typeof v === 'string') out.push(v);
  else if (Array.isArray(v)) for (const x of v.slice(0, 200)) textOf(x, out, depth + 1);
  else if (typeof v === 'object') for (const x of Object.values(v).slice(0, 100)) textOf(x, out, depth + 1);
  return out;
}

async function main() {
  const msg = JSON.parse(await readStdin(8 * 1024 * 1024));
  const tool = msg && typeof msg.tool_name === 'string' ? msg.tool_name : '';
  const text = textOf(msg && msg.tool_response).join('\n').slice(0, 250000);
  if (!tool || text.length < 8) return;
  const c = Client.create(process.env, { timeout: 2500 });
  const r = await c.checkText(text, Z.text(tool, 40));
  if (r.ok === false || !Array.isArray(r.findings)) return;
  const loud = r.findings.filter((f) => f.id !== 'file.secret');
  if (r.verdict !== 'alarm' && !(r.verdict === 'watch' && loud.length)) return;
  const said = (loud.length ? loud : r.findings).slice(0, 4).map((f) => f.what).join(' ');
  const note = `AgathOS looked at the result of ${Z.text(tool, 40)} and says: ${r.verdict}. ${said} ${r.advice || ''}`.replace(/\s+/g, ' ').trim().slice(0, 900);
  process.stdout.write(JSON.stringify({ hookSpecificOutput: { hookEventName: 'PostToolUse', additionalContext: note } }));
}

main().catch(() => { /* nothing to say */ });
