#!/usr/bin/env node
'use strict';
// AgathOS - hook of the plugin for Claude Code, before a tool runs (PreToolUse).
//
// It asks AgathOS "may I do this step?" and passes on only a "no" or an "ask first": Claude Code then refuses the step or asks the
// person. It never says "allow": a step that AgathOS finds fine goes through the permission rules of the person as if this hook were
// not there, so the hook can make nothing easier. When AgathOS cannot be reached the checks of this plugin alone are used; when those
// fail as well, the hook says nothing and the step goes on.
const Client = require('../lib/client');

function readStdin(max) {
  return new Promise((resolve) => {
    const chunks = [];
    let size = 0;
    process.stdin.on('data', (d) => { size += d.length; if (size <= max) chunks.push(d); });
    process.stdin.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    process.stdin.on('error', () => resolve(''));
  });
}

async function main() {
  const msg = JSON.parse(await readStdin(2 * 1024 * 1024));
  const tool = msg && typeof msg.tool_name === 'string' ? msg.tool_name : '';
  if (!tool) return;
  const c = Client.create(process.env, { timeout: 2500 });
  const r = await c.checkAction(tool, msg.tool_input && typeof msg.tool_input === 'object' ? msg.tool_input : {}, typeof msg.cwd === 'string' ? msg.cwd : undefined, 'claude-code');
  if (r.decision !== 'ask' && r.decision !== 'deny') return;
  process.stdout.write(JSON.stringify({
    hookSpecificOutput: { hookEventName: 'PreToolUse', permissionDecision: r.decision, permissionDecisionReason: String(r.reason || 'AgathOS asks you first.').slice(0, 300) },
  }));
}

main().catch(() => { /* when in doubt the step goes on: the hook must never get in the way of the work */ });
