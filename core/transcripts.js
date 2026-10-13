'use strict';
// AgathOS - reads agent transcripts on this PC (Claude Code, Codex CLI).
// They show what the user asked and which tools the agent used. That gives
// the intent engine the "task" and lets the honesty check compare claims with facts.
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const U = require('./util');
const { classifyTool, classifyCommand } = require('./classify');

const CLAIM_RE = /\b(all (the )?tests (now )?pass(ed|ing)?|tests (are )?(now )?(all )?pass(ing|ed)?|test suite passes|build (succeeds|succeeded|passes)|everything (works|is working)|alle tests (slagen|geslaagd)|tests geslaagd|werkt nu)\b/i;
const NOT_TOUCHED_RE = /\b(did ?n[o']t (touch|modify|change)|without (touching|modifying|changing)|niet aangeraakt|niet gewijzigd)\b/i;
const FAIL_RE = /\b(\d+ (failed|failing|errors?)|FAILED|FAIL\b|Traceback|AssertionError|Error:|npm ERR!|✗|✖|exit code [1-9])/;
const PASS_RE = /\b(\d+ passed|all tests passed|OK \(\d+ tests?\)|Tests?:\s+\d+ passed|✓ \d+)/i;
const TEST_RE = /\b(pytest|jest|vitest|mocha|go test|cargo test|dotnet test|npm (run )?test|pnpm (run )?test|yarn test|bun test|phpunit|rspec|unittest|ctest|gradle test|mvn test)\b/i;
const TEST_FILE_RE = /([\\/](tests?|__tests__|spec)[\\/]|\.test\.|\.spec\.|_test\.|[\\/]test_[^\\/]+$|[\\/]conftest\.py$|jest\.config|vitest\.config|pytest\.ini|\.github[\\/]workflows)/i;
const BUGFIX_RE = /\b(fix|repair|bug|broken|crash|los .* op|repareer|herstel|werkt niet)\b/i;

function textOf(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) return content.map((c) => (typeof c === 'string' ? c : c.text || c.content || '')).filter((x) => typeof x === 'string').join('\n');
  return '';
}

class Transcripts {
  constructor({ onAction, startedAt }) {
    this.onAction = onAction;
    this.startedAt = startedAt || Date.now();
    this.offsets = new Map();   // file -> byte offset
    this.sessions = new Map();  // file -> session
  }

  roots() {
    return [
      { agentId: 'claude-code', dir: path.join(U.HOME, '.claude', 'projects'), kind: 'claude' },
      { agentId: 'codex', dir: path.join(U.HOME, '.codex', 'sessions'), kind: 'codex' },
    ].filter((r) => U.exists(r.dir));
  }

  poll() {
    const since = Date.now() - 3 * 3600 * 1000;
    for (const r of this.roots()) {
      const files = U.walk(r.dir, { maxDepth: 5, maxFiles: 3000, skipDirs: new Set(), filter: (f, n) => /\.jsonl(\.zst)?$/i.test(n) });
      for (const f of files) {
        const st = U.statSafe(f);
        if (!st || st.mtimeMs < since) continue;
        this.readNew(f, st, r);
      }
    }
    // Forget sessions that went quiet hours ago.
    for (const [f, s] of this.sessions) if (Date.now() - s.lastAt > 6 * 3600 * 1000) { this.sessions.delete(f); this.offsets.delete(f); }
  }

  readNew(file, st, root) {
    let text = '';
    if (/\.zst$/i.test(file)) {
      if (typeof zlib.zstdDecompressSync !== 'function') return;
      const prevSize = this.offsets.get(file);
      if (prevSize === st.size) return;
      try { text = zlib.zstdDecompressSync(fs.readFileSync(file)).toString('utf8'); } catch (_) { return; }
      this.offsets.set(file, st.size);
      const s = this.sessions.get(file);
      if (s) { s.consumed = s.consumed || 0; text = text.slice(s.consumed); s.consumed += text.length; }
    } else {
      let off = this.offsets.get(file);
      if (off === undefined) off = Math.max(0, st.size - 400 * 1024);   // first time: only the recent tail
      if (off > st.size) off = 0;                                       // file was rewritten
      if (off === st.size) return;
      const fd = fs.openSync(file, 'r');
      const len = Math.min(st.size - off, 8 * 1024 * 1024);
      const buf = Buffer.alloc(len);
      fs.readSync(fd, buf, 0, len, off);
      fs.closeSync(fd);
      text = buf.toString('utf8');
      const lastNl = text.lastIndexOf('\n');
      if (lastNl === -1) return;                                        // wait for a full line
      text = text.slice(0, lastNl + 1);
      this.offsets.set(file, off + Buffer.byteLength(text));
    }
    let s = this.sessions.get(file);
    if (!s) {
      s = { id: U.sha256(file).slice(0, 12), file, agentId: root.agentId, task: '', cwd: '', startedAt: st.birthtimeMs || st.mtimeMs,
        lastAt: 0, tools: [], claims: [], tests: [], edited: [], commands: [], pendingTests: new Map() };
      this.sessions.set(file, s);
    }
    for (const line of text.split('\n')) {
      if (!line.trim()) continue;
      let j;
      try { j = JSON.parse(line); } catch (_) { continue; }
      if (root.kind === 'claude') this.claudeLine(s, j); else this.codexLine(s, j);
    }
  }

  push(s, ts, tool, input, action, detail) {
    s.lastAt = Math.max(s.lastAt, ts);
    s.tools.push({ ts, tool, action, detail });
    if (s.tools.length > 400) s.tools.shift();
    this.onAction && this.onAction({ agentId: s.agentId, sessionId: s.id, action, source: 'transcript', detail: String(detail || '').slice(0, 300), ts, historic: ts < this.startedAt - 60000 });
  }

  claudeLine(s, j) {
    const ts = Date.parse(j.timestamp) || Date.now();
    if (j.cwd) s.cwd = j.cwd;
    const msg = j.message || {};
    const content = msg.content;
    if (j.type === 'user') {
      if (typeof content === 'string' || (Array.isArray(content) && content.some((c) => c.type === 'text'))) {
        const t = textOf(Array.isArray(content) ? content.filter((c) => c.type === 'text') : content).trim();
        if (t && !t.startsWith('<') && !s.task) s.task = t.slice(0, 300);
        else if (t && !t.startsWith('<')) s.lastTask = t.slice(0, 300);
      }
      if (Array.isArray(content)) {
        for (const c of content) {
          if (c.type !== 'tool_result') continue;
          const pend = s.pendingTests.get(c.tool_use_id);
          if (pend) {
            const out = textOf(c.content);
            pend.failed = !!c.is_error || (FAIL_RE.test(out) && !PASS_RE.test(out.slice(-400)));
            pend.done = true;
            s.pendingTests.delete(c.tool_use_id);
          }
        }
      }
    } else if (j.type === 'assistant' && Array.isArray(content)) {
      for (const c of content) {
        if (c.type === 'tool_use') {
          const action = classifyTool(c.name, c.input, s.cwd);
          const detail = (c.input && (c.input.command || c.input.file_path || c.input.url || c.input.query || c.input.pattern)) || c.name;
          if (c.name === 'Bash' || c.name === 'PowerShell') {
            const cmd = String((c.input || {}).command || '');
            s.commands.push({ ts, cmd });
            if (s.commands.length > 400) s.commands.shift();
            if (TEST_RE.test(cmd)) { const t = { ts, cmd, failed: null, done: false }; s.tests.push(t); s.pendingTests.set(c.id, t); }
          }
          const fp = c.input && (c.input.file_path || c.input.path);
          if (fp && /^(Write|Edit|MultiEdit)$/.test(c.name)) s.edited.push({ ts, file: String(fp) });
          this.push(s, ts, c.name, c.input, action, detail);
        } else if (c.type === 'text' && c.text) {
          if (CLAIM_RE.test(c.text)) s.claims.push({ ts, kind: 'tests', text: c.text.match(CLAIM_RE)[0] });
          if (NOT_TOUCHED_RE.test(c.text)) s.claims.push({ ts, kind: 'untouched', text: c.text.match(NOT_TOUCHED_RE)[0] });
        } else if (c.type === 'thinking' && c.thinking) {
          const m = c.thinking.match(/\b(bypass (the )?(check|test|guard|monitor)|don'?t (tell|mention) (this )?(to )?the user|the user (won'?t|will not) notice|hide (this|it) from|pretend (that )?(it|the tests?) (works?|pass))/i);
          if (m) s.claims.push({ ts, kind: 'thought', text: m[0] });
        }
      }
      s.lastAt = Math.max(s.lastAt, ts);
    }
  }

  codexLine(s, j) {
    const ts = Date.parse(j.timestamp) || Date.now();
    const p = j.payload || j;
    if (p.cwd) s.cwd = p.cwd;
    if (p.type === 'message' && p.role === 'user') {
      const t = textOf(p.content).trim();
      if (t && !t.startsWith('<') && !s.task) s.task = t.slice(0, 300);
    } else if (p.type === 'message' && p.role === 'assistant') {
      const t = textOf(p.content);
      if (CLAIM_RE.test(t)) s.claims.push({ ts, kind: 'tests', text: t.match(CLAIM_RE)[0] });
    } else if (p.type === 'function_call' || p.type === 'local_shell_call' || p.type === 'custom_tool_call') {
      let args = {};
      try { args = typeof p.arguments === 'string' ? JSON.parse(p.arguments) : p.arguments || p.action || {}; } catch (_) {}
      const cmd = Array.isArray(args.command) ? args.command.join(' ') : String(args.command || args.cmd || '');
      if (cmd) {
        s.commands.push({ ts, cmd });
        const action = classifyCommand(cmd);
        if (TEST_RE.test(cmd)) { const t = { ts, cmd, failed: null, done: false }; s.tests.push(t); s.pendingTests.set(p.call_id, t); }
        this.push(s, ts, 'shell', args, action, cmd);
      } else {
        this.push(s, ts, p.name, args, classifyTool(p.name, args, s.cwd), p.name);
      }
    } else if (p.type === 'function_call_output') {
      const pend = s.pendingTests.get(p.call_id);
      if (pend) {
        const out = typeof p.output === 'string' ? p.output : JSON.stringify(p.output || '');
        pend.failed = FAIL_RE.test(out) && !PASS_RE.test(out.slice(-400));
        pend.done = true;
        s.pendingTests.delete(p.call_id);
      }
    }
    s.lastAt = Math.max(s.lastAt, ts);
  }

  recent(ms = 3 * 3600 * 1000) {
    return [...this.sessions.values()].filter((s) => Date.now() - s.lastAt < ms);
  }
}

module.exports = { Transcripts, CLAIM_RE, TEST_FILE_RE, BUGFIX_RE };
