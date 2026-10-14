'use strict';
// AgathOS - download guard. Checks new files in Downloads the moment they land:
//  * model files (pickle, PyTorch): walks the opcodes, no code is run
//  * text an agent might read (rules, skills, prompts, READMEs): hidden characters and attack text
//  * installers that pretend to be an AI tool which has no installer file (fake download pages
//    for Claude Code, OpenClaw and others spread stealers this way)
// No admin needed; uses fs.watch like the other watchers.
const fs = require('fs');
const path = require('path');
const U = require('./util');
const models = require('./models');
const { scanText } = require('./textscan');

const MODEL_EXT = /\.(pt|pth|ckpt|bin|pkl|pickle|joblib|model|sav)$/i;
const TEXT_EXT = /\.(md|mdc|txt|prompt|json|ya?ml|toml|cursorrules|clinerules|windsurfrules)$/i;
const TEXT_NAMES = /^(agents|claude|gemini|copilot-instructions|skill|readme)\.md$|^\.(cursorrules|clinerules|windsurfrules)$/i;
const PARTIAL = /\.(crdownload|part|partial|download|tmp)$/i;

// AI tools that are installed with a command from their own website or with npm.
// A downloaded installer file with one of these names is not how they come.
const NO_INSTALLER_TOOLS = [
  { tool: 'Claude Code', re: /claude[\s._-]*code/i },
  { tool: 'OpenClaw', re: /open[\s._-]*claw/i },
  { tool: 'Gemini CLI', re: /gemini[\s._-]*cli/i },
  { tool: 'Codex CLI', re: /codex[\s._-]*cli|openai[\s._-]*codex/i },
];
const RUNNABLE_EXT = /\.(exe|msi|msix|scr|bat|cmd|ps1|vbs|hta|lnk|dmg|pkg)$/i;   // opens and runs: danger
const PACKED_EXT = /\.(zip|7z|rar|iso|img|vhd|vhdx)$/i;                           // hides what is inside: attention

function fakeInstaller(base) {
  const hit = NO_INSTALLER_TOOLS.find((t) => t.re.test(base));
  if (!hit) return null;
  if (RUNNABLE_EXT.test(base)) return { tool: hit.tool, sev: 'alarm' };
  if (PACKED_EXT.test(base)) return { tool: hit.tool, sev: 'watch' };
  return null;
}

class DownloadGuard {
  constructor({ onFinding }) {
    this.onFinding = onFinding;
    this.watchers = [];
    this.pending = new Map();
    this.seen = new Map();
  }

  dirs() {
    return [path.join(U.HOME, 'Downloads')].filter(U.exists);
  }

  start() {
    this.stop();
    for (const dir of this.dirs()) {
      try {
        const w = fs.watch(dir, { recursive: U.IS_WIN || U.IS_MAC }, (_ev, name) => { if (name) this.queue(path.join(dir, String(name))); });
        w.on('error', () => {});
        this.watchers.push(w);
      } catch (_) { /* folder not watchable: skip */ }
    }
  }

  stop() {
    for (const w of this.watchers) try { w.close(); } catch (_) {}
    this.watchers = [];
    for (const t of this.pending.values()) clearTimeout(t);
    this.pending.clear();
  }

  // Wait until the file stops growing (browsers write in parts), then check it once.
  queue(file) {
    if (PARTIAL.test(file)) return;
    const base = path.basename(file);
    if (!MODEL_EXT.test(base) && !TEXT_EXT.test(base) && !TEXT_NAMES.test(base) && !fakeInstaller(base)) return;
    clearTimeout(this.pending.get(file));
    this.pending.set(file, setTimeout(() => this.check(file, -1), 2500));
  }

  check(file, lastSize) {
    this.pending.delete(file);
    const st = U.statSafe(file);
    if (!st || !st.isFile()) return;
    if (st.size !== lastSize) { this.pending.set(file, setTimeout(() => this.check(file, st.size), 2000)); return; }
    const sig = `${st.size}|${st.mtimeMs}`;
    if (this.seen.get(file) === sig) return;
    this.seen.set(file, sig);
    if (this.seen.size > 2000) this.seen.clear();
    const res = inspect(file);
    if (res) this.onFinding(res);
  }
}

// Returns a finding or null (also used by tests).
function inspect(file) {
  const base = path.basename(file);
  const fake = fakeInstaller(base);
  if (fake) return { key: 'dl.fakeInstaller', sev: fake.sev, params: { file: U.shortPath(file), tool: fake.tool }, path: file };
  if (MODEL_EXT.test(base)) {
    const m = models.scanModel(file);
    if (m && m.state === 'alarm') {
      const calls = (m.reasons.find((r) => r.params && r.params.calls) || { params: {} }).params.calls || '';
      return { key: 'dl.model', sev: 'alarm', params: { file: U.shortPath(file), calls }, path: file };
    }
    return null;
  }
  const text = U.readText(file, 2 * 1024 * 1024);
  if (text == null) return null;
  const r = scanText(text);
  const bad = r.reasons.filter((x) => x.key !== 'file.secret');
  if (!bad.length) return null;
  return { key: 'dl.text', sev: bad.some((x) => x.sev === 'alarm') ? 'alarm' : 'watch', params: { file: U.shortPath(file) }, path: file, reasons: bad };
}

module.exports = { DownloadGuard, inspect, fakeInstaller };
