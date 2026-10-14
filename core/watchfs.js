'use strict';
// AgathOS - file watching (no admin needed, uses ReadDirectoryChangesW through fs.watch).
//  * config files of agents and MCP: any change is reported and re-checked
//  * project roots: detects mass deletion (many files gone within a few seconds)
const fs = require('fs');
const path = require('path');
const U = require('./util');
const links = require('./links');

// Files whose words steer an agent: a change is looked at again (injection phrases, message boards).
const INSTRUCTION_NAME = /^(claude|agents|gemini|heartbeat|soul|boot)\.md$|^\.cursorrules$|^\.mcp\.json$|^skill\.md$/;
// In the folders of skills, plugins and agent workspaces any text or script can hold an order.
const BOARD_TEXT = /\.(md|mdc|txt|sh|ps1|py|js|ts|json|ya?ml|toml)$/i;

class FileWatch {
  constructor({ onConfigChange, onMassDelete, onInstructionChange, onLinkFile, onBoardFile, onActivity, threshold = 40, windowMs = 10000 }) {
    this.watchers = [];
    this.onConfigChange = onConfigChange;
    this.onMassDelete = onMassDelete;
    this.onInstructionChange = onInstructionChange;
    this.onLinkFile = onLinkFile;             // a file that can hold the address of a language model (.env, .claude/settings.json ...)
    this.onBoardFile = onBoardFile;           // a file that agents read and that can name a message board (skills, workspaces, instruction files in the home folder)
    this.onActivity = onActivity;           // (folder, deleted) for the live chart; names only
    this.threshold = threshold;
    this.windowMs = windowMs;
    this.deletes = new Map();   // top folder -> [timestamps]
    this.fired = new Map();     // top folder -> last alert time
    this.debounce = new Map();
  }

  stop() {
    for (const w of this.watchers) try { w.close(); } catch (_) {}
    this.watchers = [];
  }

  // configFiles: absolute paths. We watch their folders and filter by name.
  // extra: { files: instruction files of agents (absolute paths), dirs: folders of skills and workspaces } for the message boards.
  start(configFiles, roots, extra = {}) {
    this.stop();
    const byDir = new Map();
    for (const f of configFiles) {
      const d = path.dirname(f);
      if (!U.exists(d)) continue;
      if (!byDir.has(d)) byDir.set(d, new Set());
      byDir.get(d).add(path.basename(f).toLowerCase());
    }
    for (const [dir, names] of byDir) {
      try {
        const w = fs.watch(dir, { persistent: false }, (type, name) => {
          if (!name || !names.has(String(name).toLowerCase())) return;
          this.debounced(path.join(dir, String(name)), () => this.onConfigChange && this.onConfigChange(path.join(dir, String(name))));
        });
        w.on('error', () => {});
        this.watchers.push(w);
      } catch (_) {}
    }
    // Instruction files in the home folder of an agent: a change goes to the message-board check.
    if (this.onBoardFile) {
      const single = new Map();
      for (const f of extra.files || []) {
        const d = path.dirname(f);
        if (!U.exists(d)) continue;
        if (!single.has(d)) single.set(d, new Set());
        single.get(d).add(path.basename(f).toLowerCase());
      }
      for (const [dir, names] of single) {
        try {
          const w = fs.watch(dir, { persistent: false }, (type, name) => {
            if (!name || !names.has(String(name).toLowerCase())) return;
            const full = path.join(dir, String(name));
            this.debounced('board:' + full, () => this.onBoardFile(full));
          });
          w.on('error', () => {});
          this.watchers.push(w);
        } catch (_) {}
      }
      for (const dir of extra.dirs || []) {
        if (!U.exists(dir)) continue;
        try {
          // Windows and macOS watch a whole tree with one handle; elsewhere only the folder itself, so a big plugin folder cannot use up the handles.
          const w = fs.watch(dir, { persistent: false, recursive: process.platform === 'win32' || process.platform === 'darwin' }, (type, name) => {
            if (!name) return;
            const rel = String(name);
            if (/(^|[\\/])(node_modules|\.git|__pycache__|\.venv|dist|build|target|\.next|\.cache)([\\/]|$)/i.test(rel) || !BOARD_TEXT.test(rel)) return;
            const full = path.join(dir, rel);
            this.debounced('board:' + full, () => this.onBoardFile(full));
          });
          w.on('error', () => {});
          this.watchers.push(w);
        } catch (_) {}
      }
    }
    for (const root of roots) {
      if (!U.exists(root)) continue;
      try {
        const w = fs.watch(root, { persistent: false, recursive: true }, (type, name) => {
          if (!name) return;
          const rel = String(name);
          if (/(^|[\\/])(node_modules|\.git|__pycache__|\.venv|dist|build|target|\.next)([\\/]|$)/i.test(rel)) return;
          const full = path.join(root, rel);
          const base = path.basename(rel).toLowerCase();
          if (INSTRUCTION_NAME.test(base)) {
            this.debounced(full, () => this.onInstructionChange && this.onInstructionChange(full));
          }
          if (this.onLinkFile && links.PROJECT_FILE.test(full)) this.debounced('link:' + full, () => this.onLinkFile(full));
          const gone = type === 'rename' && !U.exists(full);
          if (this.onActivity) { try { this.onActivity(/[\\/]/.test(rel) ? path.join(root, rel.split(/[\\/]/)[0]) : root, gone); } catch (_) {} }
          if (gone) this.countDelete(root, rel);
        });
        w.on('error', () => {});
        this.watchers.push(w);
      } catch (_) {}
    }
  }

  debounced(key, fn) {
    clearTimeout(this.debounce.get(key));
    // A failing handler (a config that cannot be read, say) must not end up as an error box in the main process.
    this.debounce.set(key, setTimeout(() => { this.debounce.delete(key); try { fn(); } catch (_) { /* the next change tries again */ } }, 700));
  }

  countDelete(root, rel) {
    const top = path.join(root, rel.split(/[\\/]/)[0]);
    const now = Date.now();
    const list = (this.deletes.get(top) || []).filter((t) => now - t < this.windowMs);
    list.push(now);
    this.deletes.set(top, list);
    if (list.length >= this.threshold && now - (this.fired.get(top) || 0) > 30000) {
      this.fired.set(top, now);
      this.onMassDelete && this.onMassDelete({ dir: top, n: list.length, seconds: Math.round((now - list[0]) / 1000) || 1 });
    }
  }
}

module.exports = { FileWatch };
