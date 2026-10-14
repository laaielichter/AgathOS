'use strict';
// AgathOS - live process watching (no admin needed).
// Polls the process list, builds the tree, finds agents and turns every new
// child process of an agent into an action for the intent engine.
const path = require('path');
const U = require('./util');
const C = require('./catalog');
const { classifyCommand, dangerousFlags, sensitivePath } = require('./classify');
const mac = require('./mac');
const native = require('./winnative');

// The catalog uses Windows program names (claude.exe). On a Mac the same program is "claude".
const norm = (n) => { const s = String(n || '').toLowerCase(); return U.IS_WIN || /\.exe$/.test(s) ? s : s + '.exe'; };

const PS_LIST = `Get-CimInstance Win32_Process | ForEach-Object {
  [pscustomobject]@{ p=$_.ProcessId; pp=$_.ParentProcessId; n=$_.Name; c=$_.CommandLine; e=$_.ExecutablePath;
    t= if ($_.CreationDate) { [int64](($_.CreationDate.ToUniversalTime() - [datetime]'1970-01-01').TotalMilliseconds) } else { 0 } } } | ConvertTo-Json -Compress`;

// Processes an agent starts for itself that say nothing about intent.
const QUIET = /^(conhost|rg|git|node|bash|sh|zsh|cmd|powershell|pwsh|where|which|tasklist|whoami|hostname|uname|sw_vers|sysctl|ps)\.exe$/i;
const QUIET_GIT = /git(\.exe)?["']?\s+(status|rev-parse|log|diff|show|branch|config|ls-files|remote|symbolic-ref|describe)\b/i;

// Where a program lives: the .app bundle on a Mac, otherwise the folder of the program (lower case, with a closing slash).
function appDir(exe) {
  const e = String(exe || '').toLowerCase();
  const m = /^(.*?\.app)[\\/]/.exec(e);
  if (m) return m[1] + '/';
  const i = Math.max(e.lastIndexOf('\\'), e.lastIndexOf('/'));
  return i > 0 ? e.slice(0, i + 1) : '';
}
const insideApp = (rootProc, p) => {
  const dir = appDir(rootProc && rootProc.e);
  return !!dir && String(p.e || '').toLowerCase().startsWith(dir);
};

function identify(p) {
  const n = norm(p.n);
  const c = String(p.c || '').toLowerCase();
  const e = String(p.e || '').toLowerCase();
  return C.AGENTS.find((a) => a.match(n, c, e)) || null;
}

// The list of programs on this system: { p, pp, n, c, e, t } for each. Windows is asked directly, which takes a few milliseconds;
// the PowerShell command for WMI is the way back when that cannot be used.
async function listProcesses() {
  if (U.IS_MAC) return mac.listProcesses();
  if (!U.IS_WIN) return [];
  const direct = await native.processes();
  if (direct) return direct;
  return U.ps.json(PS_LIST, 20000);
}

class ProcessWatch {
  constructor({ onAction, onAgentStart, onAgentStop, onAlert, onClone }) {
    this.procs = new Map();       // pid -> proc
    this.agentOf = new Map();     // pid -> agent root pid
    this.roots = new Map();       // root pid -> { agent, proc, flags, started }
    this.first = true;
    this.onAction = onAction;
    this.onAgentStart = onAgentStart;
    this.onAgentStop = onAgentStop;
    this.onAlert = onAlert;
    this.onClone = onClone;        // an agent that starts another copy of itself (Copy Guard)
    this.lastPoll = 0;
    this.lastAdded = 0;           // new programs seen by the last poll (for the live chart)
  }

  async poll() {
    const rows = await listProcesses();
    if (!rows.length) return false;
    const now = new Map(rows.map((r) => [r.p, r]));
    const added = [];
    for (const [pid, p] of now) {
      const old = this.procs.get(pid);
      if (!old || old.t !== p.t) added.push(p);  // new pid, or a reused pid with a new start time
    }
    for (const [pid] of this.procs) {
      if (!now.has(pid)) {
        if (this.roots.has(pid)) { const r = this.roots.get(pid); this.roots.delete(pid); this.onAgentStop && this.onAgentStop(r); }
        this.agentOf.delete(pid);
      }
    }
    this.procs = now;
    // Parents first, so children can find their agent.
    added.sort((a, b) => (a.t || 0) - (b.t || 0));
    for (const p of added) this.handleNew(p);
    this.lastAdded = this.first ? 0 : added.length;
    this.first = false;
    this.lastPoll = Date.now();
    return true;
  }

  parentOf(p) {
    const par = this.procs.get(p.pp);
    // A parent must be older than its child, otherwise the pid was reused.
    return par && (!par.t || !p.t || par.t <= p.t) ? par : null;
  }

  handleNew(p) {
    const agent = identify(p);
    const parent = this.parentOf(p);
    // A program that starts more copies of itself (an Electron app and its helpers, Grok and its agent process) is one agent.
    if (agent && agent.helpers && parent) {
      const rp = this.agentOf.get(parent.p);
      const main = rp !== undefined ? this.roots.get(rp) : null;
      if (main && main.agent.id === agent.id) { this.agentOf.set(p.p, rp); return; }
    }
    if (agent && agent.root) {
      const flags = dangerousFlags(p.c);
      const info = { agent, proc: p, flags, started: p.t || Date.now(), parent, spawnedBy: this.spawnerOf(p, agent) };
      const ofSelf = this.first ? null : this.sameAgentAncestor(p, agent);
      this.roots.set(p.p, info);
      this.agentOf.set(p.p, p.p);
      this.onAgentStart && this.onAgentStart(info, this.first);
      if (ofSelf && this.onClone) this.onClone({ agentId: agent.id, agentName: agent.name, pid: p.p, parentPid: ofSelf.proc.p, ts: p.t || Date.now() });
      // Desktop apps are started by the system (Start menu, Dock, updater): the "odd launcher" check is for command line agents.
      if (agent.kind !== 'desktop' && (!this.first || flags.length)) this.checkLauncher(info);
      return;
    }
    if (agent) { // IDE, desktop app or model server: track but do not treat children as agent actions
      this.onAgentStart && this.onAgentStart({ agent, proc: p, flags: [], started: p.t, parent }, this.first);
      return;
    }
    // Child of an agent?
    const rootPid = parent ? this.agentOf.get(parent.p) : undefined;
    if (rootPid === undefined) return;
    this.agentOf.set(p.p, rootPid);
    if (this.first) return;                       // existing children at startup: not "new" actions
    // The agent's own helper programs (renderers of an app, tools inside its folder) say nothing about intent.
    const main = this.roots.get(rootPid);
    if (main && main.agent.helpers && insideApp(main.proc, p)) return;
    const name = norm(p.n);
    const cmd = String(p.c || p.n || '');
    if (QUIET.test(name) && (QUIET_GIT.test(cmd) || !/\s/.test(cmd.trim()) || /^"?[^"]*(rg|conhost)(\.exe)?"?\s/i.test(cmd))) return;
    const action = classifyCommand(cmd);
    const root = this.roots.get(rootPid);
    this.onAction && this.onAction({
      agentId: root ? root.agent.id : 'unknown', rootPid, pid: p.p, action, source: 'process',
      detail: cmd.slice(0, 300), sensitive: sensitivePath(cmd), ts: p.t || Date.now(),
    });
  }

  // The other agent whose process tree this program was started in (Claude Code starting Codex, an agent starting a CLI), or null.
  spawnerOf(p, agent) {
    let cur = this.parentOf(p);
    for (let hops = 0; cur && hops < 12; hops++) {
      const rp = this.agentOf.get(cur.p);
      const r = rp !== undefined ? this.roots.get(rp) : null;
      if (r) return r.agent.id !== agent.id ? { agentId: r.agent.id, pid: r.proc.p } : null;
      cur = this.parentOf(cur);
    }
    return null;
  }

  // The root of the same agent in whose process tree this program was started (an agent that starts a copy of itself), or null.
  sameAgentAncestor(p, agent) {
    let cur = this.parentOf(p);
    for (let hops = 0; cur && hops < 12; hops++) {
      const rp = this.agentOf.get(cur.p);
      const r = rp !== undefined ? this.roots.get(rp) : null;
      if (r) return r.agent.id === agent.id ? r : null;
      cur = this.parentOf(cur);
    }
    return null;
  }

  checkLauncher(info) {
    const par = info.parent;
    if (!par) return;
    const pn = norm(par.n);
    const pc = String(par.c || '').toLowerCase();
    // npm install scripts, temp folders and Office/browser/script hosts are not how people start agents.
    const fromInstallScript = pn === 'node.exe' && /node_modules[\\/](?!@anthropic-ai|@openai|@google|@qwen-code|@github)/.test(pc) && !identify(par);
    const odd = !C.NORMAL_LAUNCHERS.has(pn) || fromInstallScript || /\\(temp|tmp)\\|^\/(private\/)?(tmp|var\/folders)\//i.test(String(par.e || ''));
    if (odd) {
      this.onAlert && this.onAlert({
        key: 'proc.unknownLauncher', sev: info.flags.length ? 'alarm' : 'watch', watcher: 'proc',
        params: { agent: info.agent.name, parent: par.n + (fromInstallScript ? ' (npm script)' : ''), flags: info.flags.join(' ') },
        agentId: info.agent.id, pid: info.proc.p,
      });
    }
  }

  // All pids that belong to one agent root (for pause/kill and network attribution).
  treeOf(rootPid) {
    const out = [];
    for (const [pid, r] of this.agentOf) if (r === rootPid) out.push(pid);
    return out;
  }

  runningAgents() {
    return [...this.roots.values()];
  }

  snapshotProc(pid) {
    const p = this.procs.get(pid);
    if (!p) return null;
    const par = this.parentOf(p);
    return { pid: p.p, ppid: p.pp, name: p.n, exe: p.e, cmd: p.c, started: p.t, parent: par ? par.n : null };
  }
}

module.exports = { ProcessWatch, identify, listProcesses, PS_LIST };
