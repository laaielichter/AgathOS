'use strict';
// AgathOS - the engine. Runs all scanners and watchers, feeds the intent engine,
// keeps the event log, and builds the snapshot the window shows.
const os = require('os');
const path = require('path');
const U = require('./util');
const C = require('./catalog');
const inv = require('./inventory');
const net = require('./network');
const models = require('./models');
const extensions = require('./extensions');
const backup = require('./backup');
const supply = require('./supply');
const pause = require('./pause');
const judge = require('./judge');
const guard = require('./guard');
const { ProcessWatch } = require('./processes');
const { FileWatch } = require('./watchfs');
const { Transcripts } = require('./transcripts');
const { IntentEngine, thresholds } = require('./intent');
const { classifyTool } = require('./classify');
const remedy = require('./remedy');
const { DownloadGuard } = require('./dlguard');
const { LanScanWatch } = require('./worm');

const WATCHERS = ['gate', 'files', 'net', 'keys', 'traps', 'proc'];
const RANK = { calm: 0, watch: 1, alarm: 2 };
const worst = (list) => list.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'calm');
// Domains that agents normally talk to themselves. A child process calling them is fine too.
const AI_API = new RegExp(`(^|\\.)(${[...C.AI_PROVIDER_HOSTS, 'claude.ai', 'chatgpt.com', 'google.com', 'gstatic.com', 'github.com', 'githubusercontent.com',
  'npmjs.org', 'npmjs.com', 'pypi.org', 'pythonhosted.org', 'microsoft.com', 'visualstudio.com', 'vscode-cdn.net', 'cursor.sh', 'cursor.com',
  'codeium.com', 'windsurf.com', 'sentry.io', 'statsig.com', 'segment.io', 'cloudfront.net', 'windows.net', 'akamaized.net', 'kiro.dev',
  'ampcode.com', 'sourcegraph.com', 'factory.ai', 'augmentcode.com', 'zed.dev', 'trae.ai', 'charm.sh']
  .map((h) => h.replace(/\./g, '\\.')).join('|')})$`, 'i');

class Engine {
  constructor(store, { appDir, onUpdate, notify }) {
    this.store = store;
    this.appDir = appDir;
    this.onUpdate = onUpdate || (() => {});
    this.notify = notify || (() => {});
    this.inventory = { agents: [], mcp: [], files: [], configs: [], models: [], ports: [], autostarts: [], extensions: [], backups: [], packages: [] };
    this.scanning = null;
    this.lastScan = store.state.lastScan || 0;
    this.paused = new Map();        // agentId -> { pids, at }
    this.pausedAll = false;
    this.domains = new Map();       // agentId -> Map(domain -> ts)
    this.remoteSeen = new Map();    // agentId -> Set(ip)
    this.pidDomains = new Map();    // pid -> [domain]
    this.deletes = new Map();       // agentId -> [ts]
    this.signatures = new Map();    // exe -> signature
    this.guardState = { installed: guard.installed(), running: false, sysmon: false, elevated: false, seq: 0 };
    this.timers = [];
    this.startedAt = Date.now();
    this.updateTimer = null;
    this.blocked = new Map();       // program path -> true (firewall rules we set)

    this.intent = new IntentEngine(store, { onAlert: (a) => this.event(a) });
    this.procs = new ProcessWatch({
      onAction: (a) => { this.intent.addAction(a); this.maybeJudge(a.agentId); this.changed(); },
      onAgentStart: (info, initial) => this.agentStarted(info, initial),
      onAgentStop: (info) => this.agentStopped(info),
      onAlert: (a) => { this.event(a); if (a.agentId) this.intent.addSignal(a.agentId, { key: a.key, params: a.params, sev: a.sev, points: a.sev === 'alarm' ? 45 : 25 }); },
    });
    this.transcripts = new Transcripts({
      startedAt: this.startedAt,
      onAction: (a) => { this.intent.addAction(a); if (!a.historic) this.maybeJudge(a.agentId); },
    });
    this.worm = new LanScanWatch({ onAlert: (a) => this.wormAlert(a) });
    this.downloads = new DownloadGuard({ onFinding: (f) => this.downloadFinding(f) });
    this.files = new FileWatch({
      threshold: store.settings.massDeleteThreshold,
      onConfigChange: (f) => this.configChanged(f),
      onInstructionChange: (f) => this.instructionChanged(f),
      onMassDelete: (d) => this.massDelete(d),
    });
  }

  // ---------- life cycle ----------
  async start() {
    if (U.IS_MAC) await require('./mac').fixPath();
    this.firstRunDefaults();
    U.ps.start();
    this.event({ key: 'app.started', sev: 'calm', watcher: 'proc', params: {} }, true);
    if (!this.store.chainOk) this.event({ key: 'log.tampered', sev: 'alarm', watcher: 'files', params: {} });
    await this.fullScan('start');
    this.applySchedule();
  }

  stop() {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    this.files.stop();
    this.downloads.stop();
    U.ps.stop();
  }

  firstRunDefaults() {
    const s = this.store.settings;
    if (!s.roots.length) {
      const cands = ['Desktop', 'Documents', 'source/repos', 'repos', 'projects', 'Projects', 'dev', 'Developer', 'code', 'workspace', 'git', 'GitHub', 'Downloads'];
      s.roots = [...new Set(cands.map((c) => path.join(U.HOME, ...c.split('/'))).filter(U.exists))];
    }
    if (!s.modelDirs.length) {
      const cands = ['.ollama/models', '.cache/huggingface/hub', '.lmstudio/models', '.cache/lm-studio/models', 'models', 'Downloads'];
      s.modelDirs = cands.map((c) => path.join(U.HOME, ...c.split('/'))).filter(U.exists);
    }
    this.store.saveState();
  }

  applySchedule() {
    for (const t of this.timers) clearInterval(t);
    this.timers = [];
    const s = this.store.settings;
    this.files.threshold = s.massDeleteThreshold;
    if (s.realtime) {
      const every = (ms, fn) => { const t = setInterval(() => fn().catch(() => {}), ms); this.timers.push(t); fn().catch(() => {}); };
      every(Math.max(2, s.pollSeconds) * 1000, () => this.pollProcesses());
      every(15000, () => this.pollNetwork());
      every(8000, async () => { this.transcripts.poll(); });
      every(60000, async () => { this.intent.tick(); this.intent.honestyCheck(this.transcripts.recent()); this.changed(); });
      every(2500, () => this.pollGuard());
      if (s.wormWatch !== false) every(3000, () => this.pollWorm());
      this.files.start(this.configPaths(), s.roots);
      if (s.downloadGuard) this.downloads.start(); else this.downloads.stop();
    } else {
      this.files.stop();
      this.downloads.stop();
    }
    const full = setInterval(() => this.fullScan('schedule').catch(() => {}), Math.max(1, s.fullScanHours) * 3600 * 1000);
    this.timers.push(full);
  }

  configPaths() {
    return [...C.MCP_CONFIGS.map((c) => U.expand(c.path)), ...this.inventory.configs.map((c) => c.path).filter((p) => !p.startsWith('Environment'))];
  }

  // ---------- full scan ----------
  async fullScan(reason = 'user') {
    if (this.scanning) return false;
    const steps = [
      ['gate', async () => {
        this.inventory.agents = await inv.installedAgents();
        const files = inv.scanFiles(this.store.settings.roots, this.store);
        this._files = files;
        this.inventory.mcp = inv.scanMcp(this.store, files.projectMcp);
        this.inventory.configs = [...inv.scanGlobalConfigs(), ...files.configs, ...(await inv.envBaseUrls())];
        try { this.inventory.extensions = extensions.scan(); } catch (_) { this.inventory.extensions = []; }
        try { this.inventory.packages = this.store.settings.pkgCheck !== false ? supply.scan(this.store.settings.roots) : []; } catch (_) { this.inventory.packages = []; }
        try { this.inventory.backups = this.store.settings.backupCheck !== false ? await backup.check(this.store.settings) : []; } catch (_) { this.inventory.backups = []; }
      }],
      ['traps', async () => { this.inventory.files = this._files ? this._files.files : []; }],
      ['keys', async () => { /* secrets are part of the file scan; nothing extra to do */ }],
      ['net', async () => { await this.pollNetwork(true); }],
      ['proc', async () => {
        await this.pollProcesses();
        this.inventory.autostarts = await inv.autostarts();
        for (const a of this.procs.runningAgents()) this.loadSignature(a.proc.e);
      }],
      ['files', async () => { this.inventory.models = models.scanModelDirs(this.store.settings.modelDirs); }],
    ];
    this.scanning = { reason, watcher: steps[0][0], done: 0, total: steps.length };
    this.changed(true);
    for (const [w, fn] of steps) {
      this.scanning.watcher = w;
      this.changed(true);
      const t0 = Date.now();
      try { await fn(); } catch (_) {}
      // Each phase stays visible for at least a moment so the ring can show it.
      const wait = 450 - (Date.now() - t0);
      if (wait > 0) await new Promise((r) => setTimeout(r, wait));
      this.scanning.done++;
    }
    this.diffInventory(reason);
    this.lastScan = Date.now();
    this.store.state.lastScan = this.lastScan;
    this.store.saveState();
    this.scanning = null;
    if (this.store.settings.realtime) this.files.start(this.configPaths(), this.store.settings.roots);
    this.event({ key: 'scan.done', sev: 'calm', watcher: 'gate', params: this.counts() }, true);
    this.changed(true);
    if (reason !== 'fix') this.autoFix();
    return true;
  }

  counts() {
    const i = this.inventory;
    const issues = [...i.mcp, ...i.files, ...i.configs, ...i.models, ...i.ports, ...i.autostarts, ...(i.extensions || []), ...(i.backups || []), ...(i.packages || [])].filter((x) => x.state !== 'calm').length;
    return { agents: i.agents.length, mcp: i.mcp.length, files: i.files.length, models: i.models.length, issues };
  }

  // New things since the previous scan become events (new agent, new MCP server, new autostart, changed files).
  diffInventory(reason) {
    const seen = this.store.state.seen;
    const first = !seen.done;
    const now = {};
    const note = (kind, id, hash, make) => {
      const k = `${kind}:${id}`;
      now[k] = hash;
      if (first) return;
      if (!(k in seen)) make('new');
      else if (seen[k] !== hash) make('changed');
    };
    for (const a of this.inventory.agents) note('agent', a.id, a.version || '', (how) => how === 'new' && this.event({ key: 'agent.installed', sev: 'watch', watcher: 'proc', params: { name: a.name }, agentId: a.id }));
    for (const m of this.inventory.mcp) note('mcp', m.id, m.hash, (how) => this.event({ key: how === 'new' ? 'mcp.added' : 'mcp.defChanged', sev: m.state === 'alarm' ? 'alarm' : 'watch', watcher: 'gate', params: { name: m.name, app: m.app }, target: { type: 'mcp', id: m.id } }));
    for (const f of this.inventory.files) note('file', f.id, f.hash, (how) => f.state !== 'calm' && this.event({ key: 'file.flagged', sev: f.state, watcher: 'traps', params: { file: U.shortPath(f.path) }, target: { type: 'file', id: f.id, path: f.path } }));
    for (const a of this.inventory.autostarts) note('auto', a.id, a.id, (how) => how === 'new' && this.event({ key: 'auto.added', sev: a.state === 'calm' ? 'watch' : a.state, watcher: 'proc', params: { name: a.name, cmd: a.command.slice(0, 160) }, target: { type: 'auto', id: a.id } }));
    for (const x of this.inventory.extensions || []) note('ext', x.id, x.hash, () => x.state !== 'calm' && this.event({ key: 'ext.flagged', sev: 'watch', watcher: 'gate', params: { name: x.name, browser: x.browser }, target: { type: 'ext', id: x.id, path: x.path } }));
    for (const p of this.inventory.packages || []) note('pkg', p.id, p.hash, () => p.state !== 'calm' && this.event({ key: 'pkg.flagged', sev: p.state, watcher: 'gate', params: { name: p.name }, target: { type: 'pkg', id: p.id, path: p.path } }));
    for (const b of this.inventory.backups || []) note('backup', b.id, b.hash, () => b.state !== 'calm' && this.event({ key: 'backup.flagged', sev: 'watch', watcher: 'files', params: { folders: b.names }, target: { type: 'backup', id: b.id, path: b.path } }));
    for (const m of this.inventory.models) note('model', U.sha256(m.path).slice(0, 16), String(m.size), (how) => m.state === 'alarm' && this.event({ key: 'model.flagged', sev: 'alarm', watcher: 'files', params: { file: U.shortPath(m.path) } }));
    for (const p of this.inventory.ports) note('port', p.id, p.exposed ? 'open' : 'local', (how) => p.exposed && this.event({ key: 'port.open', sev: 'alarm', watcher: 'net', params: { product: p.product, addr: p.addr, port: p.port }, target: { type: 'port', port: p.port } }));
    if (first) {
      const c = this.counts();
      if (c.issues) this.event({ key: 'scan.firstIssues', sev: 'watch', watcher: 'gate', params: { n: c.issues } });
    }
    this.store.state.seen = { ...now, done: true };
  }

  // ---------- live loops ----------
  async pollProcesses() {
    await this.procs.poll();
    this.changed();
  }

  async pollNetwork(force) {
    const g = this.guardState.running;
    const conns = g ? (await guard.connections()).map((r) => ({ la: r.la, lp: r.lp, ra: r.ra, rp: r.rp, state: r.s, pid: r.p, n: r.n })) : await net.connections();
    if (!conns.length && !force) return;
    const name = (pid) => {
      const p = this.procs.procs.get(pid);
      if (p) return p.n;
      const c = conns.find((x) => x.pid === pid && x.n);
      return c ? `${c.n}.exe` : null;
    };
    if (this.store.settings.portCheck) {
      const before = new Map(this.inventory.ports.map((p) => [p.port, p.exposed]));
      this.inventory.ports = net.aiListeners(conns, name);
      if (!force) for (const p of this.inventory.ports) if (p.exposed && !before.get(p.port)) {
        this.event({ key: 'port.open', sev: 'alarm', watcher: 'net', params: { product: p.product, addr: p.addr, port: p.port }, target: { type: 'port', port: p.port } });
      }
    }
    // Outgoing connections of agent child processes = possible exit channel.
    for (const c of conns) {
      if (c.state !== 'Established' || net.isLoopback(c.ra) || net.isAny(c.ra)) continue;
      const root = this.procs.agentOf.get(c.pid);
      if (root === undefined || root === c.pid) continue;
      const info = this.procs.roots.get(root);
      if (!info) continue;
      const set = this.remoteSeen.get(info.agent.id) || new Set();
      this.remoteSeen.set(info.agent.id, set);
      if (set.has(c.ra)) continue;
      set.add(c.ra);
      const dom = (this.pidDomains.get(c.pid) || []).slice(-1)[0];
      if (dom && AI_API.test(dom)) continue;
      const p = this.procs.procs.get(c.pid);
      this.intent.addAction({ agentId: info.agent.id, action: 'NET_NEW', source: 'network', detail: `${p ? p.n : c.pid} → ${dom || c.ra}:${c.rp}`, pid: c.pid });
    }
    this.changed();
  }

  // Worm watch: a program that knocks on many devices or ports of your home network.
  async pollWorm() {
    const rows = await net.attempts();
    if (!rows.length) return;
    this.worm.observe(rows, (pid) => { const p = this.procs.procs.get(pid); return p ? p.n : null; });
  }

  wormAlert(a) {
    const root = this.procs.agentOf.get(a.pid);
    const info = root !== undefined ? this.procs.roots.get(root) : null;
    const agentId = info ? info.agent.id : null;
    if (agentId) this.intent.addSignal(agentId, { key: a.key, params: a.params, sev: a.sev, points: a.sev === 'alarm' ? 45 : 25 });
    this.event({ ...a, agentId });
  }

  async pollGuard() {
    if (!this.guardState.installed && !guard.installed()) return;
    this.guardState.installed = true;
    const st = await guard.status();
    this.guardState.running = !!st;
    if (!st) { this.changed(); return; }
    this.guardState.sysmon = !!st.sysmon;
    this.guardState.elevated = !!st.elevated;
    if (st.seq < this.guardState.seq) this.guardState.seq = 0;      // guard restarted
    const evs = await guard.events(this.guardState.seq);
    for (const e of evs) {
      this.guardState.seq = Math.max(this.guardState.seq, e.seq || 0);
      this.guardEvent(e);
    }
    if (evs.length) this.changed();
  }

  guardEvent(e) {
    if (e.type === 'proc' && e.pid) {
      if (!this.procs.procs.has(e.pid)) {
        const p = { p: e.pid, pp: e.ppid, n: path.basename(String(e.image || '')), c: e.cmd || e.image, e: e.image, t: e.ts };
        this.procs.procs.set(e.pid, p);
        this.procs.handleNew(p);
      }
    } else if (e.type === 'dns' && e.pid && e.name) {
      const list = this.pidDomains.get(e.pid) || [];
      list.push(String(e.name).toLowerCase());
      if (list.length > 30) list.shift();
      this.pidDomains.set(e.pid, list);
      const root = this.procs.agentOf.get(e.pid);
      if (root === undefined) return;
      const info = this.procs.roots.get(root);
      if (!info) return;
      const dm = this.domains.get(info.agent.id) || new Map();
      this.domains.set(info.agent.id, dm);
      const isNew = !dm.has(e.name);
      dm.set(String(e.name).toLowerCase(), e.ts || Date.now());
      if (isNew && root !== e.pid && !AI_API.test(e.name)) {
        this.intent.addAction({ agentId: info.agent.id, action: 'NET_NEW', source: 'dns', detail: `${path.basename(String(e.image || '')) || e.pid} → ${e.name}`, pid: e.pid });
      }
    } else if (e.type === 'net' && e.pid) {
      if (e.ip && this.store.settings.wormWatch !== false) this.worm.observe([{ pid: e.pid, ra: e.ip, rp: e.port, n: path.basename(String(e.image || '')) }]);
      if (e.host) this.guardEvent({ type: 'dns', pid: e.pid, name: e.host, image: e.image, ts: e.ts });
    } else if (e.type === 'del' && e.pid) {
      const root = this.procs.agentOf.get(e.pid);
      if (root === undefined) return;
      const info = this.procs.roots.get(root);
      if (!info) return;
      const now = Date.now();
      const list = (this.deletes.get(info.agent.id) || []).filter((t) => now - t < 10000);
      list.push(now);
      this.deletes.set(info.agent.id, list);
      if (list.length === Math.max(10, Math.round(this.store.settings.massDeleteThreshold / 2))) {
        this.intent.addAction({ agentId: info.agent.id, action: 'DELETE_MANY', source: 'guard', detail: `${list.length} × ${U.shortPath(path.dirname(String(e.file || '')))}`, pid: e.pid });
      }
    } else if (e.type === 'fw') {
      const sev = e.op === 'added' && /allow/i.test(String(e.action || '')) && /in/i.test(String(e.dir || '')) ? 'alarm' : 'watch';
      this.event({ key: 'fw.changed', sev, watcher: 'net', params: { op: e.op, rule: String(e.rule || '').slice(0, 80), by: path.basename(String(e.by || '?')) } });
    }
  }

  // ---------- callbacks from watchers ----------
  agentStarted(info, initial) {
    const a = info.agent;
    if (a.root && info.flags.length) {
      this.intent.addSignal(a.id, { key: 'flag.dangerous', params: { flag: info.flags.join(' ') }, sev: 'watch', points: 30, sticky: true });
      if (!initial) this.event({ key: 'flag.dangerous', sev: 'watch', watcher: 'proc', params: { agent: a.name, flag: info.flags.join(' ') }, agentId: a.id, pid: info.proc.p });
    }
    if (!initial && a.root) this.event({ key: 'agent.started', sev: 'calm', watcher: 'proc', params: { name: a.name, pid: info.proc.p }, agentId: a.id });
    if (this.pausedAll && a.root && !initial) this.freezeAgent(a.id, 'auto');
    this.loadSignature(info.proc.e);
    this.changed();
  }

  agentStopped(info) {
    if (info.agent.root) this.event({ key: 'agent.stopped', sev: 'calm', watcher: 'proc', params: { name: info.agent.name }, agentId: info.agent.id }, true);
    this.changed();
  }

  configChanged(file) {
    const before = new Map(this.inventory.mcp.map((m) => [m.id, m.hash]));
    this.inventory.mcp = inv.scanMcp(this.store, this._files ? this._files.projectMcp : []);
    const running = this.procs.runningAgents().map((r) => r.agent.name);
    for (const m of this.inventory.mcp) {
      if (before.get(m.id) === m.hash) continue;
      this.event({ key: before.has(m.id) ? 'mcp.defChanged' : 'mcp.added', sev: m.state === 'alarm' ? 'alarm' : 'watch', watcher: 'gate',
        params: { name: m.name, app: m.app, during: running.join(', ') }, target: { type: 'mcp', id: m.id } });
    }
    const t = U.readText(file) || '';
    const r = inv.scanConfigText(file, t, path.basename(file));
    if (r) this.event({ key: r.reasons[0].key, sev: r.state, watcher: 'gate', params: { ...r.reasons[0].params, file: U.shortPath(file) } });
    // An agent changing agent settings is a classic hijack step.
    for (const ra of this.procs.runningAgents()) this.intent.addAction({ agentId: ra.agent.id, action: 'MCP_CONFIG_CHANGE', source: 'files', detail: U.shortPath(file), historic: running.length === 0 });
    this.changed();
  }

  instructionChanged(file) {
    const res = require('./textscan').scanText(U.readText(file) || '');
    if (res.sev !== 'calm') this.event({ key: 'file.flagged', sev: res.sev, watcher: 'traps', params: { file: U.shortPath(file) } });
    const i = this.inventory.files.findIndex((f) => f.path.toLowerCase() === file.toLowerCase());
    const entry = { id: U.sha256(file.toLowerCase()).slice(0, 16), path: file, kind: 'instruction', state: res.sev, reasons: res.reasons.length ? res.reasons : [{ key: 'file.ok', params: {}, sev: 'calm' }], hash: '' };
    if (i >= 0) this.inventory.files[i] = entry; else this.inventory.files.push(entry);
    this.changed();
  }

  // A new download that can run code or carries hidden instructions.
  downloadFinding(f) {
    this.event({ key: f.key, sev: f.sev, watcher: f.key === 'dl.model' || f.key === 'dl.fakeInstaller' ? 'files' : 'traps', params: f.params, target: { type: 'download', path: f.path } });
    // A fake installer is only a warning: nothing was read, nothing to set aside by "Fix it".
    if (f.key === 'dl.fakeInstaller') { this.changed(true); return; }
    // Make it part of the inventory too, so "Fix it" can set it aside.
    if (f.key === 'dl.model') {
      const m = models.scanModel(f.path);
      if (m && !this.inventory.models.some((x) => x.path === f.path)) this.inventory.models.push(m);
    } else {
      const id = U.sha256(f.path.toLowerCase()).slice(0, 16);
      if (!this.inventory.files.some((x) => x.id === id)) this.inventory.files.push({ id, path: f.path, kind: 'instruction', state: f.sev, reasons: f.reasons, hash: '' });
    }
    this.changed(true);
  }

  async massDelete(d) {
    const running = this.procs.runningAgents();
    this.event({ key: 'mass.delete', sev: 'alarm', watcher: 'files', params: { n: d.n, s: d.seconds, dir: U.shortPath(d.dir), agents: running.map((r) => r.agent.name).join(', ') } });
    for (const r of running) this.intent.addAction({ agentId: r.agent.id, action: 'DELETE_MANY', source: 'files', detail: `${d.n} × ${U.shortPath(d.dir)}` });
    if (this.store.settings.autoFreezeOnMassDelete && running.length) {
      for (const r of running) await this.freezeAgent(r.agent.id, 'massDelete');
    }
    this.changed(true);
  }

  // ---------- judge ----------
  maybeJudge(agentId) {
    const j = this.store.settings.judge;
    if (!j.enabled || !agentId) return;
    const v = this.intent.view(agentId);
    const th = thresholds(this.store.settings.level);
    if (v.score < th.watch || v.score >= 90) return;
    const last = this._judged || {};
    if (Date.now() - (last[agentId] || 0) < 120000) return;
    last[agentId] = Date.now();
    this._judged = last;
    const sess = this.transcripts.recent().filter((s) => s.agentId === agentId).sort((a, b) => b.lastAt - a.lastAt)[0];
    const sum = this.intent.summaryForJudge(agentId, sess ? sess.lastTask || sess.task : '');
    if (!sum) return;
    judge.ask({ model: j.model, ...sum }).then((r) => {
      if (r && r.risk > v.score) { this.intent.setJudge(agentId, r.risk, r.reason); this.changed(); }
    });
  }

  // ---------- stop button ----------
  agentTree(agentId) {
    const pids = [];
    const names = {};
    for (const r of this.procs.runningAgents()) {
      if (r.agent.id !== agentId) continue;
      for (const pid of this.procs.treeOf(r.proc.p)) { pids.push(pid); const p = this.procs.procs.get(pid); if (p) names[pid] = p.n; }
    }
    // Root first, then children.
    pids.sort((a, b) => ((this.procs.procs.get(a) || {}).t || 0) - ((this.procs.procs.get(b) || {}).t || 0));
    return { pids, names };
  }

  async freezeAgent(agentId, why = 'user') {
    const { pids, names } = this.agentTree(agentId);
    if (!pids.length) return { ok: false };
    let r = await pause.suspend(pids, names);
    const missing = pids.filter((p) => !r.done.includes(p));
    if (missing.length && this.guardState.running) {
      const g = await guard.procOp('suspend', missing);
      if (g && g.done) r = { ok: true, done: r.done.concat(g.done) };
    }
    if (r.done.length) {
      this.paused.set(agentId, { pids: r.done, at: Date.now() });
      this.event({ key: why === 'massDelete' ? 'pause.autoFrozen' : 'pause.frozen', sev: 'watch', watcher: 'proc', params: { name: this.agentName(agentId), n: r.done.length }, agentId });
    }
    this.changed(true);
    return { ok: r.done.length > 0, n: r.done.length };
  }

  async resumeAgent(agentId) {
    const p = this.paused.get(agentId);
    if (!p) return { ok: false };
    await pause.resume(p.pids);
    if (this.guardState.running) await guard.procOp('resume', p.pids);
    this.paused.delete(agentId);
    this.event({ key: 'pause.resumed', sev: 'calm', watcher: 'proc', params: { name: this.agentName(agentId) }, agentId });
    this.changed(true);
    return { ok: true };
  }

  async killAgent(agentId) {
    const roots = this.procs.runningAgents().filter((r) => r.agent.id === agentId);
    // Frozen processes must be resumed before they can exit cleanly.
    if (this.paused.has(agentId)) await this.resumeAgent(agentId);
    for (const r of roots) {
      const res = await pause.kill(r.proc.p, r.proc.n, this.procs.treeOf(r.proc.p));
      if (!res.ok && this.guardState.running) await guard.procOp('kill', [r.proc.p]);
    }
    this.event({ key: 'pause.killed', sev: 'watch', watcher: 'proc', params: { name: this.agentName(agentId) }, agentId });
    setTimeout(() => this.pollProcesses().catch(() => {}), 800);
    return { ok: roots.length > 0 };
  }

  async pauseAll(source = 'user') {
    this.pausedAll = true;
    let n = 0;
    for (const id of new Set(this.procs.runningAgents().map((r) => r.agent.id))) {
      const r = await this.freezeAgent(id, source);
      if (r.ok) n += r.n;
    }
    this.event({ key: 'pause.all', sev: 'watch', watcher: 'proc', params: { n } });
    this.changed(true);
    return { ok: true, n };
  }

  async resumeAll() {
    this.pausedAll = false;
    for (const id of [...this.paused.keys()]) await this.resumeAgent(id);
    this.event({ key: 'pause.allResumed', sev: 'calm', watcher: 'proc', params: {} });
    this.changed(true);
    return { ok: true };
  }

  // Firewall through Guard.
  async blockAgent(agentId, on = true) {
    if (!this.guardState.running) return { ok: false, needGuard: true };
    const exes = new Set(this.procs.runningAgents().filter((r) => r.agent.id === agentId).map((r) => r.proc.e).filter(Boolean));
    let ok = false;
    for (const exe of exes) {
      const r = on ? await guard.fwBlock(exe) : await guard.fwUnblock(exe);
      if (r && r.ok) { ok = true; if (on) this.blocked.set(exe, agentId); else this.blocked.delete(exe); }
    }
    const shared = [...exes].some((e) => /\\(node|python|pythonw|bun|deno)\.exe$/i.test(e));
    this.event({ key: on ? (shared ? 'fw.blockedShared' : 'fw.blocked') : 'fw.unblocked', sev: on ? 'watch' : 'calm', watcher: 'net', params: { name: this.agentName(agentId) }, agentId });
    this.changed(true);
    return { ok, shared };
  }

  async localOnly(port, on = true) {
    if (!this.guardState.running) return { ok: false, needGuard: true };
    const r = await guard.fwLocalOnly(port, on);
    if (r && r.ok) this.event({ key: on ? 'fw.localOnly' : 'fw.localOnlyOff', sev: 'calm', watcher: 'net', params: { port } });
    setTimeout(() => this.pollNetwork().catch(() => {}), 1500);
    return { ok: !!(r && r.ok) };
  }

  async lockdown(on) {
    if (!this.guardState.running) return { ok: false, needGuard: true };
    if (on) {
      for (const r of this.procs.runningAgents()) if (r.agent.root && r.proc.e) await guard.fwBlock(r.proc.e, 'lockdown');
    } else {
      await guard.fwUnblock(null, 'lockdown');
    }
    this.store.state.lockdown = !!on;
    this.store.saveState();
    this.event({ key: on ? 'fw.lockdown' : 'fw.lockdownOff', sev: on ? 'watch' : 'calm', watcher: 'net', params: {} });
    this.changed(true);
    return { ok: true };
  }

  // ---------- user decisions ----------
  trust(target) {
    if (!target) return;
    if (target.type === 'mcp') {
      const m = this.inventory.mcp.find((x) => x.id === target.id);
      if (m) this.store.state.approvals[m.id] = { hash: m.hash, at: Date.now() };
      this.inventory.mcp = inv.scanMcp(this.store, this._files ? this._files.projectMcp : []);
      this.event({ key: 'mcp.trusted', sev: 'calm', watcher: 'gate', params: { name: m ? m.name : '?' } });
    } else if (target.type === 'agent') {
      this.intent.approve(target.id);
      this.event({ key: 'agent.approved', sev: 'calm', watcher: 'proc', params: { name: this.agentName(target.id) }, agentId: target.id });
    } else if (target.type === 'file' || target.type === 'auto') {
      this.store.state.ignored[target.id] = Date.now();
      for (const list of [this.inventory.files, this.inventory.autostarts]) {
        const f = list.find((x) => x.id === target.id);
        if (f && f.state === 'watch') f.state = 'calm';
      }
    }
    this.store.saveState();
    this.changed(true);
  }

  checkToolCall({ agent, tool, input, cwd }) {
    const agentId = String(agent || 'unknown');
    const action = classifyTool(tool, input || {}, cwd);
    const v = this.intent.view(agentId);
    const exit = C.LABEL_OF.exit.has(action);
    if (C.HARD_FLOOR[action]) return { decision: 'deny', action, reason: `AgathOS: ${action} is blocked by a safety rule` };
    if (exit && v.labels.untrusted && v.labels.private) return { decision: 'deny', action, reason: 'AgathOS: this would complete the lethal trifecta (untrusted input + private data + sending out)' };
    if (this.paused.has(agentId) || this.pausedAll) return { decision: 'deny', action, reason: 'AgathOS: agents are paused by the user' };
    if (C.ACTIONS[action].sev >= 0.5 || v.state === 'alarm') return { decision: 'ask', action, reason: `AgathOS: risky step (${action}), score ${v.score}` };
    return { decision: 'allow', action };
  }

  // ---------- fix it ----------
  fixPlan() { return remedy.plan(this, this.store.settings.fix, 'watch'); }

  async fixApply(picks) {
    const res = await remedy.apply(this, picks, this.store.settings.fix, { source: 'user' });
    // Look again so the window shows what is left.
    setTimeout(() => this.fullScan('fix').catch(() => {}), 300);
    return res;
  }

  fixDismiss(key) { const r = remedy.dismiss(this, String(key)); this.changed(true); return r; }
  fixRestore(key) { const r = remedy.restore(this, String(key)); this.changed(true); return r; }

  async fixUndo(rid) {
    const r = await remedy.undo(this, String(rid));
    setTimeout(() => this.fullScan('fix').catch(() => {}), 300);
    return r;
  }

  // Auto mode: debounced, so a burst of alarms becomes one round of fixes.
  autoFix() {
    const f = this.store.settings.fix;
    if (!f || !f.auto || this.scanning) return;
    clearTimeout(this.autoTimer);
    this.autoTimer = setTimeout(async () => {
      const res = await remedy.auto(this).catch(() => []);
      if (res.some((r) => r.ok)) setTimeout(() => this.fullScan('fix').catch(() => {}), 500);
    }, 1500);
  }

  // ---------- events ----------
  event(e, quiet = false) {
    const full = this.store.append({ key: e.key, sev: e.sev || 'calm', watcher: e.watcher || 'proc', params: e.params || {}, agentId: e.agentId || null, pid: e.pid || null, target: e.target || null });
    // Whether it pops up is decided by the notifier (level, repeats, bundling, limit, quiet hours).
    if (!quiet && full.sev !== 'calm') this.notify(full);
    if (full.sev === 'alarm') this.autoFix();
    this.changed();
    return full;
  }

  agentName(id) {
    const a = C.AGENTS.find((x) => x.id === id);
    return a ? a.name : id;
  }

  loadSignature(exe) {
    if (!exe || this.signatures.has(exe)) return;
    this.signatures.set(exe, null);
    inv.signature(exe).then((s) => { this.signatures.set(exe, s); this.changed(); });
  }

  changed(now = false) {
    if (now) { clearTimeout(this.updateTimer); this.updateTimer = null; this.onUpdate(this.snapshot()); return; }
    if (this.updateTimer) return;
    this.updateTimer = setTimeout(() => { this.updateTimer = null; this.onUpdate(this.snapshot()); }, 400);
  }

  // ---------- snapshot for the window ----------
  agentsView() {
    const running = this.procs.runningAgents();
    const ids = new Set([...this.inventory.agents.map((a) => a.id), ...running.map((r) => r.agent.id), ...this.intent.sessions.keys()]);
    const sessions = this.transcripts.recent();
    const out = [];
    for (const id of ids) {
      const cat = C.AGENTS.find((a) => a.id === id) || { id, name: id, kind: 'cli' };
      const inst = this.inventory.agents.find((a) => a.id === id);
      const v = this.intent.view(id);
      const runs = running.filter((r) => r.agent.id === id).map((r) => {
        const p = this.procs.snapshotProc(r.proc.p) || {};
        return { pid: r.proc.p, parent: p.parent, exe: r.proc.e, cmd: String(r.proc.c || '').slice(0, 400), started: r.started, flags: r.flags,
          signer: this.signatures.get(r.proc.e) || null, children: this.procs.treeOf(r.proc.p).length - 1 };
      });
      const sess = sessions.filter((s) => s.agentId === id).sort((a, b) => b.lastAt - a.lastAt)[0];
      const reasons = [...(inst ? inst.reasons : []), ...v.reasons];
      const state = worst([v.state, ...reasons.map((r) => r.sev)]);
      out.push({
        id, name: cat.name, kind: cat.kind, version: inst ? inst.version : null, dirs: inst ? inst.dirs.map(U.shortPath) : [],
        running: runs, state, score: v.score, labels: v.labels, prediction: v.prediction, reasons: reasons.slice(0, 8),
        actions: v.actions, learned: v.learned, task: sess ? (sess.lastTask || sess.task) : '',
        domains: [...(this.domains.get(id) || new Map()).keys()].slice(-12), paused: this.paused.has(id),
      });
    }
    return out.sort((a, b) => (b.running.length - a.running.length) || (RANK[b.state] - RANK[a.state]) || a.name.localeCompare(b.name));
  }

  watcherStates(agents, view) {
    const i = view || this.inventory;
    const recent = (w, ms = 3600000) => this.store.events.filter((e) => e.watcher === w && e.sev !== 'calm' && Date.now() - e.ts < ms);
    const issues = (list) => list.filter((x) => x.state !== 'calm');
    const st = {
      gate: { list: [...i.mcp, ...(i.extensions || []), ...(i.packages || []), ...i.configs.filter((c) => c.reasons.some((r) => r.key === 'config.autoApprove'))] },
      files: { list: [...i.models, ...(i.backups || [])], ev: recent('files') },
      net: { list: [...i.ports], ev: recent('net') },
      keys: { list: [...i.files.filter((f) => f.kind === 'env'), ...i.configs.filter((c) => c.reasons.some((r) => r.key === 'config.baseUrl'))] },
      traps: { list: [...i.files.filter((f) => f.kind !== 'env')] },
      proc: { list: [...agents.map((a) => ({ state: a.state })), ...i.autostarts], ev: recent('proc', 1800000) },
    };
    return WATCHERS.map((id) => {
      const s = st[id];
      const bad = issues(s.list);
      const evState = worst((s.ev || []).map((e) => e.sev));
      const state = worst([...bad.map((x) => x.state), evState === 'alarm' ? 'watch' : 'calm']);
      return { id, state, total: s.list.length, issues: bad.length };
    });
  }

  // Dismissed findings stay visible but count as calm, so the ring and badges calm down too.
  dismissView() {
    const st = this.store.state;
    const mark = (key, x) => (remedy.isDismissed(st, key, x.reasons) ? { ...x, state: 'calm', dismissed: key, origState: x.state } : x);
    const agents = this.agentsView().map((a) => (a.state !== 'calm' ? mark(`agent:${a.id}`, a) : a));
    const i = this.inventory;
    const view = {
      mcp: i.mcp.map((m) => mark(`mcp:${m.id}`, m)),
      files: i.files.map((f) => mark(`file:${f.id}`, f)),
      configs: i.configs.map((f) => mark(`file:${f.id}`, f)),
      models: i.models.map((m) => mark(`model:${U.sha256(m.path).slice(0, 16)}`, m)),
      ports: i.ports.map((p) => mark(`port:${p.port}`, p)),
      autostarts: i.autostarts.map((a) => mark(`auto:${a.id}`, a)),
      extensions: (i.extensions || []).map((x) => mark(`ext:${x.id}`, x)),
      backups: (i.backups || []).map((b) => mark(`backup:${b.id}`, b)),
      packages: (i.packages || []).map((p) => mark(`pkg:${p.id}`, p)),
    };
    return { agents, view };
  }

  snapshot() {
    const { agents, view } = this.dismissView();
    const i = view;
    return {
      ready: true,
      platform: process.platform,
      lastScan: this.lastScan,
      scanning: this.scanning,
      heartbeat: this.procs.lastPoll,
      guard: { ...this.guardState },
      pausedAll: this.pausedAll,
      lockdown: !!this.store.state.lockdown,
      watchers: this.watcherStates(agents, view),
      agents,
      mcp: i.mcp,
      files: [...i.files.filter((f) => f.state !== 'calm' || f.kind !== 'env' || f.dismissed), ...i.configs].map((f) => ({ ...f, short: U.shortPath(f.path) })),
      models: i.models.map((m) => ({ ...m, short: U.shortPath(m.path) })),
      ports: i.ports,
      autostarts: i.autostarts,
      extensions: i.extensions.map((x) => ({ ...x, short: U.shortPath(x.path) })),
      backups: i.backups.map((b) => ({ ...b, short: U.shortPath(b.path) })),
      packages: (i.packages || []).map((p) => ({ ...p, short: U.shortPath(p.path) })),
      events: this.store.events.slice(-250).reverse(),
      settings: this.store.settings,
      chainOk: this.store.chainOk,
      counts: this.counts(),
      learnedAgents: Object.keys(this.store.state.baselines).length,
      fixPlan: this.scanning ? (this._lastPlan || []) : (this._lastPlan = this.safePlan()),
      update: this.update || null,
      snoozeUntil: this.store.state.snoozeUntil || 0,
      dismissed: Object.entries(this.store.state.dismissed || {}).map(([key, d]) => ({ key, name: d.name, at: d.at, sev: d.sev })),
      remedies: (this.store.state.remedies || []).slice(0, 30).map(({ undo, ...r }) => ({ ...r, canUndo: !!undo && !r.undone })),
      apiPort: require('./api').PORT,
    };
  }

  safePlan() {
    try { return remedy.plan(this, this.store.settings.fix, 'watch').map(({ target, ...s }) => ({ ...s, target: target && target.path ? { type: target.type, path: target.path } : target })); } catch (_) { return []; }
  }

  publicStatus() {
    const s = this.snapshot();
    return { lastScan: s.lastScan, watchers: s.watchers, pausedAll: s.pausedAll, guard: s.guard, running: s.agents.filter((a) => a.running.length).map((a) => ({ id: a.id, score: a.score, state: a.state })) };
  }
}

module.exports = { Engine, WATCHERS };
