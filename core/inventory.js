'use strict';
// AgathOS - full scan: which agents, MCP servers, instruction files, skills,
// risky settings and autostart items exist on this PC.
const fs = require('fs');
const path = require('path');
const U = require('./util');
const C = require('./catalog');
const { scanText, findSecrets } = require('./textscan');
const links = require('./links');
const boards = require('./boards');
const copies = require('./copies');

// ---------- MCP configs ----------
function tomlVal(v) {
  try { return JSON.parse(v); } catch (_) {}
  if (/^'.*'$/.test(v)) return v.slice(1, -1);
  // TOML allows a comma after the last item of an array.
  if (/^\[.*\]$/.test(v)) {
    const flat = v.replace(/,\s*\]$/, ']');
    try { return JSON.parse(flat); } catch (_) {}
    try { return JSON.parse(flat.replace(/'/g, '"')); } catch (_) {}
  }
  if (/^\{.*\}$/.test(v)) {
    const o = {};
    for (const m of v.slice(1, -1).matchAll(/("?)([\w.-]+)\1\s*=\s*("([^"]*)"|'([^']*)'|[^,]+)/g)) o[m[2]] = m[4] ?? m[5] ?? m[3].trim();
    return o;
  }
  if (v === 'true') return true;
  if (v === 'false') return false;
  return v.replace(/^"|"$/g, '');
}

// Are all brackets of a TOML value closed? (An array or inline table can run over several lines.)
function tomlClosed(s) {
  let depth = 0;
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const ch = s[i];
    if (q) { if (ch === '\\' && q === '"') i++; else if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") q = ch;
    else if (ch === '[' || ch === '{') depth++;
    else if (ch === ']' || ch === '}') depth--;
  }
  return depth <= 0;
}

function parseTomlMcp(text) {
  // Minimal TOML subset for [mcp_servers.<name>] tables (Codex CLI, Grok Build).
  const servers = {};
  let cur = null;
  let sub = null;
  const lines = text.split(/\r?\n/);
  const clean = (raw) => raw.replace(/\s+#.*$/, '').trim();
  for (let i = 0; i < lines.length; i++) {
    const line = clean(lines[i]);
    if (!line) continue;
    const t = line.match(/^\[mcp_servers\.("?)([^\]"]+)\1(?:\.(env|headers))?\]$/);
    if (t) { cur = servers[t[2]] = servers[t[2]] || { env: {} }; sub = t[3] || null; continue; }
    if (line.startsWith('[')) { cur = null; continue; }
    if (!cur) continue;
    const kv = line.match(/^("?)([\w.-]+)\1\s*=\s*(.+)$/);
    if (!kv) continue;
    let raw = kv[3].trim();
    while (/^[[{]/.test(raw) && !tomlClosed(raw) && i + 1 < lines.length) raw += ' ' + clean(lines[++i]);
    const val = tomlVal(raw);
    if (sub) { cur[sub] = cur[sub] || {}; cur[sub][kv[2]] = val; } else cur[kv[2]] = val;
  }
  return servers;
}

function serversFromJson(json) {
  if (!json || typeof json !== 'object') return {};
  const out = {};
  const add = (obj) => { if (obj && typeof obj === 'object') Object.assign(out, obj); };
  add(json.mcpServers);
  add(json.servers);
  add(json['amp.mcpServers']);   // Amp
  add(json.context_servers);     // Zed
  if (json.mcp && typeof json.mcp === 'object') {
    if (json.mcp.servers) add(json.mcp.servers);
    // opencode, Crush and Grok CLI: "mcp": { "<name>": { command | url ... } }
    else for (const [n, v] of Object.entries(json.mcp)) if (v && typeof v === 'object' && (v.command || v.url || v.type)) out[n] = v;
  }
  if (json['mcp.servers']) add(json['mcp.servers']);
  // Claude Code keeps per-project servers in ~/.claude.json -> projects[path].mcpServers
  if (json.projects && typeof json.projects === 'object') {
    for (const [proj, p] of Object.entries(json.projects)) {
      if (p && p.mcpServers) for (const [n, s] of Object.entries(p.mcpServers)) out[`${n} (${path.basename(proj)})`] = s;
    }
  }
  // Continue: experimental.modelContextProtocolServers = [{transport:{...}}]
  const cont = json.experimental && json.experimental.modelContextProtocolServers;
  if (Array.isArray(cont)) cont.forEach((s, i) => { out[`server-${i + 1}`] = s.transport || s; });
  return out;
}

function pkgFrom(command, args) {
  const a = (args || []).map(String);
  const cmd = String(command || '').toLowerCase().replace(/\.(cmd|exe)$/, '').split(/[\\/]/).pop();
  if (['npx', 'bunx', 'pnpm', 'yarn', 'uvx', 'pipx'].includes(cmd) || (cmd === 'npm' && a[0] === 'exec')) {
    const spec = a.find((x) => !x.startsWith('-') && x !== 'dlx' && x !== 'exec' && x !== 'run');
    if (!spec) return null;
    const m = spec.match(/^(@?[^@\s]+)(?:@(.+))?$/);
    return m ? { name: m[1], version: m[2] || null, runner: cmd } : null;
  }
  return null;
}

function analyseServer(name, def, app, file, store) {
  const transport = def.url || def.serverUrl || def.httpUrl ? 'http' : 'stdio';
  // Formats differ per tool: command as string (most), as array (opencode/Crush) or as {path,args} (Zed).
  let command = def.command || '';
  let args = Array.isArray(def.args) ? def.args.map(String) : [];
  if (Array.isArray(command)) { args = command.slice(1).map(String).concat(args); command = String(command[0] || ''); }
  else if (command && typeof command === 'object') { args = (Array.isArray(command.args) ? command.args.map(String) : []).concat(args); command = String(command.path || ''); }
  const url = def.url || def.serverUrl || def.httpUrl || '';
  const env = def.env || def.environment || (def.command && def.command.env) || {};
  const headers = def.headers || {};
  const definition = JSON.stringify({ command, args, url, envKeys: Object.keys(env).sort(), headerKeys: Object.keys(headers).sort() });
  const id = U.sha256(`${app}|${file}|${name}`).slice(0, 16);
  const hash = U.sha256(definition).slice(0, 16);
  const pkg = pkgFrom(command, args);
  const reasons = [];
  let state = 'calm';
  const bump = (s) => { if (s === 'alarm' || (s === 'watch' && state === 'calm')) state = s; };

  if (pkg) {
    const bad = C.KNOWN_BAD_PACKAGES.find((b) => b.name === pkg.name);
    if (bad && (bad.anyVersionRisk || !pkg.version || bad.versions.includes(pkg.version))) {
      reasons.push({ key: 'mcp.malicious', params: { pkg: pkg.name + (pkg.version ? '@' + pkg.version : '') }, sev: 'alarm' }); bump('alarm');
    }
    if (!pkg.version || /^(latest|next|\*)$/.test(pkg.version)) {
      reasons.push({ key: 'mcp.unpinned', params: { pkg: pkg.name }, sev: 'watch' }); bump('watch');
    }
  }
  const joined = [command, ...args, url, ...Object.values(env).map(String), ...Object.values(headers).map(String)].join(' ');
  // An MCP server that is itself an agent: the program that calls it hands part of its work to another AI.
  const agentServer = links.agentMcpReason([command, ...args].join(' '));
  if (agentServer) { reasons.push(agentServer); bump('watch'); }
  const secrets = findSecrets(joined);
  if (secrets.length) { reasons.push({ key: 'mcp.inlineSecret', params: { kinds: [...new Set(secrets.map((s) => s.kind))].join(', ') }, sev: 'watch' }); bump('watch'); }
  if (url) {
    let host = '';
    try { host = new URL(url).hostname; } catch (_) {}
    if (/^http:/i.test(url) && !/^(localhost|127\.|\[::1\])/.test(host)) { reasons.push({ key: 'mcp.remoteHttp', params: { host }, sev: 'watch' }); bump('watch'); }
    else reasons.push({ key: 'mcp.remote', params: { host }, sev: 'calm' });
    // A tunnel, a site that only collects what is sent to it, or a name that pretends to be a provider.
    if (!(store.settings && store.settings.linkCheck === false)) for (const r of links.hostReasons(String(host).toLowerCase())) { reasons.push(r); bump(r.sev); }
  }
  if (/\\(temp|tmp|downloads)\\/i.test(joined)) { reasons.push({ key: 'mcp.oddPath', params: {}, sev: 'watch' }); bump('watch'); }
  if (/(curl|wget|iwr|irm)[^|]*\|\s*(bash|sh|iex|powershell)|-enc(odedcommand)?\s/i.test(joined)) {
    reasons.push({ key: 'mcp.shellPipe', params: {}, sev: 'alarm' }); bump('alarm');
  }
  const approved = store.state.approvals[id];
  if (!approved) { reasons.push({ key: 'mcp.new', params: {}, sev: 'watch' }); bump('watch'); }
  else if (approved.hash !== hash) { reasons.push({ key: 'mcp.changed', params: {}, sev: 'alarm' }); bump('alarm'); }
  if (!reasons.length || reasons.every((r) => r.sev === 'calm')) reasons.push({ key: 'mcp.ok', params: {}, sev: 'calm' });
  return { id, hash, name, app, file, transport, command, args, url, pkg, state, reasons, approved: !!approved && approved.hash === hash };
}

function scanMcp(store, extraConfigs = []) {
  const servers = [];
  const configs = [...C.MCP_CONFIGS.map((c) => ({ ...c, path: U.expand(c.path) })), ...extraConfigs];
  const done = new Set();
  for (const c of configs) {
    if (!U.exists(c.path) || done.has(c.path.toLowerCase())) continue;
    done.add(c.path.toLowerCase());
    let defs = {};
    if (c.format === 'toml') defs = parseTomlMcp(U.readText(c.path) || '');
    else defs = serversFromJson(U.readJsonLoose(c.path));
    for (const [name, def] of Object.entries(defs)) {
      if (def && typeof def === 'object') servers.push(analyseServer(name, def, c.app, c.path, store));
    }
  }
  return servers;
}

// ---------- Risky settings ----------
const slash = (p) => String(p).replace(/\\/g, '/').toLowerCase();
// Grok Build: ~/.grok/config.toml (or GROK_HOME) is the user file; a .grok/config.toml in a project may only add servers, plugins and [permission] rules.
const isGrokUserConfig = (file) => slash(file) === slash(path.join(U.grokHome(), 'config.toml'));
const isGrokHook = (file) => /[\\/]\.grok[\\/]hooks[\\/][^\\/]+\.json$/i.test(file);

function scanConfigText(file, text, app) {
  const reasons = [];
  const grokUser = isGrokUserConfig(file);
  for (const r of C.RISKY_CONFIG_KEYS) {
    if (r.userOnly && !grokUser) continue;
    if (r.re.test(text)) reasons.push({ key: 'config.autoApprove', params: { key: r.key }, sev: 'alarm' });
  }
  for (const v of C.BASE_URL_VARS) {
    const m = text.match(new RegExp(`${v}["']?\\s*[:=]\\s*["']?(https?://[^"'\\s,}]+)`, 'i'));
    if (m) {
      let host = '';
      try { host = new URL(m[1]).hostname; } catch (_) {}
      if (host && !C.OFFICIAL_HOSTS.test(host)) reasons.push({ key: 'config.baseUrl', params: { v, host }, sev: 'alarm' });
    }
  }
  // Grok Build: a model with its own base_url sends the prompts (and that model's key) there.
  if (grokUser) {
    for (const m of text.matchAll(/^\s*base_url\s*=\s*["'](https?:\/\/[^"'\s]+)["']/gim)) {
      let host = '';
      try { host = new URL(m[1]).hostname; } catch (_) {}
      if (host && !C.OFFICIAL_HOSTS.test(host)) reasons.push({ key: 'config.baseUrl', params: { v: 'base_url', host }, sev: 'alarm' });
    }
  }
  if (/[\\/]\.claude[\\/]settings(\.local)?\.json$/i.test(file) && !file.toLowerCase().startsWith(path.join(U.HOME, '.claude').toLowerCase()) && /"hooks"\s*:/.test(text)) {
    reasons.push({ key: 'config.repoHooks', params: {}, sev: 'watch' });
  }
  // Grok Build hooks in a project run shell commands (after the person trusts the project folder).
  if (isGrokHook(file) && !slash(file).startsWith(slash(path.join(U.grokHome(), 'hooks')) + '/') && /"type"\s*:\s*"command"/.test(text)) {
    reasons.push({ key: 'config.repoHooks', params: {}, sev: 'watch' });
  }
  return reasons.length ? { path: file, app, kind: 'config', state: reasons.some((r) => r.sev === 'alarm') ? 'alarm' : 'watch', reasons } : null;
}

async function envBaseUrls() {
  const out = [];
  const vals = { ...process.env };
  if (U.IS_WIN) {
    const rows = await U.ps.json(`Get-ItemProperty -Path 'HKCU:\\Environment' | Select-Object ${C.BASE_URL_VARS.join(',')} | ConvertTo-Json -Compress`);
    for (const r of rows) for (const v of C.BASE_URL_VARS) if (r && r[v]) vals[v] = r[v];
  }
  if (!U.IS_WIN) Object.assign(vals, require('./mac').shellExports(C.BASE_URL_VARS));
  for (const v of C.BASE_URL_VARS) {
    if (!vals[v]) continue;
    let host = '';
    try { host = new URL(vals[v]).hostname; } catch (_) {}
    if (host && !C.OFFICIAL_HOSTS.test(host)) out.push({ id: U.sha256(`env|${v}`).slice(0, 16), path: `Environment: ${v}`, app: U.IS_MAC ? 'macOS' : 'Windows', kind: 'config', state: 'alarm', reasons: [{ key: 'config.baseUrl', params: { v, host }, sev: 'alarm' }] });
  }
  return out;
}

// The addresses of language models that are set as variables: in this program's own environment, in the user variables of Windows,
// and in the startup files of the shell (macOS, Linux). [{ v, url, app }]
async function envEndpoints() {
  const out = [];
  const app = U.IS_WIN ? 'Windows' : U.IS_MAC ? 'macOS' : 'Linux';
  const seen = new Set();
  const add = (v, url) => {
    const k = `${v}|${url}`;
    if (!url || seen.has(k)) return;
    seen.add(k);
    out.push({ v, url: String(url), app });
  };
  const names = [...links.ENDPOINT_VARS];
  for (const v of names) if (process.env[v]) add(v, process.env[v]);
  if (U.IS_WIN) {
    const rows = await U.ps.json(`Get-ItemProperty -Path 'HKCU:\\Environment' | Select-Object ${names.join(',')} | ConvertTo-Json -Compress`);
    for (const r of rows) for (const v of names) if (r && r[v]) add(v, r[v]);
  } else {
    for (const rc of require('./mac').SHELL_RC) {
      const t = U.readText(rc, 256 * 1024);
      if (t) for (const e of links.extractEndpoints(t)) add(e.name, e.url);
    }
  }
  return out;
}

// ---------- Instruction files, skills, .env, project configs ----------
function isInstructionFile(full, name) {
  const n = name.toLowerCase();
  if (C.INSTRUCTION_FILES.has(n)) return true;
  if (C.INSTRUCTION_DIR_HINTS.some((re) => re.test(full)) && /\.(md|mdc|txt|json|ya?ml)$/i.test(n)) return true;
  return false;
}

// Project-level MCP files: .cursor/mcp.json, .vscode/mcp.json, .kiro/settings/mcp.json, .grok/settings.json, .gemini/settings.json …
function isProjectMcp(f) {
  return /[\\/]\.(cursor|vscode|kiro[\\/]settings|roo|trae|windsurf|factory|kimi)[\\/]mcp\.json$/i.test(f) ||
    /[\\/]\.grok[\\/](settings\.json|config\.toml)$/i.test(f) || /[\\/](opencode|crush)\.json$/i.test(f);
}
const projectMcpFormat = (f) => (/\.toml$/i.test(f) ? 'toml' : 'json');
function projectName(f) {
  const parts = f.split(/[\\/]/);
  const i = parts.findIndex((p) => p.startsWith('.') && p.length > 1 && p !== '.mcp.json');
  return i > 0 ? parts[i - 1] : path.basename(path.dirname(f));
}

// Written as steps (a generator): scanFiles runs it to the end at once, scanFilesAsync gives the program a turn every few milliseconds.
function* scanFilesSteps(roots, store) {
  const files = [];
  const configs = [];
  const projectMcp = [];
  const linkFiles = [];
  const boardFiles = [];       // message boards named in instruction files, skills and variable files: [{ file, app, kind, hits }]
  const boardOn = !(store.settings && store.settings.boardCheck === false);
  const copyFiles = [];        // orders to copy and long blocks of text in instruction files and skills (Copy Guard): see copies.fileHits
  const copyOn = !(store.settings && store.settings.copyGuard === false);
  const seenPaths = new Set();
  const check = (file, kind, boardKind) => {
    if (seenPaths.has(file.toLowerCase())) return;
    seenPaths.add(file.toLowerCase());
    const text = U.readText(file, 4 * 1024 * 1024);
    if (text == null) return;
    if (boardOn) {
      try {
        const hits = boards.extract(text, { kind: boardKind || (kind === 'env' ? 'env' : 'instruction') });
        if (hits.length) boardFiles.push({ file, app: boards.appOf(file, projectName(file)), kind: boardKind || (kind === 'env' ? 'env' : 'instruction'), hits });
      } catch (_) { /* a file that cannot be searched gives no boards */ }
    }
    if (copyOn && kind !== 'env' && boardKind !== 'code' && boardKind !== 'config') {
      try {
        const h = copies.fileHits(file, text, { kind: kind === 'skill' ? 'skill' : 'instruction', app: boards.appOf(file, projectName(file)) });
        if (h) copyFiles.push(h);
      } catch (_) { /* a file that cannot be searched gives no hits */ }
    }
    const res = scanText(text);
    const reasons = kind === 'env' ? res.reasons.filter((r) => r.key === 'file.secret') : res.reasons;
    let state = reasons.some((r) => r.sev === 'alarm') ? 'alarm' : reasons.some((r) => r.sev === 'watch') ? 'watch' : 'calm';
    if (kind === 'env' && !reasons.length) return;
    if (!reasons.length) reasons.push({ key: 'file.ok', params: {}, sev: 'calm' });
    const id = U.sha256(file.toLowerCase()).slice(0, 16);
    if (store.state.ignored[id] && state !== 'alarm') state = 'calm';
    files.push({ id, path: file, kind, state, reasons, hash: U.sha256(text).slice(0, 16) });
  };

  for (const root of roots) {
    if (!U.exists(root)) continue;
    const found = yield* U.walkSteps(root, {
      maxDepth: 6, maxFiles: 60000,
      filter: (full, name) => {
        const n = name.toLowerCase();
        return isInstructionFile(full, name) || /^\.env(\..+)?$/.test(n) || n === '.mcp.json' || isProjectMcp(full) ||
          (/[\\/]\.(claude|vscode|cursor|gemini|codex|grok)[\\/]/i.test(full) && /\.(json|toml)$/.test(n)) || links.PROJECT_FILE.test(full);
      },
    });
    for (const f of found) {
      yield;
      const n = path.basename(f).toLowerCase();
      // Files that can hold the address of a language model (AI links look at them; a file with only settings is not an instruction file).
      if (links.PROJECT_FILE.test(f)) linkFiles.push({ path: f, app: `Project ${projectName(f)}` });
      if (/\.ya?ml$/.test(n) && !isInstructionFile(f, path.basename(f))) continue;
      if (/^\.env(\..+)?$/.test(n)) { if (!/\.example$|\.sample$|\.template$/.test(n)) check(f, 'env'); continue; }
      const isMcpFile = n === '.mcp.json' || isProjectMcp(f);
      if (isMcpFile) projectMcp.push({ app: `Project ${projectName(f)}`, path: f, format: projectMcpFormat(f) });
      // A project .grok/config.toml holds servers and also [permission] rules: it gets both checks.
      if (isMcpFile && !/[\\/]\.grok[\\/]config\.toml$/i.test(f)) continue;
      if (/\.(json|toml)$/.test(n) && !isInstructionFile(f, path.basename(f))) {
        const r = scanConfigText(f, U.readText(f) || '', 'Project');
        if (r) configs.push({ id: U.sha256(f.toLowerCase()).slice(0, 16), ...r });
        continue;
      }
      check(f, 'instruction');
    }
  }
  // macOS and Linux: API keys are often exported in shell startup files.
  if (!U.IS_WIN) for (const rc of require('./mac').SHELL_RC) if (U.exists(rc)) check(rc, 'env');
  for (const d of C.SKILL_DIRS.map(U.expand)) {
    if (!U.exists(d)) continue;
    const skillFiles = yield* U.walkSteps(d, { maxDepth: 5, maxFiles: 5000, filter: (full, n) => /\.(md|mdc|txt|sh|ps1|py|js|ts|json|ya?ml)$/i.test(n) });
    for (const f of skillFiles) { check(f, 'skill', boards.kindOf(f, true)); yield; }
  }
  return { files, configs, projectMcp, linkFiles, boardFiles, copyFiles };
}
const scanFiles = (roots, store) => U.run(scanFilesSteps(roots, store));
const scanFilesAsync = (roots, store) => U.runCooperative(scanFilesSteps(roots, store));

function scanGlobalConfigs() {
  const out = [];
  const list = [
    ['%USERPROFILE%\\.claude\\settings.json', 'Claude Code'], ['%USERPROFILE%\\.claude\\settings.local.json', 'Claude Code'],
    ['%USERPROFILE%\\.codex\\config.toml', 'Codex CLI'], ['%APPDATA%\\Code\\User\\settings.json', 'VS Code'],
    ['%APPDATA%\\Cursor\\User\\settings.json', 'Cursor'], ['%USERPROFILE%\\.gemini\\settings.json', 'Gemini CLI'],
    ['%USERPROFILE%\\.qwen\\settings.json', 'Qwen Code'], ['%APPDATA%\\Windsurf\\User\\settings.json', 'Windsurf'],
    ['%GROK_HOME%\\config.toml', 'Grok Build'],
  ];
  for (const [p, app] of list) {
    const f = U.expand(p);
    const t = U.readText(f);
    if (t == null) continue;
    const r = scanConfigText(f, t, app);
    if (r) out.push({ id: U.sha256(f.toLowerCase()).slice(0, 16), ...r });
  }
  return out;
}

// ---------- Installed agents and versions ----------
function cmpVersion(a, b) {
  const pa = String(a).match(/\d+/g) || [];
  const pb = String(b).match(/\d+/g) || [];
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (+pa[i] || 0) - (+pb[i] || 0);
    if (d) return d;
  }
  return 0;
}

async function installedAgents() {
  const out = [];
  for (const a of C.AGENTS) {
    const dirs = (a.dirs || []).map(U.expand).filter(U.exists);
    if (!dirs.length) continue;
    const entry = { id: a.id, name: a.name, kind: a.kind, dirs, version: null, reasons: [] };
    if (a.version && (U.IS_WIN || U.IS_MAC)) {
      const out1 = U.IS_WIN ? await U.execFileText('cmd.exe', ['/d', '/c', a.version[0], ...a.version[1]], 6000) : await U.execFileText(a.version[0], a.version[1], 6000);
      const m = out1 && out1.match(/\d+\.\d+(\.\d+)?/);
      if (m) entry.version = m[0];
    }
    const min = C.MIN_VERSIONS[a.id];
    if (min && entry.version && cmpVersion(entry.version, min.min) < 0) {
      entry.reasons.push({ key: 'version.old', params: { v: entry.version, min: min.min, cve: min.cve }, sev: 'alarm' });
    }
    out.push(entry);
  }
  return out;
}

async function exeVersion(exePath) {
  if (!U.IS_WIN || !exePath) return null;
  const out = await U.ps.run(`(Get-Item -LiteralPath ${U.psq(exePath)}).VersionInfo.ProductVersion`, 5000);
  const m = out && out.match(/\d+\.\d+(\.\d+)?/);
  return m ? m[0] : null;
}

async function signature(exePath) {
  if (U.IS_MAC) return require('./mac').signature(exePath);
  if (!U.IS_WIN || !exePath) return null;
  const rows = await U.ps.json(`$s = Get-AuthenticodeSignature -LiteralPath ${U.psq(exePath)}; [pscustomobject]@{ status = "$($s.Status)"; subject = "$($s.SignerCertificate.Subject)" } | ConvertTo-Json -Compress`, 8000);
  const r = rows[0];
  if (!r) return null;
  const cn = (r.subject.match(/CN=("?)([^,"]+)\1/) || [])[2] || '';
  return { valid: r.status === 'Valid', status: r.status, signer: cn };
}

// ---------- Autostart ----------
async function autostarts() {
  if (U.IS_MAC) return require('./mac').autostarts();
  if (!U.IS_WIN) return [];
  const rows = await U.ps.json(`
$a = @(Get-CimInstance Win32_StartupCommand | ForEach-Object { [pscustomobject]@{ kind='startup'; name=$_.Name; command=$_.Command; where=$_.Location } })
$b = @(Get-ScheduledTask | Where-Object { $_.State -ne 'Disabled' -and $_.TaskPath -notlike '\\Microsoft\\*' } | ForEach-Object {
  $act = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' ; '
  [pscustomobject]@{ kind='task'; name=$_.TaskName; command=$act; where=$_.TaskPath } })
@($a + $b) | ConvertTo-Json -Compress -Depth 3`, 30000);
  return rows.filter((r) => r && r.command).map((r) => {
    const cmd = String(r.command);
    const reasons = [];
    let state = 'calm';
    if (/powershell[^\n]*-(enc|encodedcommand|w(indowstyle)?\s+hidden)|mshta|wscript|cscript.*\.(js|vbs)|rundll32[^\n]*,/i.test(cmd)) { reasons.push({ key: 'auto.hiddenScript', params: {}, sev: 'alarm' }); state = 'alarm'; }
    if (/\\(temp|tmp|downloads)\\/i.test(cmd)) { reasons.push({ key: 'auto.tempPath', params: {}, sev: 'watch' }); if (state === 'calm') state = 'watch'; }
    if (/node(\.exe)?\s|python(w)?(\.exe)?\s|bun(\.exe)?\s|deno(\.exe)?\s|npx|uvx/i.test(cmd)) { reasons.push({ key: 'auto.scriptRuntime', params: {}, sev: 'watch' }); if (state === 'calm') state = 'watch'; }
    if (/claude|codex|gemini|openclaw|ollama|agent|mcp|llm|gpt/i.test(cmd + ' ' + r.name)) reasons.push({ key: 'auto.ai', params: {}, sev: 'calm' });
    const id = U.sha256(`${r.kind}|${r.name}|${cmd}`).slice(0, 16);
    return { id, kind: r.kind, name: r.name, command: cmd, where: r.where, state, reasons };
  });
}

module.exports = {
  isProjectMcp, scanMcp, scanFiles, scanFilesAsync, scanFilesSteps, scanGlobalConfigs, envBaseUrls, envEndpoints, installedAgents, exeVersion, signature, autostarts,
  parseTomlMcp, serversFromJson, analyseServer, pkgFrom, cmpVersion, scanConfigText, projectName,
};
