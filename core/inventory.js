'use strict';
// AgathOS - full scan: which agents, MCP servers, instruction files, skills,
// risky settings and autostart items exist on this PC.
const fs = require('fs');
const path = require('path');
const U = require('./util');
const C = require('./catalog');
const { scanText, findSecrets } = require('./textscan');

// ---------- MCP configs ----------
function tomlVal(v) {
  try { return JSON.parse(v); } catch (_) {}
  if (/^'.*'$/.test(v)) return v.slice(1, -1);
  if (/^\[.*\]$/.test(v)) { try { return JSON.parse(v.replace(/'/g, '"')); } catch (_) {} }
  if (/^\{.*\}$/.test(v)) {
    const o = {};
    for (const m of v.slice(1, -1).matchAll(/("?)([\w.-]+)\1\s*=\s*("([^"]*)"|'([^']*)'|[^,]+)/g)) o[m[2]] = m[4] ?? m[5] ?? m[3].trim();
    return o;
  }
  if (v === 'true') return true;
  if (v === 'false') return false;
  return v.replace(/^"|"$/g, '');
}

function parseTomlMcp(text) {
  // Minimal TOML subset for [mcp_servers.<name>] tables (Codex CLI).
  const servers = {};
  let cur = null;
  let sub = null;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.replace(/\s+#.*$/, '').trim();
    if (!line) continue;
    const t = line.match(/^\[mcp_servers\.("?)([^\]"]+)\1(?:\.(env|headers))?\]$/);
    if (t) { cur = servers[t[2]] = servers[t[2]] || { env: {} }; sub = t[3] || null; continue; }
    if (line.startsWith('[')) { cur = null; continue; }
    if (!cur) continue;
    const kv = line.match(/^("?)([\w.-]+)\1\s*=\s*(.+)$/);
    if (!kv) continue;
    const val = tomlVal(kv[3].trim());
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
  const secrets = findSecrets(joined);
  if (secrets.length) { reasons.push({ key: 'mcp.inlineSecret', params: { kinds: [...new Set(secrets.map((s) => s.kind))].join(', ') }, sev: 'watch' }); bump('watch'); }
  if (url) {
    let host = '';
    try { host = new URL(url).hostname; } catch (_) {}
    if (/^http:/i.test(url) && !/^(localhost|127\.|\[::1\])/.test(host)) { reasons.push({ key: 'mcp.remoteHttp', params: { host }, sev: 'watch' }); bump('watch'); }
    else reasons.push({ key: 'mcp.remote', params: { host }, sev: 'calm' });
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
  for (const c of configs) {
    if (!U.exists(c.path)) continue;
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
function scanConfigText(file, text, app) {
  const reasons = [];
  for (const r of C.RISKY_CONFIG_KEYS) if (r.re.test(text)) reasons.push({ key: 'config.autoApprove', params: { key: r.key }, sev: 'alarm' });
  for (const v of C.BASE_URL_VARS) {
    const m = text.match(new RegExp(`${v}["']?\\s*[:=]\\s*["']?(https?://[^"'\\s,}]+)`, 'i'));
    if (m) {
      let host = '';
      try { host = new URL(m[1]).hostname; } catch (_) {}
      if (host && !C.OFFICIAL_HOSTS.test(host)) reasons.push({ key: 'config.baseUrl', params: { v, host }, sev: 'alarm' });
    }
  }
  if (/[\\/]\.claude[\\/]settings(\.local)?\.json$/i.test(file) && !file.toLowerCase().startsWith(path.join(U.HOME, '.claude').toLowerCase()) && /"hooks"\s*:/.test(text)) {
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
  for (const v of C.BASE_URL_VARS) {
    if (!vals[v]) continue;
    let host = '';
    try { host = new URL(vals[v]).hostname; } catch (_) {}
    if (host && !C.OFFICIAL_HOSTS.test(host)) out.push({ path: `Environment: ${v}`, app: 'Windows', kind: 'config', state: 'alarm', reasons: [{ key: 'config.baseUrl', params: { v, host }, sev: 'alarm' }] });
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
    /[\\/]\.grok[\\/]settings\.json$/i.test(f) || /[\\/](opencode|crush)\.json$/i.test(f);
}
function projectName(f) {
  const parts = f.split(/[\\/]/);
  const i = parts.findIndex((p) => p.startsWith('.') && p.length > 1 && p !== '.mcp.json');
  return i > 0 ? parts[i - 1] : path.basename(path.dirname(f));
}

function scanFiles(roots, store) {
  const files = [];
  const configs = [];
  const projectMcp = [];
  const seenPaths = new Set();
  const check = (file, kind) => {
    if (seenPaths.has(file.toLowerCase())) return;
    seenPaths.add(file.toLowerCase());
    const text = U.readText(file, 4 * 1024 * 1024);
    if (text == null) return;
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
    const found = U.walk(root, {
      maxDepth: 6, maxFiles: 60000,
      filter: (full, name) => {
        const n = name.toLowerCase();
        return isInstructionFile(full, name) || /^\.env(\..+)?$/.test(n) || n === '.mcp.json' || isProjectMcp(full) ||
          (/[\\/]\.(claude|vscode|cursor|gemini|codex)[\\/]/i.test(full) && /\.(json|toml)$/.test(n));
      },
    });
    for (const f of found) {
      const n = path.basename(f).toLowerCase();
      if (/^\.env(\..+)?$/.test(n)) { if (!/\.example$|\.sample$|\.template$/.test(n)) check(f, 'env'); continue; }
      if (n === '.mcp.json' || isProjectMcp(f)) { projectMcp.push({ app: `Project ${projectName(f)}`, path: f, format: 'json' }); continue; }
      if (/\.(json|toml)$/.test(n) && !isInstructionFile(f, path.basename(f))) {
        const r = scanConfigText(f, U.readText(f) || '', 'Project');
        if (r) configs.push({ id: U.sha256(f.toLowerCase()).slice(0, 16), ...r });
        continue;
      }
      check(f, 'instruction');
    }
  }
  for (const d of C.SKILL_DIRS.map(U.expand)) {
    if (!U.exists(d)) continue;
    for (const f of U.walk(d, { maxDepth: 5, maxFiles: 5000, filter: (full, n) => /\.(md|mdc|txt|sh|ps1|py|js|ts|json|ya?ml)$/i.test(n) })) check(f, 'skill');
  }
  return { files, configs, projectMcp };
}

function scanGlobalConfigs() {
  const out = [];
  const list = [
    ['%USERPROFILE%\\.claude\\settings.json', 'Claude Code'], ['%USERPROFILE%\\.claude\\settings.local.json', 'Claude Code'],
    ['%USERPROFILE%\\.codex\\config.toml', 'Codex CLI'], ['%APPDATA%\\Code\\User\\settings.json', 'VS Code'],
    ['%APPDATA%\\Cursor\\User\\settings.json', 'Cursor'], ['%USERPROFILE%\\.gemini\\settings.json', 'Gemini CLI'],
    ['%USERPROFILE%\\.qwen\\settings.json', 'Qwen Code'], ['%APPDATA%\\Windsurf\\User\\settings.json', 'Windsurf'],
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
    if (a.version && U.IS_WIN) {
      const out1 = await U.execFileText('cmd.exe', ['/d', '/c', a.version[0], ...a.version[1]], 6000);
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
  if (!U.IS_WIN || !exePath) return null;
  const rows = await U.ps.json(`$s = Get-AuthenticodeSignature -LiteralPath ${U.psq(exePath)}; [pscustomobject]@{ status = "$($s.Status)"; subject = "$($s.SignerCertificate.Subject)" } | ConvertTo-Json -Compress`, 8000);
  const r = rows[0];
  if (!r) return null;
  const cn = (r.subject.match(/CN=("?)([^,"]+)\1/) || [])[2] || '';
  return { valid: r.status === 'Valid', status: r.status, signer: cn };
}

// ---------- Autostart ----------
async function autostarts() {
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
  isProjectMcp, scanMcp, scanFiles, scanGlobalConfigs, envBaseUrls, installedAgents, exeVersion, signature, autostarts,
  parseTomlMcp, serversFromJson, analyseServer, pkgFrom, cmpVersion, scanConfigText,
};
