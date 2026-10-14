'use strict';
// AgathOS - Worm watch, part 2: worms that spread through packages and projects.
// Shai-Hulud (2025) hid in npm packages: an install script stole tokens, then published the
// worm into every package the victim could publish. A second wave added a GitHub workflow that
// sent all secrets to a catch-all web address. AgathOS reads only text files of the project
// folders it watches (package.json, install scripts, GitHub workflows). Nothing is run, nothing
// is changed. It cannot prove that a package is bad, and a clean result is not a guarantee.
//   * known leftovers of Shai-Hulud (file and workflow names)         -> danger
//   * an install script that downloads and runs code, or reads tokens -> danger
//   * an install script that hides what it does (base64, eval)        -> attention
//   * a workflow that dumps all secrets or posts to a catch-all site  -> attention / danger
const fs = require('fs');
const path = require('path');
const U = require('./util');

const LIFECYCLE = ['preinstall', 'install', 'postinstall', 'prepublish', 'prepare', 'preuninstall', 'postuninstall'];
const IOC_FILES = new Set(['setup_bun.js', 'bun_environment.js', 'trufflesecrets.json']);
const IOC_WORKFLOW = /^shai-hulud.*\.ya?ml$/i;
const SKIP = new Set(['.git', 'venv', '.venv', '__pycache__', 'dist', 'build', 'target', 'AppData', 'Library', '.cache', '.npm', 'node_modules']);

const FETCH_RUN = /\b(curl|wget|iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n|;&]*\|\s*(sh|bash|zsh|node|python3?|iex|invoke-expression)\b|\b(iex|invoke-expression)\b[^\n]*\b(iwr|irm|downloadstring|webclient)|powershell[^\n]*-enc(odedcommand)?\b|\bnode\s+-e\b[^\n]*https?:|\b(mshta|bitsadmin)\b|certutil[^\n]*-urlcache/i;
const SECRET_REF = /trufflehog|gitleaks|\.npmrc|\.ssh[\\/]|\.aws[\\/]|\.git-credentials|\bid_(rsa|ed25519)\b|\b(NPM|GITHUB|GH)_TOKEN\b/i;
const HIDDEN = /base64\s+(-d|--decode)|\batob\(|Buffer\.from\([^)]*base64|\beval\(|new Function\(/i;
const CATCHALL = /webhook\.site|requestbin|pipedream\.net|interact\.sh|oast\.(fun|live|pro|site)|ngrok(-free)?\.(io|app|dev)|burpcollaborator/i;
// Words inside a script file that, together, make it a token thief or a self-spreader.
const BODY_TOKENS = /trufflehog|\.npmrc|\bNPM_TOKEN\b|\bGITHUB_TOKEN\b|\.aws[\\/]credentials|\.git-credentials/i;
const BODY_PUBLISH = /npm\s+publish|registry\.npmjs\.org\/-\/|\/-\/npm\/v1\/(tokens|user)/i;
const BODY_SEND = /webhook\.site|api\.github\.com\/(user\/repos|repos\/[^'"`]*\/(contents|actions))|raw\.githubusercontent\.com\/[^'"`]*\.sh/i;

const safeJson = (file, max = 256 * 1024) => {
  const txt = U.readText(file, max);
  if (txt == null) return null;
  try { return JSON.parse(String(txt).replace(/^﻿/, '')); } catch (_) { return null; }
};

// One install script (the command line), and the script file it starts, when it is a plain "node file.js".
function analyseScript(name, cmd, dir) {
  const reasons = [];
  const text = String(cmd || '');
  if (FETCH_RUN.test(text)) reasons.push({ key: 'pkg.fetchRun', params: { script: name }, sev: 'alarm' });
  if (SECRET_REF.test(text)) reasons.push({ key: 'pkg.stealer', params: { script: name }, sev: 'alarm' });
  if (HIDDEN.test(text)) reasons.push({ key: 'pkg.obfuscated', params: { script: name }, sev: 'watch' });
  const m = /^\s*(?:node|bash|sh)\s+(?:\.[\\/])?([\w@./\\-]+\.(?:js|cjs|mjs|sh))\s*$/i.exec(text);
  if (m && !m[1].includes('..')) {
    const body = U.readText(path.join(dir, m[1]), 400 * 1024) || '';
    const tokens = BODY_TOKENS.test(body);
    if (tokens && BODY_PUBLISH.test(body)) reasons.push({ key: 'pkg.selfSpread', params: { script: name }, sev: 'alarm' });
    else if (tokens && (BODY_SEND.test(body) || CATCHALL.test(body))) reasons.push({ key: 'pkg.stealer', params: { script: name }, sev: 'alarm' });
    else if (HIDDEN.test(body) && /https?:\/\//i.test(body) && /child_process|execSync|spawn/i.test(body)) reasons.push({ key: 'pkg.obfuscated', params: { script: name }, sev: 'watch' });
  }
  return reasons;
}

// package.json of a project or of a package in node_modules.
function analysePackage(manifest, dir) {
  if (!manifest || typeof manifest !== 'object' || !manifest.scripts || typeof manifest.scripts !== 'object') return [];
  const out = [];
  for (const k of LIFECYCLE) if (typeof manifest.scripts[k] === 'string') out.push(...analyseScript(k, manifest.scripts[k], dir));
  return out;
}

function analyseWorkflow(text) {
  const reasons = [];
  const dump = /toJSON\(\s*secrets\s*\)/i.test(text);
  const send = CATCHALL.test(text);
  if (send) reasons.push({ key: 'pkg.wfSend', params: {}, sev: 'alarm' });
  if (dump) reasons.push({ key: 'pkg.wfDump', params: {}, sev: send ? 'alarm' : 'watch' });
  return reasons;
}

const worst = (reasons) => (reasons.some((r) => r.sev === 'alarm') ? 'alarm' : reasons.length ? 'watch' : 'calm');

function item(kind, name, file, reasons) {
  reasons = reasons.filter((r, i, a) => a.findIndex((x) => x.key === r.key && JSON.stringify(x.params) === JSON.stringify(r.params)) === i);
  return {
    id: U.sha256(`${kind}|${file}`).slice(0, 16), kind, name, path: file, state: worst(reasons), reasons,
    hash: U.sha256(JSON.stringify(reasons.map((r) => [r.key, r.params]))).slice(0, 16),
  };
}

function listDir(dir) { try { return fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { return []; } }

// Project folders: a folder with a package.json or a .github/workflows folder, a few levels deep.
function findProjects(roots, maxDepth = 3, maxDirs = 3000, maxProjects = 60) {
  const out = [];
  let seen = 0;
  const stack = roots.filter((r) => U.exists(r)).map((r) => [r, 0]);
  while (stack.length && seen < maxDirs && out.length < maxProjects) {
    const [dir, depth] = stack.pop();
    seen++;
    const entries = listDir(dir);
    if (entries.some((e) => e.name === 'package.json' && e.isFile()) || entries.some((e) => e.name === '.github' && e.isDirectory())) out.push(dir);
    if (depth >= maxDepth) continue;
    for (const e of entries) if (e.isDirectory() && !e.isSymbolicLink() && !SKIP.has(e.name) && !e.name.startsWith('.')) stack.push([path.join(dir, e.name), depth + 1]);
  }
  return out;
}

function scanProject(dir, budget) {
  const found = [];
  // The project's own package.json.
  const own = path.join(dir, 'package.json');
  const m = safeJson(own);
  if (m) {
    const r = analysePackage(m, dir);
    if (r.length) found.push(item('package', m.name || path.basename(dir), own, r));
  }
  // Leftovers of Shai-Hulud in the project folder.
  for (const e of listDir(dir)) {
    if (e.isFile() && IOC_FILES.has(e.name.toLowerCase())) found.push(item('ioc', e.name, path.join(dir, e.name), [{ key: 'pkg.ioc', params: { file: e.name }, sev: 'alarm' }]));
  }
  // GitHub workflows.
  const wfDir = path.join(dir, '.github', 'workflows');
  for (const e of listDir(wfDir).slice(0, 40)) {
    if (!e.isFile() || !/\.ya?ml$/i.test(e.name)) continue;
    const file = path.join(wfDir, e.name);
    const reasons = [];
    if (IOC_WORKFLOW.test(e.name)) reasons.push({ key: 'pkg.ioc', params: { file: e.name }, sev: 'alarm' });
    reasons.push(...analyseWorkflow(U.readText(file, 128 * 1024) || ''));
    if (reasons.length) found.push(item('workflow', e.name, file, reasons));
  }
  // Packages that were installed here (first level, plus @scope/name).
  const nm = path.join(dir, 'node_modules');
  for (const e of listDir(nm)) {
    if (budget.left <= 0) break;
    if (!e.isDirectory() || e.name.startsWith('.')) continue;
    const pkgDirs = e.name.startsWith('@') ? listDir(path.join(nm, e.name)).filter((x) => x.isDirectory()).map((x) => path.join(nm, e.name, x.name)) : [path.join(nm, e.name)];
    for (const pd of pkgDirs) {
      if (budget.left-- <= 0) break;
      const file = path.join(pd, 'package.json');
      const pm = safeJson(file);
      const reasons = pm ? analysePackage(pm, pd) : [];
      for (const f of listDir(pd)) if (f.isFile() && IOC_FILES.has(f.name.toLowerCase())) reasons.push({ key: 'pkg.ioc', params: { file: f.name }, sev: 'alarm' });
      if (reasons.length) found.push(item('package', `${(pm && pm.name) || path.basename(pd)}${pm && pm.version ? ' ' + pm.version : ''}`, file, reasons));
    }
  }
  return found;
}

// roots: the project folders AgathOS watches. Returns only what is worth a look.
function scan(roots, { maxPackages = 1500 } = {}) {
  const budget = { left: maxPackages };
  const out = [];
  const seen = new Set();
  for (const p of findProjects(roots || [])) {
    for (const it of scanProject(p, budget)) if (!seen.has(it.id)) { seen.add(it.id); out.push(it); }
  }
  const RANK = { alarm: 2, watch: 1, calm: 0 };
  return out.sort((a, b) => RANK[b.state] - RANK[a.state] || a.name.localeCompare(b.name)).slice(0, 100);
}

module.exports = { scan, analysePackage, analyseScript, analyseWorkflow, findProjects, LIFECYCLE };
