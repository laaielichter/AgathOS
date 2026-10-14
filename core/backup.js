'use strict';
// AgathOS - backup check.
// An agent that deletes a folder (Antigravity wiped a whole drive in 2025, Shai-Hulud wipes the
// home folder) is only a disaster when there is no second copy. AgathOS looks for a sign of a copy
// of each work folder it watches. It never reads file contents and never changes anything.
//   * the folder lies inside a cloud folder (OneDrive, Dropbox, Google Drive, iCloud Drive)
//   * every Git project in it has a remote (a copy on a server)
//   * Mac: Time Machine has made a backup
// It does not look inside File History or other backup programs, and it cannot see an external
// disk. So it only ever says "no sign of a backup", never "no backup", and you can dismiss it.
const fs = require('fs');
const path = require('path');
const U = require('./util');

const SKIP = new Set(['node_modules', '.git', 'venv', '.venv', '__pycache__', 'dist', 'build', 'target', 'AppData', 'Library', '.cache', '.npm']);
const SKIP_ROOT_NAMES = /^downloads$/i;   // downloads can be fetched again: not worth a warning

const same = (a, b) => (U.IS_WIN || U.IS_MAC ? String(a).toLowerCase() === String(b).toLowerCase() : a === b);
function inside(child, parent) {
  const c = path.resolve(child);
  const p = path.resolve(parent);
  const norm = (x) => (U.IS_WIN || U.IS_MAC ? x.toLowerCase() : x);
  return norm(c) === norm(p) || norm(c).startsWith(norm(p) + path.sep);
}

// Folders that a sync program keeps a copy of.
function syncRoots(home = U.HOME, env = process.env) {
  const out = [];
  const add = (service, dir) => { if (dir && U.exists(dir) && !out.some((o) => same(o.dir, dir))) out.push({ service, dir }); };
  for (const k of ['OneDrive', 'OneDriveConsumer', 'OneDriveCommercial']) add('OneDrive', env[k]);
  let names = [];
  try { names = fs.readdirSync(home); } catch (_) { /* no home: nothing to find */ }
  for (const n of names) {
    if (/^OneDrive(\b|\s|-)/i.test(n)) add('OneDrive', path.join(home, n));
    else if (/^Dropbox/i.test(n)) add('Dropbox', path.join(home, n));
    else if (/^(Google ?Drive|My Drive)$/i.test(n)) add('Google Drive', path.join(home, n));
    else if (/^iCloud ?Drive$/i.test(n)) add('iCloud Drive', path.join(home, n));
  }
  add('iCloud Drive', path.join(home, 'Library', 'Mobile Documents', 'com~apple~CloudDocs'));
  try {
    for (const n of fs.readdirSync(path.join(home, 'Library', 'CloudStorage'))) {
      const svc = /^Dropbox/i.test(n) ? 'Dropbox' : /^GoogleDrive/i.test(n) ? 'Google Drive' : /^OneDrive/i.test(n) ? 'OneDrive' : /^iCloud/i.test(n) ? 'iCloud Drive' : null;
      if (svc) add(svc, path.join(home, 'Library', 'CloudStorage', n));
    }
  } catch (_) { /* not a Mac */ }
  return out;
}

// Counts Git projects below a folder (a few levels deep) and how many have a remote copy.
function gitRepos(root, maxDepth = 3, maxDirs = 3000) {
  let total = 0;
  let withRemote = 0;
  let seen = 0;
  const stack = [[root, 0]];
  while (stack.length && seen < maxDirs) {
    const [dir, depth] = stack.pop();
    seen++;
    const cfg = path.join(dir, '.git', 'config');
    if (U.exists(cfg)) {
      total++;
      const txt = U.readText(cfg, 64 * 1024) || '';
      if (/^\s*\[remote\s+"[^"]+"\]/m.test(txt)) withRemote++;
      continue;       // a project inside a project is not counted twice
    }
    if (depth >= maxDepth) continue;
    let entries = [];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of entries) if (e.isDirectory() && !e.isSymbolicLink() && !SKIP.has(e.name) && !e.name.startsWith('.')) stack.push([path.join(dir, e.name), depth + 1]);
  }
  return { total, withRemote };
}

function inspectRoot(root, sync) {
  const hit = sync.find((s) => inside(root, s.dir));
  return { path: root, service: hit ? hit.service : null, repos: gitRepos(root) };
}

// rows: [{ path, service, repos: { total, withRemote } }]; system: { timeMachine: bool|null }
function assess(rows, system = {}) {
  const short = (p) => U.shortPath(p);
  const protectedBy = (r) => r.service ? 'cloud' : (r.repos.total > 0 && r.repos.withRemote === r.repos.total) ? 'git' : null;
  if (!rows.length) return null;
  const reasons = [];
  if (system.timeMachine) {
    reasons.push({ key: 'backup.timeMachine', params: {}, sev: 'calm' });
    return { state: 'calm', reasons, names: rows.map((r) => short(r.path)).join(', '), path: rows[0].path, hash: 'tm' };
  }
  const bad = rows.filter((r) => !protectedBy(r));
  for (const r of rows) {
    const by = protectedBy(r);
    if (by === 'cloud') reasons.push({ key: 'backup.cloud', params: { folder: short(r.path), service: r.service }, sev: 'calm' });
    else if (by === 'git') reasons.push({ key: 'backup.git', params: { folder: short(r.path), repos: r.repos.total }, sev: 'calm' });
  }
  if (bad.length) reasons.unshift({ key: 'backup.none', params: { n: bad.length, folders: bad.slice(0, 4).map((r) => short(r.path)).join(', ') }, sev: 'watch' });
  return {
    state: bad.length ? 'watch' : 'calm', reasons,
    names: (bad.length ? bad : rows).map((r) => short(r.path)).join(', ').slice(0, 120),
    path: (bad[0] || rows[0]).path,
    hash: U.sha256(JSON.stringify(bad.map((r) => r.path).sort())).slice(0, 16),
  };
}

async function timeMachine() {
  if (!U.IS_MAC) return null;
  const out = await U.execFileText('tmutil', ['latestbackup'], 8000);
  const line = out ? out.trim().split('\n')[0] : '';
  return line.startsWith('/') ? true : null;      // anything else: unknown, not "no backup"
}

// The item for the inventory (an array with zero or one entry).
async function check(settings, { sync = syncRoots(), tm = timeMachine } = {}) {
  const roots = (settings.roots || []).filter((r) => U.exists(r) && !SKIP_ROOT_NAMES.test(path.basename(r)));
  if (!roots.length) return [];
  const rows = roots.map((r) => inspectRoot(r, sync));
  const a = assess(rows, { timeMachine: await tm() });
  return a ? [{ id: 'work', ...a }] : [];
}

module.exports = { check, assess, syncRoots, gitRepos, inspectRoot };
