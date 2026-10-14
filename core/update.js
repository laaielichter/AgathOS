'use strict';
// AgathOS - updates from GitHub Releases.
// Checks the latest release of the repository in package.json ("agathos.updateRepo").
// Windows (installed app): downloads the installer, checks its SHA-256 against the checksum
// GitHub publishes for the file, and only then runs it silently and restarts AgathOS.
// Mac, or running from source: opens the download page.
// A private repository cannot be read without a login; then the check reports "unreachable".
const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');
const crypto = require('crypto');
const cp = require('child_process');

const pkg = require('../package.json');
const REPO = (pkg.agathos && pkg.agathos.updateRepo) || '';
const CURRENT = pkg.version;

function cmp(a, b) {
  const pa = String(a).replace(/^v/, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  const pb = String(b).replace(/^v/, '').split(/[.-]/).map((x) => parseInt(x, 10) || 0);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (pa[i] || 0) - (pb[i] || 0); if (d) return d; }
  return 0;
}

function request(url, { json = false, file = null, maxRedirects = 5, timeout = 20000 } = {}) {
  return new Promise((settle) => {
    // Answer once. A connection that breaks half way never ends the stream, so the end of the
    // stream alone is not enough: without the 'close' check below the answer would never come.
    let answered = false;
    const resolve = (v) => { if (!answered) { answered = true; settle(v); } };
    if (!/^https:\/\//.test(url)) { resolve(null); return; }
    const req = https.get(url, { headers: { 'User-Agent': `AgathOS/${CURRENT}`, Accept: json ? 'application/vnd.github+json' : 'application/octet-stream' }, timeout }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && maxRedirects > 0) {
        res.resume();
        let next = null;
        try { next = new URL(res.headers.location, url).toString(); } catch (_) { /* not a web address */ }
        if (!next) { resolve(null); return; }
        request(next, { json, file, maxRedirects: maxRedirects - 1, timeout }).then(resolve);
        return;
      }
      if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
      let out = null;
      res.on('error', () => resolve(null));
      res.on('close', () => { if (!res.complete) { if (out) out.destroy(); resolve(null); } });
      if (file) {
        const hash = crypto.createHash('sha256');
        out = fs.createWriteStream(file);
        res.on('data', (d) => hash.update(d));
        res.pipe(out);
        out.on('finish', () => resolve({ sha256: hash.digest('hex') }));
        out.on('error', () => resolve(null));
        return;
      }
      const chunks = [];
      let size = 0;
      res.on('data', (d) => { size += d.length; if (size < 2 * 1024 * 1024) chunks.push(d); });
      res.on('end', () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch (_) { resolve(null); } });
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(null));
  });
}

// A release tag becomes part of a file name, so only a plain version number is accepted.
const SAFE_VERSION = /^\d+(\.\d+){0,3}([-+][0-9A-Za-z.]{1,30})?$/;

async function check() {
  if (!REPO) return { status: 'unreachable', current: CURRENT, at: Date.now() };
  const rel = await request(`https://api.github.com/repos/${REPO}/releases/latest`, { json: true });
  if (!rel || !rel.tag_name) return { status: 'unreachable', current: CURRENT, at: Date.now() };
  const version = String(rel.tag_name).replace(/^v/, '');
  if (!SAFE_VERSION.test(version)) return { status: 'unreachable', current: CURRENT, at: Date.now() };
  const assets = (Array.isArray(rel.assets) ? rel.assets : []).filter((a) => a && typeof a === 'object')
    .map((a) => ({ name: String(a.name || ''), url: a.browser_download_url, size: a.size, digest: a.digest || null }));
  return { status: cmp(version, CURRENT) > 0 ? 'newer' : 'latest', current: CURRENT, version, page: rel.html_url, assets, at: Date.now() };
}

// Which installer of a release belongs to this computer. A Windows PC with an ARM chip (Snapdragon) can run the Intel installer too,
// but slower, so the ARM one is taken when the release has it and GitHub published its checksum. The ARM installer has a name that
// the older versions of AgathOS do not match, so they keep taking the Intel one.
const SETUP_X64 = /^AgathOS-Setup-.*\.exe$/i;
const SETUP_ARM64 = /^AgathOS-Windows-ARM64-Setup-.*\.exe$/i;
const HAS_SUM = /^sha256:[a-f0-9]{64}$/i;
function pickInstaller(info, arch = process.arch) {
  const assets = ((info && info.assets) || []).filter((a) => a && typeof a === 'object');
  if (arch === 'arm64') {
    const arm = assets.find((a) => SETUP_ARM64.test(a.name) && HAS_SUM.test(a.digest || ''));
    if (arm) return arm;
  }
  return assets.find((a) => SETUP_X64.test(a.name)) || null;
}

// Windows installer: download, verify, run silently (/S) and start AgathOS again (--force-run).
async function install(info) {
  if (process.platform !== 'win32' || !info || info.status !== 'newer') return { ok: false, reason: 'page' };
  const asset = pickInstaller(info);
  const want = asset && /^sha256:([a-f0-9]{64})$/i.exec(asset.digest || '');
  // Without a published checksum we do not run anything: the download page opens instead.
  if (!asset || !want) return { ok: false, reason: 'page' };
  const file = path.join(os.tmpdir(), `AgathOS-Setup-${info.version}.exe`);
  const got = await request(asset.url, { file, timeout: 120000 });
  if (!got || got.sha256.toLowerCase() !== want[1].toLowerCase()) { try { fs.unlinkSync(file); } catch (_) {} return { ok: false, reason: 'checksum' }; }
  // AgathOS only closes itself once the installer has really started. If it cannot start (a virus
  // scanner blocks it, say), AgathOS keeps running and the update is reported as failed.
  const started = await new Promise((done) => {
    let child;
    try { child = cp.spawn(file, ['/S', '--force-run'], { detached: true, stdio: 'ignore', windowsHide: true }); } catch (_) { done(false); return; }
    child.once('error', () => done(false));
    child.once('spawn', () => { try { child.unref(); } catch (_) { /* already gone */ } done(true); });
  });
  if (!started) { try { fs.unlinkSync(file); } catch (_) { /* nothing to remove */ } return { ok: false, reason: 'start' }; }
  return { ok: true };
}

// ---------- updating by itself ----------
const RETRY_MS = 20 * 60 * 1000;   // not a quiet moment: look again 20 minutes later

// A quiet moment: no agent running (a frozen agent would stay frozen if AgathOS restarts),
// no scan busy, nothing paused, and the AgathOS window not in use.
function calmMoment(s) {
  return !s.runningAgents && !s.scanning && !s.windowInUse && !s.paused;
}

// Can this app put the new version on by itself? Only the installed Windows app can, and only when
// GitHub publishes a SHA-256 checksum for the installer. Anything else opens the download page.
function canSelfInstall(info, platform = process.platform, packaged = false, arch = process.arch) {
  if (platform !== 'win32' || !packaged || !info || info.status !== 'newer') return false;
  const asset = pickInstaller(info, arch);
  return !!asset && HAS_SUM.test(asset.digest || '');
}

// A look that failed (offline, GitHub busy) must not wipe out an update that was found before.
function keepKnown(prev, fresh) {
  if (fresh && fresh.status === 'unreachable' && prev && prev.status === 'newer' && prev.current === fresh.current) return prev;
  return fresh;
}

// What to do with a new version: 'skip' (not for this app, setting or version),
// 'wait' (try again in RETRY_MS) or 'go' (tell the user quietly, then install).
function autoDecision({ platform, packaged, autoUpdate, info, failedVersion, calm }) {
  if (platform !== 'win32' || !packaged || autoUpdate === false) return 'skip';
  if (!info || info.status !== 'newer' || info.version === failedVersion) return 'skip';
  // Without a published SHA-256 checksum nothing runs by itself; the download page stays a manual step.
  if (!canSelfInstall(info, platform, packaged)) return 'skip';
  return calm ? 'go' : 'wait';
}

module.exports = { check, install, pickInstaller, cmp, calmMoment, autoDecision, canSelfInstall, keepKnown, RETRY_MS, REPO, CURRENT };
