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
const { spawn } = require('child_process');

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
  return new Promise((resolve) => {
    if (!/^https:\/\//.test(url)) { resolve(null); return; }
    const req = https.get(url, { headers: { 'User-Agent': `AgathOS/${CURRENT}`, Accept: json ? 'application/vnd.github+json' : 'application/octet-stream' }, timeout }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location && maxRedirects > 0) {
        res.resume();
        request(new URL(res.headers.location, url).toString(), { json, file, maxRedirects: maxRedirects - 1, timeout }).then(resolve);
        return;
      }
      if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
      if (file) {
        const hash = crypto.createHash('sha256');
        const out = fs.createWriteStream(file);
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

async function check() {
  if (!REPO) return { status: 'unreachable', current: CURRENT, at: Date.now() };
  const rel = await request(`https://api.github.com/repos/${REPO}/releases/latest`, { json: true });
  if (!rel || !rel.tag_name) return { status: 'unreachable', current: CURRENT, at: Date.now() };
  const version = String(rel.tag_name).replace(/^v/, '');
  const assets = (rel.assets || []).map((a) => ({ name: a.name, url: a.browser_download_url, size: a.size, digest: a.digest || null }));
  return { status: cmp(version, CURRENT) > 0 ? 'newer' : 'latest', current: CURRENT, version, page: rel.html_url, assets, at: Date.now() };
}

// Windows installer: download, verify, run silently (/S) and start AgathOS again (--force-run).
async function install(info) {
  if (process.platform !== 'win32' || !info || info.status !== 'newer') return { ok: false, reason: 'page' };
  const asset = (info.assets || []).find((a) => /^AgathOS-Setup-.*\.exe$/i.test(a.name));
  const want = asset && /^sha256:([a-f0-9]{64})$/i.exec(asset.digest || '');
  // Without a published checksum we do not run anything: the download page opens instead.
  if (!asset || !want) return { ok: false, reason: 'page' };
  const file = path.join(os.tmpdir(), `AgathOS-Setup-${info.version}.exe`);
  const got = await request(asset.url, { file, timeout: 120000 });
  if (!got || got.sha256.toLowerCase() !== want[1].toLowerCase()) { try { fs.unlinkSync(file); } catch (_) {} return { ok: false, reason: 'checksum' }; }
  try {
    const child = spawn(file, ['/S', '--force-run'], { detached: true, stdio: 'ignore', windowsHide: true });
    child.unref();
  } catch (_) { return { ok: false, reason: 'start' }; }
  return { ok: true };
}

// ---------- updating by itself ----------
const RETRY_MS = 20 * 60 * 1000;   // not a quiet moment: look again 20 minutes later

// A quiet moment: no agent running (a frozen agent would stay frozen if AgathOS restarts),
// no scan busy, nothing paused, and the AgathOS window not in use.
function calmMoment(s) {
  return !s.runningAgents && !s.scanning && !s.windowInUse && !s.paused;
}

// What to do with a new version: 'skip' (not for this app, setting or version),
// 'wait' (try again in RETRY_MS) or 'go' (tell the user quietly, then install).
function autoDecision({ platform, packaged, autoUpdate, info, failedVersion, calm }) {
  if (platform !== 'win32' || !packaged || autoUpdate === false) return 'skip';
  if (!info || info.status !== 'newer' || info.version === failedVersion) return 'skip';
  const asset = (info.assets || []).find((a) => /^AgathOS-Setup-.*\.exe$/i.test(a.name));
  // Without a published SHA-256 checksum nothing runs by itself; the download page stays a manual step.
  if (!asset || !/^sha256:[a-f0-9]{64}$/i.test(asset.digest || '')) return 'skip';
  return calm ? 'go' : 'wait';
}

module.exports = { check, install, cmp, calmMoment, autoDecision, RETRY_MS, REPO, CURRENT };
