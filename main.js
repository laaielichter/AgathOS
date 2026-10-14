// AgathOS - main process.
// Window, system tray, notifications, the pause hotkey and the bridge to the engine.
// Security first: no Node in the page, strict isolation, only whitelisted IPC calls.
const { app, BrowserWindow, shell, ipcMain, Tray, Menu, Notification, nativeImage, globalShortcut, dialog, screen, clipboard } = require('electron');
const fs = require('fs');
const path = require('path');
const { Store } = require('./core/store');
const { Engine } = require('./core/engine');
const api = require('./core/api');
const guard = require('./core/guard');
const judge = require('./core/judge');
const updater = require('./core/update');
const report = require('./core/report');
const { checkText } = require('./core/textscan');
const { Notifier } = require('./core/notifier');
const errlog = require('./core/errlog');
const { I18N } = require('./src/i18n.js');

const THEMES = {
  dark: { color: '#0D1020', symbolColor: '#E8EBF5' },
  light: { color: '#F2F3F8', symbolColor: '#151A2E' },
};

const IS_MAC = process.platform === 'darwin';
let win = null;
let mini = null;          // the small pop-up above the tray icon (Windows)
let miniHiddenAt = 0;
let tray = null;
let engine = null;
let store = null;
let quitting = false;
let apiServer = null;
let uiLang = 'en';
let trayPaused = null;
let trayLive = null;
let trayState = null;     // calm | watch | alarm | paused: the tray icon shows it
let updateInfo = null;    // last update check

// Only one AgathOS at a time. A second copy quits at once and must not start an engine of its own.
const gotLock = app.requestSingleInstanceLock();
if (!gotLock) app.quit();
// Errors nobody caught go to a small log file instead of an error box (core/errlog.js).
try { errlog.install(path.join(app.getPath('userData'), 'data')); } catch (_) { /* no log, but still running */ }
app.on('second-instance', () => showWindow());
app.on('activate', () => showWindow());   // macOS: clicking the Dock icon
// Must match the installer's appId, or Windows drops the notifications.
app.setAppUserModelId(app.isPackaged ? 'io.agathos.app' : process.execPath);

const tt = (key, params = {}) => {
  const s = (I18N[uiLang] && I18N[uiLang][key]) || I18N.en[key] || key;
  return s.replace(/\{(\w+)\}/g, (_, k) => (k in params ? params[k] : ''));
};

function createWindow() {
  const theme = THEMES[(store.state.ui && store.state.ui.theme) || 'dark'] || THEMES.dark;
  win = new BrowserWindow({
    width: 1320, height: 860, minWidth: 1000, minHeight: 660,
    backgroundColor: theme.color, title: 'AgathOS',
    icon: ICON,
    // Windows: own title bar with the system buttons drawn on top. Mac: the traffic lights in our title bar.
    ...(IS_MAC ? { titleBarStyle: 'hiddenInset', trafficLightPosition: { x: 14, y: 13 } } : { titleBarStyle: 'hidden', titleBarOverlay: { ...theme, height: 40 } }),
    show: false,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  // Windows starts us with --hidden. On a Mac the system only says "opened at login" (the older "opened as hidden" is gone).
  const hidden = process.argv.includes('--hidden') || (IS_MAC && (() => { try { return !!app.getLoginItemSettings().wasOpenedAtLogin; } catch (_) { return false; } })());
  win.once('ready-to-show', () => { if (!hidden) win.show(); });
  win.loadFile(path.join(__dirname, 'src', 'index.html'));
  win.webContents.setWindowOpenHandler(({ url }) => { if (url.startsWith('https://')) shell.openExternal(url); return { action: 'deny' }; });
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.on('close', (e) => {
    if (!quitting && store.settings.closeToTray && store.settings.realtime) { e.preventDefault(); win.hide(); }
  });
}

// ---------- mini pop-up next to the clock ----------
// A left click on the tray icon opens a small window right above it, like the Windows
// volume or Wi-Fi flyouts. It closes as soon as you click somewhere else.
const MINI_W = 340;
const MINI_H = 468;
function createMini() {
  const theme = THEMES[(store.state.ui && store.state.ui.theme) || 'dark'] || THEMES.dark;
  mini = new BrowserWindow({
    width: MINI_W, height: MINI_H, show: false, frame: false, resizable: false, movable: false, minimizable: false, maximizable: false,
    fullscreenable: false, skipTaskbar: true, alwaysOnTop: true, backgroundColor: theme.color, title: 'AgathOS',
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  mini.loadFile(path.join(__dirname, 'src', 'mini.html'));
  mini.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  mini.webContents.on('will-navigate', (e) => e.preventDefault());
  mini.on('blur', () => { if (mini && mini.isVisible()) { mini.hide(); miniHiddenAt = Date.now(); } });
  mini.on('closed', () => { mini = null; });
}
function placeMini() {
  const tb = tray.getBounds();
  const point = tb.width ? { x: Math.round(tb.x + tb.width / 2), y: Math.round(tb.y + tb.height / 2) } : screen.getCursorScreenPoint();
  const d = screen.getDisplayNearestPoint(point);
  const wa = d.workArea;
  const b = d.bounds;
  const gap = 10;
  let x = Math.round(point.x - MINI_W / 2);
  let y = wa.y + wa.height - MINI_H - gap;                         // taskbar at the bottom (normal)
  if (wa.y > b.y) y = wa.y + gap;                                    // taskbar at the top
  if (wa.x > b.x) { x = wa.x + gap; y = Math.round(point.y - MINI_H / 2); }                 // left
  else if (wa.width < b.width && wa.x === b.x && point.x > wa.x + wa.width) { x = wa.x + wa.width - MINI_W - gap; y = Math.round(point.y - MINI_H / 2); } // right
  x = Math.min(Math.max(x, wa.x + gap), wa.x + wa.width - MINI_W - gap);
  y = Math.min(Math.max(y, wa.y + gap), wa.y + wa.height - MINI_H - gap);
  mini.setBounds({ x, y, width: MINI_W, height: MINI_H });
}
function toggleMini() {
  if (!mini) createMini();
  if (mini.isVisible()) { mini.hide(); return; }
  // The click that blurred the pop-up is the same click on the icon: do not reopen it.
  if (Date.now() - miniHiddenAt < 250) return;
  placeMini();
  mini.webContents.send('agathos:navigate', 'refresh');
  if (engine) mini.webContents.send('agathos:update', engine.snapshot());
  mini.show();
  mini.focus();
}

// The window to put a dialog on, or nothing when it is gone (a destroyed window cannot be a parent).
const parentWin = () => (win && !win.isDestroyed() ? win : undefined);

function showWindow(view) {
  if (mini && !mini.isDestroyed() && mini.isVisible()) mini.hide();
  // Mac: closing the window does not quit the app. A click on the Dock icon then needs a new window.
  const fresh = !!store && (!win || win.isDestroyed());
  if (fresh) createWindow();
  if (!win || win.isDestroyed()) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
  if (!view) return;
  // A window that was just made has not loaded its page yet: wait, or the request is lost.
  if (fresh) win.webContents.once('did-finish-load', () => { if (win && !win.isDestroyed()) win.webContents.send('agathos:navigate', view); });
  else win.webContents.send('agathos:navigate', view);
}

// Windows gets the .ico with hand-made small sizes; elsewhere the PNG.
const ICON = path.join(__dirname, 'src', process.platform === 'win32' ? 'icon.ico' : 'icon.png');

function trayImage(state) {
  // Windows: the icon carries a small coloured dot for attention, danger or paused.
  if (process.platform === 'win32') return nativeImage.createFromPath(state && state !== 'calm' ? path.join(__dirname, 'src', `tray-${state}.ico`) : ICON);
  // macOS menu bar: a black "Template" image that the system tints for light and dark menu bars.
  if (IS_MAC) { const t = nativeImage.createFromPath(path.join(__dirname, 'src', 'trayTemplate.png')); t.setTemplateImage(true); return t; }
  return nativeImage.createFromPath(ICON).resize({ width: 16, height: 16 });
}

// Notifications can be paused for a while; danger still comes through.
const snoozed = () => !!(store && store.state.snoozeUntil && Date.now() < store.state.snoozeUntil);
function snooze(ms) {
  store.state.snoozeUntil = ms ? Date.now() + ms : 0;
  store.saveState();
  buildTray();
  engine.changed(true);
}
function untilTomorrow() {
  const d = new Date();
  d.setDate(d.getDate() + 1);
  d.setHours(8, 0, 0, 0);
  return d.getTime() - Date.now();
}

function statusText(snap) {
  if (!snap || !snap.watchers) return '';
  if (snap.pausedAll) return tt('status.paused');
  const n = snap.watchers.filter((w) => w.state !== 'calm').length;
  return n === 0 ? tt('status.calm') : n === 1 ? tt('status.one') : tt('status.many', { n });
}

function buildTray() {
  const img = trayImage(trayState);
  if (!tray) {
    tray = new Tray(img);
    // Windows: left click = the mini pop-up, double click = the full window, right click = menu.
    if (process.platform === 'win32') {
      tray.on('click', () => toggleMini());
      tray.on('double-click', () => showWindow());
    } else {
      tray.on('click', () => showWindow());
    }
  }
  tray.setImage(img);
  tray.setToolTip(engine ? `AgathOS · ${statusText(engine.lastSnap)}`.slice(0, 120) : 'AgathOS');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: tt('tray.open'), click: () => showWindow() },
    { label: tt('tray.scan'), click: () => engine.fullScan('tray') },
    { label: tt('tray.check'), click: () => showWindow('check') },
    { label: tt('tray.live'), type: 'checkbox', checked: !!(store && store.settings.realtime), click: (item) => setLive(item.checked) },
    { type: 'separator' },
    engine && engine.pausedAll
      ? { label: tt('tray.resume'), click: () => engine.resumeAll() }
      : { label: tt('tray.pause'), click: () => engine.pauseAll('tray') },
    { type: 'separator' },
    snoozed()
      ? { label: tt('tray.snoozeOff'), click: () => snooze(0) }
      : { label: tt('tray.snooze'), submenu: [
        { label: tt('set.snooze1h'), click: () => snooze(3600 * 1000) },
        { label: tt('set.snoozeTomorrow'), click: () => snooze(untilTomorrow()) },
      ] },
    ...(updateInfo && updateInfo.status === 'newer' ? [{ label: tt('upd.available', { v: updateInfo.version }), click: () => installUpdate() }] : []),
    { type: 'separator' },
    { label: tt('tray.quit'), click: () => { quitting = true; app.quit(); } },
  ]));
}

// The live scanner switch (window, tray and API all end up here).
function setLive(on) {
  store.updateSettings({ realtime: !!on });
  engine.applySchedule();
  applyOsSettings();
  engine.changed(true);
}

function eventText(e) {
  const p = { ...(e.params || {}) };
  if (p.fix) p.fix = tt('fixact.' + p.fix);
  return tt(e.key, p).replace(/\s+/g, ' ').trim();
}

// Calm notifications: core/notifier.js decides what pops up, bundles bursts and keeps a limit.
const viewOf = (e) => (e.watcher === 'gate' ? 'mcp' : e.watcher === 'traps' || e.watcher === 'keys' ? 'files' : e.watcher === 'net' ? 'network' : 'agents');
function showNotification(events, { sound, overflow }) {
  if (!Notification.isSupported() || !events.length) return;
  const first = events[0];
  const title = overflow ? tt('notif.title') : events.length > 1 ? `${tt('notif.title')} · ${tt('notif.bundle', { n: events.length })}` : `${tt('notif.title')} · ${tt('state.' + first.sev)}`;
  const body = overflow ? tt('notif.more') : events.length > 1 ? events.slice(0, 3).map((x) => `• ${eventText(x)}`).join('\n').slice(0, 300) : eventText(first).slice(0, 220);
  const n = new Notification({ title, body, icon: path.join(__dirname, 'src', 'icon.png'), silent: !sound });
  n.on('click', () => showWindow(overflow || events.length > 1 ? 'overview' : viewOf(first)));
  // Mac (Electron 42 and newer): a notification fails when the app is not code signed or the system blocks it.
  // Then the Dock icon bounces instead, so a danger message is not lost silently.
  n.on('failed', () => { try { if (IS_MAC && app.dock && !(win && !win.isDestroyed() && win.isFocused())) app.dock.bounce(first.sev === 'alarm' ? 'critical' : 'informational'); } catch (_) { /* no Dock */ } });
  n.show();
  if (store.settings.notify === 'ask' && first.sev === 'alarm' && !overflow) showWindow();
}
let notifier = null;
function notify(e) {
  if (!notifier) {
    notifier = new Notifier({
      show: showNotification,
      settings: () => store.settings,
      snoozed,
      windowFocused: () => !!(win && !win.isDestroyed() && win.isVisible() && win.isFocused()),
    });
  }
  notifier.push(e);
}

function applyOsSettings() {
  const s = store.settings;
  // Installed app: start AgathOS.exe itself. From source (npm start): electron.exe needs the app folder too.
  const args = app.isPackaged ? ['--hidden'] : [app.getAppPath(), '--hidden'];
  try { app.setLoginItemSettings(IS_MAC ? { openAtLogin: !!s.startWithWindows } : { openAtLogin: !!s.startWithWindows, args }); } catch (_) {}
  globalShortcut.unregisterAll();
  if (s.hotkey) {
    globalShortcut.register('Control+Alt+Shift+P', () => {
      if (engine.pausedAll) engine.resumeAll(); else engine.pauseAll('hotkey');
    });
  }
  if (s.api && !apiServer) apiServer = api.start(engine, store.dir);
  if (!s.api && apiServer) { apiServer.close(); apiServer = null; }
}

// ---------- updates from GitHub Releases ----------
async function checkUpdate(manual = false) {
  if (!manual && !store.settings.updates) return updateInfo;
  const before = updateInfo && updateInfo.version;
  updateInfo = await updater.check();
  if (engine) { engine.update = updateInfo; engine.changed(true); }
  if (updateInfo.status === 'newer' && updateInfo.version !== before && !manual) {
    engine.event({ key: 'upd.event', sev: 'watch', watcher: 'gate', params: { v: updateInfo.version } });
  }
  buildTray();
  if (!manual) scheduleAutoUpdate(0);
  return updateInfo;
}

// Updating by itself (Windows, installed app): only at a quiet moment, after a calm notice,
// and only with a verified SHA-256 checksum. Not quiet? Look again 20 minutes later.
let autoTimer = null;
let autoFailed = null;       // version that failed once: not tried again until a newer one appears
let autoNotified = null;     // version we already told the user about
function scheduleAutoUpdate(ms) {
  clearTimeout(autoTimer);
  autoTimer = setTimeout(() => autoUpdateTick().catch(() => {}), ms);
}
let autoBusy = false;        // one self-update at a time (a settings change must not start a second download)
async function autoUpdateTick() {
  if (!engine || !store || autoBusy) return;
  autoBusy = true;
  try { await autoUpdateRun(); } finally { autoBusy = false; }
}
async function autoUpdateRun() {
  const decide = () => updater.autoDecision({
    platform: process.platform, packaged: app.isPackaged, autoUpdate: store.settings.autoUpdate, info: updateInfo, failedVersion: autoFailed,
    calm: updater.calmMoment({
      runningAgents: engine.procs.runningAgents().length,
      scanning: !!engine.scanning,
      windowInUse: !!((win && !win.isDestroyed() && win.isVisible() && win.isFocused()) || (mini && !mini.isDestroyed() && mini.isVisible())),
      paused: !!engine.pausedAll,
    }),
  });
  let d = decide();
  if (d === 'wait') { scheduleAutoUpdate(updater.RETRY_MS); return; }
  if (d !== 'go') return;
  const v = updateInfo.version;
  if (autoNotified !== v) {
    autoNotified = v;
    engine.event({ key: 'upd.auto', sev: 'calm', watcher: 'gate', params: { v } });
    if (Notification.isSupported()) new Notification({ title: tt('notif.title'), body: tt('upd.auto', { v }), icon: path.join(__dirname, 'src', 'icon.png'), silent: true }).show();
  }
  await new Promise((r) => setTimeout(r, 20000));      // a moment to read it, and to see that it is still quiet
  d = decide();
  if (d === 'wait') { scheduleAutoUpdate(updater.RETRY_MS); return; }
  if (d !== 'go') return;
  const r = await installUpdate();
  if (r && r.reason === 'busy') return;
  if (!r || r.ok === false) {
    autoFailed = v;
    engine.event({ key: 'upd.autoFailed', sev: 'watch', watcher: 'gate', params: { v } });
  }
}

let installing = false;
async function installUpdate() {
  if (!updateInfo || updateInfo.status !== 'newer') return { ok: false };
  if (installing) return { ok: false, reason: 'busy' };
  installing = true;
  try { return await installUpdateNow(); } finally { installing = false; }
}
async function installUpdateNow() {
  // Only the installed Windows app updates itself; otherwise open the download page.
  if (process.platform === 'win32' && app.isPackaged) {
    const r = await updater.install(updateInfo);
    if (r.ok) { quitting = true; setTimeout(() => app.quit(), 500); return { ok: true }; }
    if (r.reason !== 'page') return { ok: false, reason: r.reason };
  }
  if (updateInfo.page && /^https:\/\/github\.com\//.test(updateInfo.page)) shell.openExternal(updateInfo.page);
  return { ok: true, page: true };
}

// ---------- live view: a light push once a second, only while the window shows it ----------
let liveTimer = null;
let liveSince = 0;
function setLiveWatching(on, since) {
  clearInterval(liveTimer);
  liveTimer = null;
  if (!engine) return;
  if (!on) { engine.setLiveWatching(false); return; }
  liveSince = Number.isFinite(since) && since > 0 ? Math.floor(since) : 0;
  const tick = () => {
    const visible = !!(win && !win.isDestroyed() && win.isVisible() && !win.isMinimized());
    engine.setLiveWatching(visible);
    if (!visible) return;
    const v = engine.liveView(liveSince);
    liveSince = v.seq;
    win.webContents.send('agathos:live', v);
  };
  tick();
  liveTimer = setInterval(tick, 1000);
}

// ---------- IPC: a short, fixed list of calls ----------
function wireIpc() {
  const h = (name, fn) => ipcMain.handle(`agathos:${name}`, async (_e, ...args) => {
    try { return await fn(...args); } catch (err) { return { ok: false, error: String(err && err.message || err) }; }
  });
  h('snapshot', () => engine.snapshot());
  h('scan', () => engine.fullScan('user'));
  h('pauseAll', () => engine.pauseAll('user'));
  h('resumeAll', () => engine.resumeAll());
  h('freeze', (id) => engine.freezeAgent(String(id)));
  h('resume', (id) => engine.resumeAgent(String(id)));
  h('kill', async (id) => {
    const name = engine.agentName(String(id));
    const r = await dialog.showMessageBox(parentWin(), { type: 'warning', buttons: [tt('btn.kill'), tt('cancel')], defaultId: 1, cancelId: 1, message: tt('confirm.kill', { name }) });
    return r.response === 0 ? engine.killAgent(String(id)) : { ok: false, cancelled: true };
  });
  h('block', (id, on) => engine.blockAgent(String(id), on !== false));
  h('localOnly', (port, on) => engine.localOnly(Number(port), on !== false));
  h('lockdown', (on) => engine.lockdown(!!on));
  h('trust', (target) => engine.trust(target));
  h('fixPlan', () => engine.fixPlan());
  h('fixApply', (picks) => engine.fixApply(Array.isArray(picks) ? picks.slice(0, 200).map((p) => ({ id: String(p && p.id), action: String(p && p.action) })) : []));
  h('fixUndo', (rid) => engine.fixUndo(String(rid)));
  h('fixDismiss', (key) => engine.fixDismiss(String(key)));
  h('fixRestore', (key) => engine.fixRestore(String(key)));
  h('settings', (patch) => {
    const s = store.updateSettings(patch || {});
    engine.applySchedule();
    applyOsSettings();
    engine.changed(true);
    if (patch && 'autoUpdate' in patch && updateInfo && updateInfo.status === 'newer') scheduleAutoUpdate(5000);
    return s;
  });
  h('ui', (patch) => {
    store.state.ui = { ...(store.state.ui || {}), ...(patch || {}) };
    store.saveState();
    if (patch && patch.lang && I18N[patch.lang]) { uiLang = patch.lang; buildTray(); }
    if (patch && patch.theme && THEMES[patch.theme] && win) {
      try { if (!IS_MAC) win.setTitleBarOverlay({ ...THEMES[patch.theme], height: 40 }); win.setBackgroundColor(THEMES[patch.theme].color); } catch (_) {}
      try { if (mini) mini.setBackgroundColor(THEMES[patch.theme].color); } catch (_) {}
    }
    return store.state.ui;
  });
  h('uiState', () => ({ ...(store.state.ui || {}), snoozeUntil: store.state.snoozeUntil || 0, update: updateInfo, version: app.getVersion() }));
  // From the mini pop-up: open the full window (optionally on a page or the fix dialog).
  h('checkText', (text) => checkText(typeof text === 'string' ? text : ''));
  // Since Electron 44 the clipboard writes through a promise; older versions return nothing. Await handles both.
  h('copyText', async (text) => { if (typeof text !== 'string') return false; try { await clipboard.writeText(text); return true; } catch (_) { return false; } });
  h('snooze', (what) => { snooze(what === '1h' ? 3600 * 1000 : what === 'tomorrow' ? untilTomorrow() : 0); return store.state.snoozeUntil || 0; });
  h('saveReport', async () => {
    const d = new Date();
    const name = `AgathOS-report-${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}.html`;
    const r = await dialog.showSaveDialog(parentWin(), { defaultPath: path.join(app.getPath('documents'), name), filters: [{ name: 'HTML', extensions: ['html'] }] });
    if (r.canceled || !r.filePath) return { ok: false, cancelled: true };
    const snap = { ...engine.snapshot(), statusLine: statusText(engine.snapshot()) };
    const rtl = ['ar'].includes(uiLang);
    fs.writeFileSync(r.filePath, report.build(snap, tt, uiLang, rtl ? 'rtl' : 'ltr'), 'utf8');
    shell.showItemInFolder(r.filePath);
    return { ok: true };
  });
  h('checkUpdate', () => checkUpdate(true));
  h('installUpdate', () => installUpdate());
  h('openMain', (view) => { showWindow(typeof view === 'string' ? view : undefined); return true; });
  h('closeMini', () => { if (mini) mini.hide(); return true; });
  h('verifyLog', () => store.verify());
  h('rollback', () => engine.intent.rollbackBaseline());
  h('forget', () => { engine.intent.resetBaseline(); return true; });
  h('judgeModels', () => judge.models());
  h('guardInstall', async () => { if (process.platform !== 'win32') return { ok: false, unsupported: true }; const ok = await guard.install(__dirname.replace(/app\.asar$/, 'app.asar.unpacked')); engine.guardState.installed = guard.installed(); engine.changed(true); return { ok }; });
  h('guardUninstall', async () => { const ok = await guard.uninstall(); engine.guardState = { installed: guard.installed(), running: false, sysmon: false, elevated: false, seq: 0 }; engine.changed(true); return { ok }; });
  h('addFolder', async (kind) => {
    const r = await dialog.showOpenDialog(parentWin(), { properties: ['openDirectory'] });
    if (r.canceled || !r.filePaths[0]) return store.settings;
    const key = kind === 'models' ? 'modelDirs' : 'roots';
    const list = [...new Set([...store.settings[key], r.filePaths[0]])];
    store.updateSettings({ [key]: list });
    engine.applySchedule();
    return store.settings;
  });
  h('removeFolder', (kind, p) => {
    const key = kind === 'models' ? 'modelDirs' : 'roots';
    store.updateSettings({ [key]: store.settings[key].filter((x) => x !== p) });
    engine.applySchedule();
    return store.settings;
  });
  h('liveWatch', (on, since) => { setLiveWatching(on === true, Number(since) || 0); return true; });
  h('reveal', (p) => { if (typeof p === 'string' && path.isAbsolute(p)) shell.showItemInFolder(p); return true; });
}

app.whenReady().then(async () => {
  if (!gotLock) return;          // the second copy only passes the word on and quits
  store = new Store(path.join(app.getPath('userData'), 'data'));
  uiLang = (store.state.ui && store.state.ui.lang) || ((app.getLocale() || 'en').slice(0, 2) in I18N ? app.getLocale().slice(0, 2) : 'en');
  engine = new Engine(store, {
    appDir: __dirname,
    onUpdate: (snap) => {
      if (win && !win.isDestroyed()) win.webContents.send('agathos:update', snap);
      if (mini && !mini.isDestroyed() && mini.isVisible()) mini.webContents.send('agathos:update', snap);
      engine.lastSnap = snap;
      const st = snap.pausedAll ? 'paused' : snap.watchers.some((w) => w.state === 'alarm') ? 'alarm' : snap.watchers.some((w) => w.state === 'watch') ? 'watch' : 'calm';
      if (tray && (snap.pausedAll !== trayPaused || snap.settings.realtime !== trayLive || st !== trayState)) { trayPaused = snap.pausedAll; trayLive = snap.settings.realtime; trayState = st; buildTray(); }
    },
    notify,
  });
  wireIpc();
  createWindow();
  buildTray();
  // If the first scan fails, the rest still has to start: the tray, the watchers and the settings.
  try { await engine.start(); } catch (err) { errlog.record(path.join(app.getPath('userData'), 'data'), 'error', err); }
  applyOsSettings();
  buildTray();
  // First update check a minute after start, then once a day.
  setTimeout(() => checkUpdate().catch(() => {}), 60 * 1000);
  setInterval(() => checkUpdate().catch(() => {}), 24 * 3600 * 1000);
});

app.on('before-quit', () => { quitting = true; });
app.on('will-quit', () => { globalShortcut.unregisterAll(); if (engine) engine.stop(); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin' && (quitting || !store || !store.settings.closeToTray)) app.quit(); });
