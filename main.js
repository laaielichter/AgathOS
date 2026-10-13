// AgathOS - main process.
// Window, system tray, notifications, the pause hotkey and the bridge to the engine.
// Security first: no Node in the page, strict isolation, only whitelisted IPC calls.
const { app, BrowserWindow, shell, ipcMain, Tray, Menu, Notification, nativeImage, globalShortcut, dialog } = require('electron');
const path = require('path');
const { Store } = require('./core/store');
const { Engine } = require('./core/engine');
const api = require('./core/api');
const guard = require('./core/guard');
const judge = require('./core/judge');
const { I18N } = require('./src/i18n.js');

const THEMES = {
  dark: { color: '#0D1020', symbolColor: '#E8EBF5' },
  light: { color: '#F2F3F8', symbolColor: '#151A2E' },
};

let win = null;
let tray = null;
let engine = null;
let store = null;
let quitting = false;
let apiServer = null;
let uiLang = 'en';
let trayPaused = null;
let trayLive = null;

// Only one AgathOS at a time.
if (!app.requestSingleInstanceLock()) { app.quit(); }
app.on('second-instance', () => showWindow());
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
    titleBarStyle: 'hidden', titleBarOverlay: { ...theme, height: 40 },
    show: false,
    webPreferences: { preload: path.join(__dirname, 'preload.js'), contextIsolation: true, nodeIntegration: false, sandbox: true },
  });
  win.once('ready-to-show', () => { if (!process.argv.includes('--hidden')) win.show(); });
  win.loadFile(path.join(__dirname, 'src', 'index.html'));
  win.webContents.setWindowOpenHandler(({ url }) => { if (url.startsWith('https://')) shell.openExternal(url); return { action: 'deny' }; });
  win.webContents.on('will-navigate', (e) => e.preventDefault());
  win.on('close', (e) => {
    if (!quitting && store.settings.closeToTray && store.settings.realtime) { e.preventDefault(); win.hide(); }
  });
}

function showWindow(view) {
  if (!win) return;
  if (win.isMinimized()) win.restore();
  win.show();
  win.focus();
  if (view) win.webContents.send('agathos:navigate', view);
}

// Windows gets the .ico with hand-made small sizes; elsewhere the PNG.
const ICON = path.join(__dirname, 'src', process.platform === 'win32' ? 'icon.ico' : 'icon.png');

function buildTray() {
  const img = process.platform === 'win32' ? nativeImage.createFromPath(ICON) : nativeImage.createFromPath(ICON).resize({ width: 16, height: 16 });
  if (!tray) {
    tray = new Tray(img);
    tray.on('click', () => showWindow());
  }
  tray.setToolTip('AgathOS');
  tray.setContextMenu(Menu.buildFromTemplate([
    { label: tt('tray.open'), click: () => showWindow() },
    { label: tt('tray.scan'), click: () => engine.fullScan('tray') },
    { label: tt('tray.live'), type: 'checkbox', checked: !!(store && store.settings.realtime), click: (item) => setLive(item.checked) },
    { type: 'separator' },
    engine && engine.pausedAll
      ? { label: tt('tray.resume'), click: () => engine.resumeAll() }
      : { label: tt('tray.pause'), click: () => engine.pauseAll('tray') },
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

function notify(e) {
  if (!Notification.isSupported()) return;
  const n = new Notification({ title: `${tt('notif.title')} · ${tt('state.' + e.sev)}`, body: eventText(e).slice(0, 220), icon: path.join(__dirname, 'src', 'icon.png'), silent: e.sev !== 'alarm' });
  n.on('click', () => showWindow(e.watcher === 'gate' ? 'mcp' : e.watcher === 'traps' || e.watcher === 'keys' ? 'files' : e.watcher === 'net' ? 'network' : 'agents'));
  n.show();
  if (store.settings.notify === 'ask' && e.sev === 'alarm') showWindow();
}

function applyOsSettings() {
  const s = store.settings;
  // Installed app: start AgathOS.exe itself. From source (npm start): electron.exe needs the app folder too.
  const args = app.isPackaged ? ['--hidden'] : [app.getAppPath(), '--hidden'];
  try { app.setLoginItemSettings({ openAtLogin: !!s.startWithWindows, args }); } catch (_) {}
  globalShortcut.unregisterAll();
  if (s.hotkey) {
    globalShortcut.register('Control+Alt+Shift+P', () => {
      if (engine.pausedAll) engine.resumeAll(); else engine.pauseAll('hotkey');
    });
  }
  if (s.api && !apiServer) apiServer = api.start(engine, store.dir);
  if (!s.api && apiServer) { apiServer.close(); apiServer = null; }
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
    const r = await dialog.showMessageBox(win, { type: 'warning', buttons: [tt('btn.kill'), tt('cancel')], defaultId: 1, cancelId: 1, message: tt('confirm.kill', { name }) });
    return r.response === 0 ? engine.killAgent(String(id)) : { ok: false, cancelled: true };
  });
  h('block', (id, on) => engine.blockAgent(String(id), on !== false));
  h('localOnly', (port, on) => engine.localOnly(Number(port), on !== false));
  h('lockdown', (on) => engine.lockdown(!!on));
  h('trust', (target) => engine.trust(target));
  h('fixPlan', () => engine.fixPlan());
  h('fixApply', (picks) => engine.fixApply(Array.isArray(picks) ? picks.slice(0, 200).map((p) => ({ id: String(p && p.id), action: String(p && p.action) })) : []));
  h('fixUndo', (rid) => engine.fixUndo(String(rid)));
  h('settings', (patch) => {
    const s = store.updateSettings(patch || {});
    engine.applySchedule();
    applyOsSettings();
    engine.changed(true);
    return s;
  });
  h('ui', (patch) => {
    store.state.ui = { ...(store.state.ui || {}), ...(patch || {}) };
    store.saveState();
    if (patch && patch.lang && I18N[patch.lang]) { uiLang = patch.lang; buildTray(); }
    if (patch && patch.theme && THEMES[patch.theme] && win) {
      try { win.setTitleBarOverlay({ ...THEMES[patch.theme], height: 40 }); win.setBackgroundColor(THEMES[patch.theme].color); } catch (_) {}
    }
    return store.state.ui;
  });
  h('uiState', () => store.state.ui || {});
  h('verifyLog', () => store.verify());
  h('rollback', () => engine.intent.rollbackBaseline());
  h('forget', () => { engine.intent.resetBaseline(); return true; });
  h('judgeModels', () => judge.models());
  h('guardInstall', async () => { const ok = await guard.install(__dirname.replace(/app\.asar$/, 'app.asar.unpacked')); engine.guardState.installed = guard.installed(); engine.changed(true); return { ok }; });
  h('guardUninstall', async () => { const ok = await guard.uninstall(); engine.guardState = { installed: guard.installed(), running: false, sysmon: false, elevated: false, seq: 0 }; engine.changed(true); return { ok }; });
  h('addFolder', async (kind) => {
    const r = await dialog.showOpenDialog(win, { properties: ['openDirectory'] });
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
  h('reveal', (p) => { if (typeof p === 'string' && path.isAbsolute(p)) shell.showItemInFolder(p); return true; });
}

app.whenReady().then(async () => {
  store = new Store(path.join(app.getPath('userData'), 'data'));
  uiLang = (store.state.ui && store.state.ui.lang) || ((app.getLocale() || 'en').slice(0, 2) in I18N ? app.getLocale().slice(0, 2) : 'en');
  engine = new Engine(store, {
    appDir: __dirname,
    onUpdate: (snap) => {
      if (win && !win.isDestroyed()) win.webContents.send('agathos:update', snap);
      if (tray && (snap.pausedAll !== trayPaused || snap.settings.realtime !== trayLive)) { trayPaused = snap.pausedAll; trayLive = snap.settings.realtime; buildTray(); }
    },
    notify,
  });
  wireIpc();
  createWindow();
  buildTray();
  await engine.start();
  applyOsSettings();
  buildTray();
});

app.on('before-quit', () => { quitting = true; });
app.on('will-quit', () => { globalShortcut.unregisterAll(); if (engine) engine.stop(); });
app.on('window-all-closed', () => { if (process.platform !== 'darwin' && (quitting || !store || !store.settings.closeToTray)) app.quit(); });
