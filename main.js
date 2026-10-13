// AgathOS - main process
// Opens the app window. Security first: no Node in the page, strict isolation.
const { app, BrowserWindow, shell, ipcMain } = require('electron');
const path = require('path');

const THEMES = {
  dark: { color: '#0D1020', symbolColor: '#E8EBF5' },
  light: { color: '#F2F3F8', symbolColor: '#151A2E' },
};
const BG = THEMES.dark.color;
const TEXT = THEMES.dark.symbolColor;

function createWindow() {
  const win = new BrowserWindow({
    width: 1280,
    height: 820,
    minWidth: 980,
    minHeight: 640,
    backgroundColor: BG,
    title: 'AgathOS',
    icon: path.join(__dirname, 'src', 'icon.png'),
    titleBarStyle: 'hidden',
    titleBarOverlay: { color: BG, symbolColor: TEXT, height: 40 },
    show: false,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });

  win.once('ready-to-show', () => win.show());
  win.loadFile(path.join(__dirname, 'src', 'index.html'));

  // Never let the page open new windows; open real links in the normal browser.
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (url.startsWith('https://')) shell.openExternal(url);
    return { action: 'deny' };
  });
  win.webContents.on('will-navigate', (e) => e.preventDefault());
}

// Keep the Windows title bar buttons in the same colours as the app.
ipcMain.on('agathos:theme', (event, theme) => {
  const win = BrowserWindow.fromWebContents(event.sender);
  const t = THEMES[theme];
  if (!win || !t) return;
  try {
    win.setTitleBarOverlay({ ...t, height: 40 });
    win.setBackgroundColor(t.color);
  } catch (_) { /* not supported on this platform */ }
});

app.whenReady().then(() => {
  createWindow();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});
