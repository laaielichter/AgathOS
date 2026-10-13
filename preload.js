// AgathOS - preload
// The bridge between the window and the main process. In step 1 it only
// exposes version info and the theme switch; the real scanner arrives in step 2.
const { contextBridge, ipcRenderer } = require('electron');

contextBridge.exposeInMainWorld('agathos', {
  version: '0.1.0',
  platform: process.platform,
  demo: true,
  setTheme: (theme) => ipcRenderer.send('agathos:theme', theme === 'light' ? 'light' : 'dark'),
});
