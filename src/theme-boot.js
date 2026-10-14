// AgathOS - puts the saved look on the page before it is drawn, so a black (Stealth) window
// never flashes dark blue first. The page itself (app.js) takes over a moment later.
(() => {
  try {
    const s = JSON.parse(localStorage.getItem('agathos-ui') || '{}');
    if (s && (s.theme === 'light' || s.theme === 'stealth')) document.documentElement.dataset.theme = s.theme;
  } catch (_) { /* nothing saved: the page starts dark */ }
})();
