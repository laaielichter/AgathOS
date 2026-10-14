'use strict';
// AgathOS - the looks of the window.
// Dark and Light are the standard ones. Palantyr is an extra look in the style of an operations
// console (pure black for OLED screens); it is switched on in Settings and is off until then.
// The colours here are the ones of the window itself: the background before the page has drawn
// and the Windows buttons in the title bar. The rest of the look is in src/styles.css and
// src/theme-palantyr.css.
const THEMES = {
  dark: { color: '#0D1020', symbolColor: '#E8EBF5' },
  light: { color: '#F2F3F8', symbolColor: '#151A2E' },
  palantyr: { color: '#000000', symbolColor: '#D3DDE7' },
};
const THEME_IDS = Object.keys(THEMES);

// Own keys only: "constructor" or "__proto__" are not a look.
const isTheme = (id) => typeof id === 'string' && Object.prototype.hasOwnProperty.call(THEMES, id);
// The colours of a look; an unknown or missing name gives the standard dark one.
const themeOf = (id) => THEMES[isTheme(id) ? id : 'dark'];

// The saved window settings with a change on top. An unknown look is left out of the change,
// so a wrong or old value can never end up saved.
function mergeUi(current, patch) {
  const p = { ...(patch && typeof patch === 'object' ? patch : {}) };
  if ('theme' in p && !isTheme(p.theme)) delete p.theme;
  return { ...(current || {}), ...p };
}

module.exports = { THEMES, THEME_IDS, isTheme, themeOf, mergeUi };
