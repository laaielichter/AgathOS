'use strict';
// AgathOS - the menu of the tray icon (right click on Windows, click on a Mac) as plain data,
// so it can be tested without a screen.
//   tt   text lookup: tt(key, params)
//   s    { live, paused, snoozed, update }   what the menu has to show
//   act  what each item does
function template(tt, s, act) {
  const update = s.update && s.update.status === 'newer' ? s.update : null;
  return [
    { id: 'open', label: tt('tray.open'), click: act.open },
    { id: 'scan', label: tt('tray.scan'), click: act.scan },
    { id: 'check', label: tt('tray.check'), click: act.checkText },
    { id: 'live', label: tt('tray.live'), type: 'checkbox', checked: !!s.live, click: (item) => act.setLive(!!(item && item.checked)) },
    { type: 'separator' },
    s.paused
      ? { id: 'resume', label: tt('tray.resume'), click: act.resume }
      : { id: 'pause', label: tt('tray.pause'), click: act.pause },
    { type: 'separator' },
    s.snoozed
      ? { id: 'snoozeOff', label: tt('tray.snoozeOff'), click: act.snoozeOff }
      : { id: 'snooze', label: tt('tray.snooze'), submenu: [
        { id: 'snooze1h', label: tt('set.snooze1h'), click: act.snooze1h },
        { id: 'snoozeTomorrow', label: tt('set.snoozeTomorrow'), click: act.snoozeTomorrow },
      ] },
    { type: 'separator' },
    // A new version that was found: opens the window with the button to install it (it never installs on a single click).
    ...(update ? [{ id: 'updateFound', label: tt('upd.available', { v: update.version }), click: act.showUpdate }] : []),
    { id: 'update', label: tt('tray.update'), click: act.checkUpdate },
    { type: 'separator' },
    { id: 'quit', label: tt('tray.quit'), click: act.quit },
  ];
}

module.exports = { template };
