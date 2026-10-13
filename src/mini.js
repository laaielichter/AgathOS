// AgathOS - the mini pop-up above the tray icon.
// The essentials in one glance: status, live scanner, fix all, scan, pause, running agents.
// Same bridge and same texts as the main window; data never becomes HTML.
(() => {
  const A = window.agathos;
  const $ = (id) => document.getElementById(id);
  const WATCHERS = ['gate', 'files', 'net', 'keys', 'traps', 'proc'];
  let snap = null;
  let lang = 'en';
  let theme = 'dark';
  let busy = false;

  const dict = () => window.I18N[lang] || window.I18N.en;
  const t = (key, params = {}) => (dict()[key] || window.I18N.en[key] || key)
    .replace(/\{(\w+)\}/g, (_, k) => (k in params && params[k] != null ? String(params[k]) : '')).replace(/\s{2,}/g, ' ').trim();
  const numberWord = (n) => ((window.NUMBER_WORDS[lang] || window.NUMBER_WORDS.en)[n] || String(n));
  const capital = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const pad = (n) => String(n).padStart(2, '0');
  const clock = (ts) => { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };

  function h(tag, props, ...kids) {
    const n = document.createElement(tag);
    if (props) for (const [k, v] of Object.entries(props)) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else if (k === 'style') { for (const decl of String(v).split(';')) { const i = decl.indexOf(':'); if (i > 0) n.style.setProperty(decl.slice(0, i).trim(), decl.slice(i + 1).trim()); } }
      else n.setAttribute(k, v === true ? '' : v);
    }
    for (const k of kids.flat(Infinity)) if (k != null && k !== false) n.appendChild(typeof k === 'string' ? document.createTextNode(k) : k);
    return n;
  }
  const fill = (el, ...kids) => { el.textContent = ''; for (const k of kids.flat(Infinity)) if (k) el.appendChild(k); };
  const btn = (text, fn, cls = 'btn-ghost') => h('button', { class: cls, type: 'button', text, onclick: fn });

  async function loadUi() {
    let ui = {};
    try { ui = (A.uiState && (await A.uiState())) || {}; } catch (_) {}
    const guess = (navigator.language || 'en').slice(0, 2).toLowerCase();
    lang = ui.lang || (window.I18N[guess] ? guess : 'en');
    theme = ui.theme || 'dark';
    const meta = window.LANGS.find((l) => l.code === lang);
    document.documentElement.lang = lang;
    document.documentElement.dir = meta && meta.rtl ? 'rtl' : 'ltr';
    document.documentElement.dataset.theme = theme;
    render();
  }

  // Close with Escape, like the Windows flyouts.
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && A.closeMini) A.closeMini(); });

  function render() {
    const s = snap;
    const realtime = !!(s && s.settings.realtime);
    const live = $('miniLive');
    live.classList.toggle('is-live', realtime);
    live.setAttribute('aria-checked', realtime ? 'true' : 'false');
    live.title = realtime ? t('live.onHint') : t('live.offHint');
    $('miniLiveText').textContent = `${t('live.scanner')} · ${realtime ? t('on') : t('off')}`;
    live.onclick = () => { if (s && A.settings) A.settings({ realtime: !realtime }); };

    // Six segments, one per watcher, in the colours of the ring.
    const bar = $('miniBar');
    if (bar.childNodes.length !== 6) fill(bar, WATCHERS.map(() => h('span')));
    WATCHERS.forEach((id, i) => {
      const w = s ? s.watchers.find((x) => x.id === id) : null;
      bar.childNodes[i].className = `seg-w ${s ? (s.pausedAll ? 'paused' : w ? w.state : 'calm') : 'pending'}${s && s.scanning && s.scanning.watcher === id ? ' is-scanning' : ''}`;
      bar.childNodes[i].title = `${t(`w.${id}.name`)}: ${t('state.' + (w ? w.state : 'calm'))}`;
    });

    let line;
    let sub = '';
    if (!s) line = t('status.first');
    else if (s.pausedAll) { line = t('status.paused'); sub = t('status.pausedSub'); }
    else if (!s.lastScan) line = t('status.first');
    else {
      const needs = s.watchers.filter((w) => w.state !== 'calm').length;
      line = needs === 0 ? t('status.calm') : needs === 1 ? t('status.one') : t('status.many', { n: capital(numberWord(needs)) });
      sub = s.scanning ? t('scanPhase', { w: t(`w.${s.scanning.watcher}.name`) }) : t('lastScan', { t: clock(s.lastScan) });
    }
    $('miniStatus').textContent = line;
    $('miniStatus').className = `mini-status ${s && !s.pausedAll ? (s.watchers.some((w) => w.state === 'alarm') ? 'alarm' : s.watchers.some((w) => w.state === 'watch') ? 'watch' : 'calm') : ''}`;
    $('miniSub').textContent = sub;

    const plan = (s && s.fixPlan) || [];
    const picks = plan.filter((x) => x.cat !== 'manual' && x.action !== 'off');
    const danger = plan.some((x) => x.sev === 'alarm');
    fill($('miniActions'),
      picks.length ? btn(`${t('fix.all')} (${picks.length})`, () => A.openMain('fix'), `btn-primary wide${danger ? ' danger' : ''}`)
        : plan.length ? btn(`${t('fix.choose')} (${plan.length})`, () => A.openMain('fix'), 'btn-primary wide') : null,
      h('div', { class: 'mini-row' },
        btn(s && s.scanning ? t('scanning') : t('scan'), async () => { if (busy || (s && s.scanning)) return; busy = true; await A.scan(); busy = false; }, 'btn-ghost'),
        s && s.pausedAll ? btn(t('resumeAll'), () => A.resumeAll(), 'btn-ghost ice') : btn(t('panic'), () => A.pauseAll(), 'btn-ghost danger')));

    $('miniAgentsTitle').textContent = t('live.title');
    const running = s ? s.agents.filter((a) => a.running.length).slice(0, 4) : [];
    if (!running.length) fill($('miniAgents'), h('li', { class: 'mini-empty', text: t('live.none') }));
    else {
      fill($('miniAgents'), running.map((a) => h('li', { class: `mini-agent ${a.paused ? 'paused' : a.state}` },
        h('button', { type: 'button', class: 'mini-agent-btn', onclick: () => A.openMain('agents') },
          h('span', { class: 'mini-agent-name', text: a.name }),
          h('span', { class: 'mini-meter' }, h('span', { class: `meter-fill ${a.state}`, style: `width:${Math.max(3, a.score)}%` })),
          h('span', { class: `mini-score state-text ${a.state}`, text: a.paused ? '❚❚' : String(a.score) })))));
    }
    $('miniOpen').textContent = t('tray.open');
  }
  $('miniOpen').addEventListener('click', () => A.openMain());

  A.onUpdate((s) => { snap = s; render(); });
  if (A.onNavigate) A.onNavigate((v) => { if (v === 'refresh') loadUi(); });
  loadUi().then(async () => { const s = await A.snapshot(); if (s && s.ready) { snap = s; render(); } });
})();
