// AgathOS - window logic (step 1: demo data, no real scanning yet).
(() => {
  const D = window.DEMO;
  const $ = (id) => document.getElementById(id);
  const RANK = { alarm: 0, watch: 1, calm: 2 };

  let lang = 'nl';
  let theme = 'dark';
  try { lang = localStorage.getItem('agathos-lang') || guessLang(); } catch (_) { lang = guessLang(); }
  if (!window.I18N[lang]) lang = 'en';

  // First start: follow the Windows language if we support it.
  function guessLang() {
    const n = (navigator.language || 'en').slice(0, 2).toLowerCase();
    return window.I18N[n] ? n : 'en';
  }
  try { theme = localStorage.getItem('agathos-theme') || 'dark'; } catch (_) {}

  const t = (key, vars = {}) => {
    const s = (window.I18N[lang] && window.I18N[lang][key]) || window.I18N.en[key] || key;
    return s.replace(/\{(\w+)\}/g, (_, k) => (k in vars ? vars[k] : ''));
  };
  const L = (obj) => (obj && typeof obj === 'object' ? obj[lang] || obj.en : obj);

  // Small helper: build elements without innerHTML (data never becomes markup).
  function el(tag, cls, text) {
    const n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  // ---------- Ring ----------
  const R = 112;
  const SVG = 'http://www.w3.org/2000/svg';
  function arcPath(a0, a1) {
    const rad = (a) => ((a - 90) * Math.PI) / 180;
    const x0 = R * Math.cos(rad(a0)), y0 = R * Math.sin(rad(a0));
    const x1 = R * Math.cos(rad(a1)), y1 = R * Math.sin(rad(a1));
    return `M ${x0.toFixed(2)} ${y0.toFixed(2)} A ${R} ${R} 0 0 1 ${x1.toFixed(2)} ${y1.toFixed(2)}`;
  }

  function renderRing() {
    const g = $('ringArcs');
    g.textContent = '';
    const n = D.watchers.length;
    const span = 360 / n;
    const gap = 9;
    D.watchers.forEach((a, i) => {
      const p = document.createElementNS(SVG, 'path');
      p.setAttribute('d', arcPath(i * span + gap / 2, (i + 1) * span - gap / 2));
      p.setAttribute('class', `ring-arc ${a.state}`);
      p.dataset.watcher = a.id;
      const title = document.createElementNS(SVG, 'title');
      title.textContent = `${L(a.name)}: ${L(a.status)}`;
      p.appendChild(title);
      p.addEventListener('mouseenter', () => highlight(a.id));
      p.addEventListener('mouseleave', () => highlight(null));
      g.appendChild(p);
    });
    $('ringTitle').textContent = t('ring.title');
  }

  function highlight(id) {
    document.querySelectorAll('.ring-arc').forEach((p) => {
      p.classList.toggle('is-hot', p.dataset.watcher === id);
      p.classList.toggle('is-dim', id != null && p.dataset.watcher !== id);
    });
    document.querySelectorAll('.watcher').forEach((li) => {
      li.classList.toggle('is-hot', li.dataset.watcher === id);
    });
  }

  // ---------- Status ----------
  function renderStatus() {
    const needs = D.watchers.filter((a) => a.state !== 'calm').length;
    $('statusLine').textContent =
      needs === 0 ? t('status.calm') : needs === 1 ? t('status.one') : t('status.many', { n: capital(numberWord(needs)) });
    $('statusSub').textContent = t('status.sub', { a: D.agents.length, m: D.mcp.length, w: capital(numberWord(D.watchers.length)) });
    $('lastScan').textContent = t('lastScan', { t: D.lastScan });
  }
  function numberWord(n) {
    const w = window.NUMBER_WORDS[lang] || window.NUMBER_WORDS.en;
    return w[n] || String(n);
  }
  const capital = (s) => s.charAt(0).toUpperCase() + s.slice(1);

  // ---------- Watchers ----------
  function renderWatchers() {
    const ul = $('watcherList');
    ul.textContent = '';
    D.watchers.forEach((a) => {
      const li = el('li', 'watcher');
      li.dataset.watcher = a.id;
      li.appendChild(el('span', `dot ${a.state}`));
      const mid = el('div');
      mid.appendChild(el('div', 'watcher-name', L(a.name)));
      mid.appendChild(el('div', 'watcher-does', L(a.does)));
      li.appendChild(mid);
      li.appendChild(el('span', `watcher-state ${a.state}`, L(a.status)));
      li.addEventListener('mouseenter', () => highlight(a.id));
      li.addEventListener('mouseleave', () => highlight(null));
      ul.appendChild(li);
    });
  }

  // ---------- Events ----------
  function renderEvents(target, list) {
    target.textContent = '';
    list.forEach((e) => {
      const li = el('li', `event ${e.state}`);
      li.appendChild(el('span', 'event-time', e.time));
      const body = el('div');
      body.appendChild(el('p', 'event-text', L(e.text)));
      const watcher = D.watchers.find((a) => a.id === e.watcher);
      if (watcher) body.appendChild(el('div', 'event-who', L(watcher.name)));
      if (e.actions) {
        const row = el('div', 'event-actions');
        e.actions.forEach((act) => {
          const b = el('button', `btn-small${act.fix ? ' fix' : ''}`, L(act));
          b.addEventListener('click', () => showModal(t('demo.title'), t('demo.action')));
          row.appendChild(b);
        });
        body.appendChild(row);
      }
      li.appendChild(body);
      target.appendChild(li);
    });
  }

  // ---------- List views ----------
  function renderRows(target, list) {
    target.textContent = '';
    [...list].sort((a, b) => RANK[a.state] - RANK[b.state]).forEach((r) => {
      const li = el('li', 'row');
      li.appendChild(el('span', `dot ${r.state}`));
      const left = el('div');
      left.appendChild(el('div', 'row-name', r.name));
      left.appendChild(el('div', 'row-where', r.where));
      li.appendChild(left);
      li.appendChild(el('div', 'row-why', L(r.why)));
      li.appendChild(el('span', `watcher-state ${r.state}`, t(`state.${r.state}`)));
      target.appendChild(li);
    });
  }

  // ---------- Navigation ----------
  function showView(name) {
    document.querySelectorAll('.nav-item').forEach((b) => b.classList.toggle('is-active', b.dataset.view === name));
    document.querySelectorAll('.view').forEach((v) => v.classList.toggle('is-active', v.id === `view-${name}`));
    $('main').scrollTop = 0;
  }
  document.querySelectorAll('.nav-item').forEach((b) => b.addEventListener('click', () => showView(b.dataset.view)));

  // ---------- Modal / toast ----------
  function showModal(title, body) {
    $('modalTitle').textContent = title;
    $('modalBody').textContent = body;
    $('modalClose').textContent = t('ok');
    $('modal').showModal();
  }
  $('modalClose').addEventListener('click', () => $('modal').close());

  let toastTimer;
  function toast(msg) {
    const n = $('toast');
    n.textContent = msg;
    n.classList.add('is-on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => n.classList.remove('is-on'), 2600);
  }

  // ---------- Buttons ----------
  $('scanBtn').addEventListener('click', () => {
    const btn = $('scanBtn');
    const ring = $('ring');
    btn.disabled = true;
    btn.firstElementChild.textContent = t('scanning');
    ring.classList.add('is-scanning');
    setTimeout(() => {
      ring.classList.remove('is-scanning');
      btn.disabled = false;
      btn.firstElementChild.textContent = t('scan');
      const now = new Date();
      D.lastScan = `${String(now.getHours()).padStart(2, '0')}:${String(now.getMinutes()).padStart(2, '0')}`;
      renderStatus();
      toast(t('demo.done'));
    }, 2800);
  });

  $('panicBtn').addEventListener('click', () => showModal(t('demo.title'), t('demo.panic')));

  // Language buttons are built from the list in i18n.js.
  const langBox = $('langSeg');
  window.LANGS.forEach((l) => {
    const b = el('button', 'seg-btn lang-btn', l.label);
    b.dataset.lang = l.code;
    b.lang = l.code;
    langBox.appendChild(b);
  });
  document.querySelectorAll('.lang-btn').forEach((b) =>
    b.addEventListener('click', () => {
      lang = b.dataset.lang;
      try { localStorage.setItem('agathos-lang', lang); } catch (_) {}
      renderAll();
    })
  );

  document.querySelectorAll('[data-theme-set]').forEach((b) =>
    b.addEventListener('click', () => {
      theme = b.dataset.themeSet;
      try { localStorage.setItem('agathos-theme', theme); } catch (_) {}
      applyTheme();
    })
  );

  function applyTheme() {
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll('[data-theme-set]').forEach((b) => b.classList.toggle('is-active', b.dataset.themeSet === theme));
    if (window.agathos && window.agathos.setTheme) window.agathos.setTheme(theme);
  }

  // ---------- All ----------
  function renderAll() {
    document.documentElement.lang = lang;
    document.querySelectorAll('[data-i18n]').forEach((n) => (n.textContent = t(n.dataset.i18n)));
    document.querySelectorAll('.lang-btn').forEach((b) => b.classList.toggle('is-active', b.dataset.lang === lang));
    $('countAgents').textContent = D.agents.length;
    $('countMcp').textContent = D.mcp.length;
    $('countFiles').textContent = D.files.length;
    renderRing();
    renderStatus();
    renderWatchers();
    renderEvents($('eventList'), D.events);
    renderEvents($('logRows'), D.events);
    renderRows($('agentRows'), D.agents);
    renderRows($('mcpRows'), D.mcp);
    renderRows($('fileRows'), D.files);
  }

  applyTheme();
  renderAll();
})();
