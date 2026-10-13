// AgathOS - the window. Renders the engine snapshot; every button calls the engine
// through the small, fixed bridge in preload.js. Data never becomes HTML.
(() => {
  const A = window.agathos;
  const $ = (id) => document.getElementById(id);
  const WATCHERS = ['gate', 'files', 'net', 'keys', 'traps', 'proc'];
  const VIEWS = ['overview', 'agents', 'mcp', 'files', 'models', 'network', 'log', 'settings'];
  const RANK = { calm: 0, watch: 1, alarm: 2 };

  let snap = null;
  let lang = 'en';
  let theme = 'dark';
  let view = 'overview';
  let fileTab = 'instruction';
  let introDone = false;
  let lastBeat = 0;
  const seenEvents = new Set();
  let firstEvents = true;

  // ---------- text ----------
  const dict = () => window.I18N[lang] || window.I18N.en;
  function t(key, params = {}) {
    const s = dict()[key] || window.I18N.en[key] || key;
    return s.replace(/\{(\w+)\}/g, (_, k) => (k in params && params[k] != null ? String(params[k]) : '')).replace(/\s+([.,:])(?=\s|$)/g, '$1').replace(/\s{2,}/g, ' ').trim();
  }
  // Some parameters are codes that need their own translation.
  function tp(key, params = {}) {
    const p = { ...params };
    if (p.action) p.action = t('act.' + p.action);
    if (p.next) p.next = t('act.' + p.next);
    if (p.chain) p.chain = t('chain.' + p.chain);
    if (p.labels) p.labels = String(p.labels).split('+').map((l) => t('label.' + l)).join(' + ');
    if ('agents' in p) p.agents = p.agents ? `(${p.agents})` : '';
    if ('flags' in p) p.flags = p.flags ? `· ${p.flags}` : '';
    if ('during' in p) delete p.during;
    return t(key, p);
  }
  const numberWord = (n) => ((window.NUMBER_WORDS[lang] || window.NUMBER_WORDS.en)[n] || String(n));
  const capital = (s) => s.charAt(0).toUpperCase() + s.slice(1);
  const pad = (n) => String(n).padStart(2, '0');
  const clock = (ts) => { const d = new Date(ts); return `${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const worst = (list) => list.reduce((a, b) => (RANK[b] > RANK[a] ? b : a), 'calm');

  // ---------- tiny DOM builder (textContent only) ----------
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
    for (const k of kids.flat()) if (k != null && k !== false) n.appendChild(typeof k === 'string' ? document.createTextNode(k) : k);
    return n;
  }
  const svg = (tag, attrs) => { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v); return n; };
  const fill = (el, ...kids) => { el.textContent = ''; for (const k of kids.flat()) if (k) el.appendChild(k); };

  // ---------- modal / toast ----------
  function modal(title, body) {
    $('modalTitle').textContent = title;
    $('modalBody').textContent = body;
    $('modalClose').textContent = t('ok');
    if (!$('modal').open) $('modal').showModal();
  }
  $('modalClose').addEventListener('click', () => $('modal').close());
  let toastTimer;
  function toast(msg) {
    const n = $('toast');
    n.textContent = msg;
    n.classList.add('is-on');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => n.classList.remove('is-on'), 2800);
  }
  async function run(p, okMsg) {
    const r = await p;
    if (r && r.needGuard) { modal(t('guard.title'), t('net.guardNeeded')); return r; }
    if (okMsg && r && r.ok !== false) toast(okMsg);
    return r;
  }

  // ---------- navigation ----------
  function badge(state, n) { return n ? h('span', { class: `nav-badge ${state}`, text: String(n) }) : null; }
  function renderNav() {
    const s = snap;
    const cnt = (list) => (list || []).filter((x) => x.state !== 'calm');
    const b = {
      agents: cnt(s && s.agents), mcp: cnt(s && s.mcp), files: cnt(s && [...s.files, ...s.autostarts]), models: cnt(s && s.models), network: cnt(s && s.ports),
    };
    fill($('nav'), VIEWS.map((v) => {
      const list = b[v] || [];
      return h('li', null, h('button', { class: `nav-item${v === view ? ' is-active' : ''}`, type: 'button', onclick: () => show(v) },
        h('span', { text: t('nav.' + v) }), badge(worst(list.map((x) => x.state)), list.length)));
    }));
  }
  function show(v) {
    if (!VIEWS.includes(v)) return;
    view = v;
    document.querySelectorAll('.view').forEach((n) => n.classList.toggle('is-active', n.id === `view-${v}`));
    $('main').scrollTop = 0;
    render();
  }
  if (A.onNavigate) A.onNavigate((v) => show(v));

  // ---------- chrome ----------
  function renderChrome() {
    document.documentElement.lang = lang;
    document.documentElement.dataset.theme = theme;
    document.querySelectorAll('[data-t]').forEach((n) => { n.textContent = t(n.dataset.t); });
    const live = snap && snap.settings.realtime && snap.platform === 'win32';
    $('livePill').classList.toggle('is-live', !!live);
    $('liveText').textContent = snap && snap.demo ? t('pill.demo') : live ? t('pill.live') : t('pill.off');
    $('guardPill').hidden = !(snap && snap.guard.running);
    if (snap && snap.heartbeat && snap.heartbeat !== lastBeat) {
      lastBeat = snap.heartbeat;
      const d = $('liveDot');
      d.classList.remove('beat'); void d.offsetWidth; d.classList.add('beat');
    }
    const paused = snap && snap.pausedAll;
    $('panicBtn').classList.toggle('is-paused', !!paused);
    $('panicLabel').textContent = paused ? t('resumeAll') : t('panic');
    $('panicBtn').title = paused ? '' : t('panic.hold');
    fill($('themeSeg'), ['dark', 'light'].map((th) => h('button', { class: `seg-btn${th === theme ? ' is-active' : ''}`, type: 'button', text: t('theme.' + th), onclick: () => setUi({ theme: th }) })));
    const sel = $('langSel');
    if (sel.options.length !== window.LANGS.length) {
      fill(sel, window.LANGS.filter((l) => window.I18N[l.code]).map((l) => h('option', { value: l.code, lang: l.code, text: l.label })));
      sel.onchange = () => setUi({ lang: sel.value });
    }
    sel.value = lang;
    const meta = window.LANGS.find((l) => l.code === lang);
    document.documentElement.dir = meta && meta.rtl ? 'rtl' : 'ltr';
    renderNav();
  }
  async function setUi(patch) {
    if (patch.lang) lang = patch.lang;
    if (patch.theme) theme = patch.theme;
    try { localStorage.setItem('agathos-ui', JSON.stringify({ lang, theme })); } catch (_) {}
    if (A.ui) A.ui(patch);
    render();
  }

  // ---------- panic button: hold to pause, click to resume ----------
  (() => {
    const btn = $('panicBtn');
    let timer = null;
    const start = (e) => {
      if (e.type === 'keydown' && (e.repeat || (e.key !== 'Enter' && e.key !== ' '))) return;
      if (e.type === 'keydown') e.preventDefault();
      if (snap && snap.pausedAll) { run(A.resumeAll()); return; }
      btn.classList.add('is-holding');
      timer = setTimeout(() => { timer = null; btn.classList.remove('is-holding'); run(A.pauseAll()); }, 1200);
    };
    const stop = () => { if (timer) { clearTimeout(timer); timer = null; } btn.classList.remove('is-holding'); };
    btn.addEventListener('pointerdown', start);
    btn.addEventListener('keydown', start);
    ['pointerup', 'pointerleave', 'pointercancel', 'keyup', 'blur'].forEach((ev) => btn.addEventListener(ev, stop));
  })();

  // ---------- overview ----------
  const R = 112;
  function arcPath(a0, a1) {
    const rad = (a) => ((a - 90) * Math.PI) / 180;
    return `M ${(R * Math.cos(rad(a0))).toFixed(2)} ${(R * Math.sin(rad(a0))).toFixed(2)} A ${R} ${R} 0 0 1 ${(R * Math.cos(rad(a1))).toFixed(2)} ${(R * Math.sin(rad(a1))).toFixed(2)}`;
  }
  function highlight(id) {
    document.querySelectorAll('.ring-arc').forEach((p) => { p.classList.toggle('is-hot', p.dataset.w === id); p.classList.toggle('is-dim', id != null && p.dataset.w !== id); });
    document.querySelectorAll('.watcher').forEach((li) => li.classList.toggle('is-hot', li.dataset.w === id));
  }
  const watcherView = { gate: 'mcp', files: 'models', net: 'network', keys: 'files', traps: 'files', proc: 'agents' };

  function renderRing() {
    const ring = $('ring');
    const ws = snap ? snap.watchers : WATCHERS.map((id) => ({ id, state: 'calm' }));
    const scanning = snap && snap.scanning;
    const arcs = $('ringArcs');
    // Build once, then only change classes so colour changes animate.
    if (arcs.childNodes.length !== 6) {
      arcs.textContent = '';
      WATCHERS.forEach((id, i) => {
        const p = svg('path', { d: arcPath(i * 60 + 4.5, (i + 1) * 60 - 4.5), class: 'ring-arc' });
        p.style.setProperty('--i', String(i));   // CSSOM is allowed by the CSP; a style attribute is not
        p.dataset.w = id;
        p.appendChild(svg('title'));
        p.addEventListener('mouseenter', () => highlight(id));
        p.addEventListener('mouseleave', () => highlight(null));
        p.addEventListener('click', () => show(watcherView[id]));
        arcs.appendChild(p);
      });
    }
    const rip = $('ringRipples');
    rip.textContent = '';
    WATCHERS.forEach((id, i) => {
      const w = ws.find((x) => x.id === id) || { state: 'calm' };
      const p = arcs.childNodes[i];
      const cls = ['ring-arc', snap ? w.state : 'pending'];
      if (scanning && scanning.watcher === id) cls.push('is-scanning');
      p.setAttribute('class', cls.join(' '));
      p.firstChild.textContent = `${t(`w.${id}.name`)}: ${t('state.' + w.state)}`;
      if (snap && w.state !== 'calm' && !snap.pausedAll) rip.appendChild(svg('path', { d: arcPath(i * 60 + 4.5, (i + 1) * 60 - 4.5), class: `ring-ripple ${w.state}` }));
    });
    ring.classList.toggle('is-scanning', !!scanning);
    ring.classList.toggle('is-paused', !!(snap && snap.pausedAll));
    if (scanning) {
      const i = Math.max(0, WATCHERS.indexOf(scanning.watcher));
      $('ringPointer').style.transform = `rotate(${i * 60 + 30}deg)`;
    }
    $('ringTitle').textContent = t('ring.title');
    if (snap && !introDone) {
      introDone = true;
      ring.classList.add('is-intro');
      setTimeout(() => ring.classList.remove('is-intro'), 1900);
    }
  }

  function renderStatus() {
    const s = snap;
    let line;
    let sub;
    if (!s) { line = t('status.first'); sub = ''; }
    else if (s.pausedAll) { line = t('status.paused'); sub = t('status.pausedSub'); }
    else if (!s.lastScan) { line = t('status.first'); sub = ''; }
    else {
      const needs = s.watchers.filter((w) => w.state !== 'calm').length;
      line = needs === 0 ? t('status.calm') : needs === 1 ? t('status.one') : t('status.many', { n: capital(numberWord(needs)) });
      sub = t('status.sub', { a: s.counts.agents, m: s.counts.mcp, w: capital(numberWord(6)) });
      if (s.platform !== 'win32' && !s.demo) sub += ' ' + t('notWindows');
    }
    $('statusLine').textContent = line;
    $('statusSub').textContent = sub;
    const btn = $('scanBtn');
    const scanning = s && s.scanning;
    btn.disabled = !!scanning;
    btn.textContent = scanning ? t('scanning') : t('scan');
    $('lastScan').textContent = scanning ? t('scanPhase', { w: t(`w.${scanning.watcher}.name`) }) : s && s.lastScan ? t('lastScan', { t: clock(s.lastScan) }) : t('never');
  }
  $('scanBtn').addEventListener('click', () => A.scan());

  function meter(score, state) {
    return h('div', { class: 'meter' },
      h('div', { class: 'meter-bar' }, h('div', { class: `meter-fill ${state}`, style: `width:${Math.max(2, score)}%` })),
      h('span', { class: `meter-num state-text ${state}`, text: String(score) }));
  }

  function renderLive() {
    $('liveTitle').textContent = t('live.title');
    const running = snap ? snap.agents.filter((a) => a.running.length) : [];
    if (!running.length) { fill($('liveCards'), h('div', { class: 'live-empty', text: t('live.none') })); return; }
    fill($('liveCards'), running.map((a) => {
      const next = a.prediction ? `${t('card.next')}: ${t('act.' + a.prediction.action)}` : a.task ? `${t('card.task')}: ${a.task}` : '';
      return h('button', { class: `live-card ${a.paused ? 'paused' : a.state}`, type: 'button', onclick: () => show('agents') },
        h('div', { class: 'live-top' }, h('span', { class: 'live-name', text: a.name }), h('span', { class: 'chip', text: a.paused ? t('card.paused') : `PID ${a.running[0].pid}` })),
        meter(a.score, a.state),
        next ? h('div', { class: 'live-next', text: next.slice(0, 120) }) : null);
    }));
  }

  function renderWatchers() {
    $('watchersTitle').textContent = t('watchers.title');
    const scanning = snap && snap.scanning;
    fill($('watcherList'), WATCHERS.map((id) => {
      const w = (snap && snap.watchers.find((x) => x.id === id)) || { state: 'calm', issues: 0 };
      const li = h('li', { class: `watcher${scanning && scanning.watcher === id ? ' is-scanning' : ''}`, onclick: () => show(watcherView[id]),
        onmouseenter: () => highlight(id), onmouseleave: () => highlight(null) },
        h('span', { class: `dot ${snap ? w.state : 'pending'}` }),
        h('div', null, h('div', { class: 'watcher-name', text: t(`w.${id}.name`) }), h('div', { class: 'watcher-does', text: t(`w.${id}.does`) })),
        h('span', { class: `state-text ${w.state}`, text: w.issues ? t('w.issues', { n: w.issues }) : t('w.calm') }));
      li.dataset.w = id;
      return li;
    }));
  }

  // ---------- events ----------
  const agentRunning = (id) => snap && snap.agents.find((a) => a.id === id && a.running.length);
  function eventActions(e) {
    const out = [];
    if (Date.now() - e.ts > 6 * 3600 * 1000) return out;
    const tg = e.target || {};
    if (e.key === 'port.open') {
      out.push({ label: t('btn.localOnly'), cls: 'fix', fn: () => run(A.localOnly(e.params.port, true), t('fw.localOnly', { port: e.params.port })) });
      out.push({ label: t('btn.how'), fn: () => modal(t('btn.how'), t('fix.port')) });
    } else if (tg.type === 'mcp') {
      const m = snap.mcp.find((x) => x.id === tg.id);
      if (m && !m.approved) out.push({ label: t('btn.trust'), fn: () => run(A.trust(tg), t('mcp.trusted', { name: m.name })) });
      out.push({ label: t('btn.how'), fn: () => modal(t('btn.how'), t('fix.mcp', { app: e.params.app || '' })) });
    } else if (tg.type === 'file' && tg.path) {
      out.push({ label: t('btn.open'), fn: () => A.reveal(tg.path) });
      out.push({ label: t('btn.ignore'), fn: () => run(A.trust(tg)) });
    } else if (tg.type === 'auto') {
      out.push({ label: t('btn.ignore'), fn: () => run(A.trust(tg)) });
    } else if (e.key === 'model.flagged') {
      out.push({ label: t('btn.how'), fn: () => modal(t('btn.how'), t('fix.model')) });
    } else if (e.key === 'mass.delete' && snap.agents.some((a) => a.paused)) {
      out.push({ label: t('resumeAll'), fn: () => run(A.resumeAll()) });
    }
    if (e.agentId && e.sev !== 'calm' && agentRunning(e.agentId)) {
      const a = agentRunning(e.agentId);
      if (a.paused) out.push({ label: t('btn.resume'), cls: 'ice', fn: () => run(A.resume(a.id)) });
      else out.push({ label: t('btn.freeze'), cls: 'ice', fn: () => run(A.freeze(a.id)) });
      out.push({ label: t('btn.kill'), cls: 'danger', fn: () => run(A.kill(a.id)) });
      if (/^(intent|honesty|proc|flag)\./.test(e.key)) out.push({ label: t('btn.approve'), fn: () => run(A.trust({ type: 'agent', id: a.id }), t('agent.approved', { name: a.name })) });
    }
    return out;
  }

  function eventItem(e) {
    const isNew = !firstEvents && !seenEvents.has(e.hash);
    seenEvents.add(e.hash);
    const actions = eventActions(e);
    const agent = e.agentId && snap.agents.find((a) => a.id === e.agentId);
    return h('li', { class: `event ${e.sev}${isNew ? ' is-new' : ''}` },
      h('span', { class: 'event-time', text: clock(e.ts) }),
      h('div', null,
        h('p', { class: 'event-text', text: tp(e.key, e.params) }),
        h('div', { class: 'event-who', text: [t(`w.${e.watcher}.name`), agent ? agent.name : null].filter(Boolean).join(' · ') }),
        actions.length ? h('div', { class: 'event-actions' }, actions.map((a) => h('button', { class: `btn-small ${a.cls || ''}`, type: 'button', text: a.label, onclick: a.fn }))) : null));
  }
  const QUIET = new Set(['app.started', 'agent.stopped']);
  function renderEvents() {
    $('eventsTitle').textContent = t('events.title');
    const list = snap ? snap.events.filter((e) => !QUIET.has(e.key)).slice(0, 10) : [];
    fill($('eventList'), list.map(eventItem));
    firstEvents = false;
  }

  // ---------- agents ----------
  function reasonList(reasons) {
    if (!reasons || !reasons.length) return h('div', { class: 'field-value', style: 'color:var(--dim)', text: t('card.noReasons') });
    return h('ul', { class: 'reasons' }, reasons.map((r) => h('li', null, h('span', { class: `dot ${r.sev}` }), h('span', { text: tp(r.key, r.params) }))));
  }
  function field(label, ...value) { return h('div', null, h('div', { class: 'field-label', text: label }), ...value); }
  function trifecta(labels) {
    const on = ['untrusted', 'private', 'exit'].filter((k) => labels && labels[k]);
    const box = h('div', { class: `trifecta${on.length === 3 ? ' full' : ''}` });
    ['untrusted', 'private', 'exit'].forEach((k, i) => {
      if (i) box.appendChild(h('span', { class: 'tri-link' }));
      box.appendChild(h('span', { class: `tri-light${labels && labels[k] ? ' on' : ''}`, text: t('label.' + k) }));
    });
    return box;
  }
  function renderAgents() {
    const list = snap ? snap.agents : [];
    if (!list.length) { fill($('agentCards'), h('div', { class: 'rows-empty', text: t('empty') })); return; }
    fill($('agentCards'), list.map((a) => {
      const run0 = a.running[0];
      const meta = [
        run0 ? h('span', { class: a.paused ? 'frozen' : 'on', text: a.paused ? t('card.paused') : t('card.running', { pid: run0.pid }) }) : h('span', { text: t('card.idle') }),
        a.version ? h('span', { text: `${t('card.version')} ${a.version}` }) : null,
        run0 && run0.children > 0 ? h('span', { text: t('card.children', { n: run0.children }) }) : null,
        h('span', { text: a.learned ? t('card.learned') : t('card.learning') }),
      ];
      const body = [];
      if (run0) {
        body.push(field(t('card.parent'), h('div', { class: 'field-value', text: run0.parent || '?' })));
        body.push(field(t('card.signer'), h('div', { class: 'field-value', text: run0.signer ? (run0.signer.valid ? run0.signer.signer : `${t('card.unsigned')} (${run0.signer.status})`) : '…' })));
        body.push(h('div', { style: 'grid-column:1/-1' }, field('PID ' + run0.pid, h('div', { class: 'code', text: run0.cmd || run0.exe || '' }))));
        if (run0.flags && run0.flags.length) body.push(field(t('card.flags'), h('div', { class: 'flag', text: run0.flags.join(' ') })));
      }
      if (a.task) body.push(field(t('card.task'), h('div', { class: 'field-value', text: a.task })));
      body.push(field(t('card.labels'), trifecta(a.labels)));
      if (a.prediction) body.push(field(t('card.next'), h('div', { class: 'field-value', text: `${t('act.' + a.prediction.action)} · ${Math.round(a.prediction.p * 100)}%` })));
      body.push(h('div', { style: 'grid-column:1/-1' }, field(t('card.why'), reasonList(a.reasons))));
      if (a.domains && a.domains.length) body.push(h('div', { style: 'grid-column:1/-1' }, field(t('card.domains'), h('div', { class: 'domains' }, a.domains.map((d) => h('span', { class: 'chip', text: d })))))) ;
      if (a.actions && a.actions.length) {
        body.push(h('div', { style: 'grid-column:1/-1' }, field(t('card.recent'), h('ul', { class: 'actions-list' },
          a.actions.slice(0, 20).map((x) => h('li', null, h('span', { text: clock(x.ts) }), h('span', { class: 'a', text: t('act.' + x.action) }), h('span', { class: 'd', text: x.detail || '' })))))));
      }
      if (!run0 && a.dirs.length) body.push(field(t('card.where'), h('div', { class: 'field-value', text: a.dirs.join(', ') })));
      const btns = [];
      if (run0) {
        btns.push(a.paused ? h('button', { class: 'btn-small ice', type: 'button', text: t('btn.resume'), onclick: () => run(A.resume(a.id)) })
          : h('button', { class: 'btn-small ice', type: 'button', text: t('btn.freeze'), onclick: () => run(A.freeze(a.id)) }));
        btns.push(h('button', { class: 'btn-small danger', type: 'button', text: t('btn.kill'), onclick: () => run(A.kill(a.id)) }));
        btns.push(h('button', { class: 'btn-small', type: 'button', text: t('btn.block'), onclick: () => run(A.block(a.id, true)) }));
      }
      if (a.state !== 'calm' || a.actions.length) btns.push(h('button', { class: 'btn-small', type: 'button', text: t('btn.approve'), onclick: () => run(A.trust({ type: 'agent', id: a.id }), t('agent.approved', { name: a.name })) }));
      return h('article', { class: `card ${a.paused ? 'paused' : a.state}` },
        h('div', { class: 'card-head' }, h('div', null, h('h2', { class: 'card-name', text: a.name }), h('div', { class: 'card-meta' }, meta)), h('div', null, h('div', { class: 'field-label', text: t('card.score') }), meter(a.score, a.state))),
        h('div', { class: 'card-body' }, body),
        btns.length ? h('div', { class: 'card-actions' }, btns) : null);
    }));
  }

  // ---------- generic rows ----------
  function rowList(target, items, opts) {
    if (!items.length) { fill(target, h('li', { class: 'rows-empty', text: opts.empty || t('empty') })); return; }
    const sorted = [...items].sort((a, b) => RANK[b.state] - RANK[a.state]);
    fill(target, sorted.map((x) => h('li', { class: 'row' },
      h('span', { class: `dot ${x.state}` }),
      h('div', null, h('div', { class: 'row-name', text: opts.name(x) }), h('div', { class: 'row-where', text: opts.where(x) })),
      h('div', null,
        h('div', { class: 'row-why' }, (x.reasons || []).map((r) => h('span', { class: `r ${r.sev}`, text: tp(r.key, r.params) }))),
        opts.actions ? h('div', { class: 'row-actions' }, opts.actions(x)) : null),
      h('span', { class: `state-text ${x.state}`, text: t('state.' + x.state) }))));
  }
  const btn = (label, fn, cls = '') => h('button', { class: `btn-small ${cls}`, type: 'button', text: label, onclick: fn });

  function renderMcp() {
    rowList($('mcpRows'), snap ? snap.mcp : [], {
      name: (m) => m.name,
      where: (m) => `${t('mcp.in', { app: m.app })} · ${m.transport === 'http' ? m.url : [m.command, ...(m.args || [])].join(' ')}`.slice(0, 200),
      actions: (m) => [
        !m.approved ? btn(t('btn.trust'), () => run(A.trust({ type: 'mcp', id: m.id }), t('mcp.trusted', { name: m.name })), m.state === 'alarm' ? '' : 'fix') : h('span', { class: 'chip', text: t('mcp.approved') }),
        m.state !== 'calm' ? btn(t('btn.how'), () => modal(t('btn.how'), t('fix.mcp', { app: m.app }))) : null,
        btn(t('btn.open'), () => A.reveal(m.file)),
      ],
    });
  }

  function renderFiles() {
    const all = snap ? snap.files : [];
    const groups = {
      instruction: all.filter((f) => f.kind === 'instruction'), skill: all.filter((f) => f.kind === 'skill'),
      config: all.filter((f) => f.kind === 'config'), env: all.filter((f) => f.kind === 'env'), auto: snap ? snap.autostarts : [],
    };
    fill($('fileTabs'), Object.entries(groups).map(([k, list]) => {
      const bad = list.filter((x) => x.state !== 'calm');
      return h('button', { class: `tab${k === fileTab ? ' is-active' : ''}`, type: 'button', role: 'tab', onclick: () => { fileTab = k; renderFiles(); } },
        t('tab.' + k), h('span', { class: `n ${worst(bad.map((x) => x.state))}`, text: String(bad.length || list.length) }));
    }));
    if (fileTab === 'auto') {
      rowList($('fileRows'), groups.auto, {
        name: (a) => a.name, where: (a) => a.command.slice(0, 200),
        actions: (a) => (a.state !== 'calm' ? [btn(t('btn.ignore'), () => run(A.trust({ type: 'auto', id: a.id })))] : []),
      });
      return;
    }
    rowList($('fileRows'), groups[fileTab], {
      name: (f) => f.path.split(/[\\/]/).pop(), where: (f) => f.short || f.path,
      actions: (f) => [
        f.path && !f.path.startsWith('Environment') ? btn(t('btn.open'), () => A.reveal(f.path)) : null,
        f.state === 'watch' && f.id ? btn(t('btn.ignore'), () => run(A.trust({ type: 'file', id: f.id, path: f.path }))) : null,
        f.reasons.some((r) => r.key === 'file.secret') ? btn(t('btn.how'), () => modal(t('btn.how'), t('fix.secret'))) : null,
      ],
    });
  }

  function renderModels() {
    rowList($('modelRows'), snap ? snap.models : [], {
      empty: t('empty.models'),
      name: (m) => m.path.split(/[\\/]/).pop(),
      where: (m) => `${m.format} · ${(m.size / 1048576).toFixed(m.size > 1e9 ? 0 : 1)} MB · ${m.short || m.path}`,
      actions: (m) => [btn(t('btn.open'), () => A.reveal(m.path)), m.state !== 'calm' ? btn(t('btn.how'), () => modal(t('btn.how'), t('fix.model'))) : null],
    });
  }

  function renderNetwork() {
    const s = snap;
    const g = s ? s.guard : {};
    const ports = h('ul', { class: 'rows' });
    rowList(ports, s ? s.ports : [], {
      empty: t('net.noPorts'),
      name: (p) => `${p.product} · ${p.port}`, where: (p) => `${p.addr}:${p.port} · ${p.process || ''} · PID ${p.pid}`,
      actions: (p) => (p.exposed ? [btn(t('btn.localOnly'), () => run(A.localOnly(p.port, true), t('fw.localOnly', { port: p.port })), 'fix'), btn(t('btn.how'), () => modal(t('btn.how'), t('fix.port')))] : []),
    });
    const guardChip = g.running ? h('span', { class: 'status-chip on', text: t('guard.running') }) : g.installed ? h('span', { class: 'status-chip warn', text: t('guard.stopped') }) : h('span', { class: 'status-chip', text: t('guard.none') });
    fill($('networkBody'), h('div', { class: 'stack' },
      h('div', null, h('h2', { class: 'panel-title', style: 'margin-left:0', text: t('net.ports') }), ports),
      h('div', { class: 'box' },
        h('div', { class: 'box-row' }, h('h2', { text: t('net.lockdown') }), s && s.lockdown ? h('span', { class: 'status-chip warn', text: t('fw.lockdown') }) : null),
        h('p', { text: t('net.lockdownDesc') + (g.running ? '' : ' ' + t('net.guardNeeded')) }),
        btn(s && s.lockdown ? t('net.lockdownOff') : t('net.lockdownOn'), () => run(A.lockdown(!(s && s.lockdown))), s && s.lockdown ? '' : 'danger')),
      h('div', { class: 'box' },
        h('div', { class: 'box-row' }, h('h2', { text: t('guard.title') }), guardChip),
        h('p', { text: t('guard.desc') }),
        g.running ? h('p', { text: g.sysmon ? t('guard.sysmon') : t('guard.basic') }) : null,
        g.installed
          ? btn(t('guard.uninstall'), async () => { const r = await A.guardUninstall(); toast(r && r.ok ? t('guard.removed') : t('guard.failed')); })
          : btn(t('guard.install'), async () => {
            modal(t('guard.title'), t('guard.uac'));
            const r = await A.guardInstall();
            if ($('modal').open) $('modal').close();
            modal(t('guard.title'), r && r.ok ? t('guard.done') : t('guard.failed'));
          }, 'fix'))));
  }

  function renderLog() {
    const list = snap ? snap.events : [];
    fill($('logRows'), list.length ? list.map(eventItem) : h('li', { class: 'rows-empty', text: t('empty') }));
  }

  // ---------- settings ----------
  function sw(on, fn) { return h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-checked': on ? 'true' : 'false', onclick: fn }); }
  async function save(patch) { if (!A.settings) return; await A.settings(patch); toast(t('set.saved')); }
  function setRow(label, control, small) {
    return h('div', { class: 'set' }, h('div', { class: 'set-label' }, h('span', { text: label }), small ? h('small', { text: small }) : null), h('div', { class: 'set-control' }, control));
  }
  function num(value, min, max, key, unit) {
    return [h('input', { type: 'number', value: String(value), min: String(min), max: String(max),
      onchange: (e) => { const v = Math.min(max, Math.max(min, Number(e.target.value) || min)); save({ [key]: v }); } }), h('span', { class: 'set-label', text: unit })];
  }
  function folders(list, kind) {
    return h('ul', { class: 'folders' }, list.map((p) => h('li', null, h('span', { text: p }), btn(t('set.remove'), async () => { await A.removeFolder(kind, p); }))));
  }
  let judgeModels = null;
  function renderSettings() {
    if (!snap) return;
    const body = $('settingsBody');
    if (body.contains(document.activeElement) && /INPUT|SELECT/.test(document.activeElement.tagName)) return;
    const s = snap.settings;
    if (judgeModels === null && A.judgeModels) { judgeModels = []; A.judgeModels().then((m) => { judgeModels = m || []; renderSettings(); }); }
    const levelSeg = h('div', { class: 'seg' }, ['strict', 'balanced', 'relaxed'].map((l) => h('button', { class: `seg-btn${s.level === l ? ' is-active' : ''}`, type: 'button', text: t('set.level.' + l), onclick: () => save({ level: l }) })));
    const notifySel = h('select', { onchange: (e) => save({ notify: e.target.value }) }, ['log', 'notify', 'ask'].map((n) => h('option', { value: n, selected: s.notify === n, text: t('set.notify.' + n) })));
    const models = (judgeModels && judgeModels.length ? judgeModels : [s.judge.model]);
    const judgeSel = h('select', { onchange: (e) => save({ judge: { model: e.target.value } }) }, models.map((m) => h('option', { value: m, selected: s.judge.model === m, text: m })));
    fill(body,
      h('section', { class: 'set-group' }, h('h2', { text: t('set.protection') }),
        setRow(t('set.level'), levelSeg),
        setRow(t('set.notify'), notifySel),
        setRow(t('set.autoFreeze'), sw(s.autoFreezeOnMassDelete, () => save({ autoFreezeOnMassDelete: !s.autoFreezeOnMassDelete }))),
        setRow(t('set.threshold'), num(s.massDeleteThreshold, 10, 1000, 'massDeleteThreshold', t('set.files10s'))),
        setRow(t('set.portCheck'), sw(s.portCheck, () => save({ portCheck: !s.portCheck }))),
        setRow(t('set.hotkey'), sw(s.hotkey, () => save({ hotkey: !s.hotkey })))),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.watching') }),
        setRow(t('set.realtime'), sw(s.realtime, () => save({ realtime: !s.realtime }))),
        setRow(t('set.poll'), num(s.pollSeconds, 2, 60, 'pollSeconds', t('set.seconds'))),
        setRow(t('set.fullScan'), num(s.fullScanHours, 1, 48, 'fullScanHours', t('set.hours'))),
        h('div', { class: 'set' }, h('div', { class: 'set-label' }, h('span', { text: t('set.roots') })), h('div', { class: 'set-control' }, btn(t('set.add'), () => A.addFolder('roots'))), folders(s.roots, 'roots')),
        h('div', { class: 'set' }, h('div', { class: 'set-label' }, h('span', { text: t('set.modelDirs') })), h('div', { class: 'set-control' }, btn(t('set.add'), () => A.addFolder('models'))), folders(s.modelDirs, 'models'))),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.smart') }),
        setRow(t('set.learning'), [btn(t('set.rollback'), async () => { if (await A.rollback()) toast(t('set.rolledBack')); }), btn(t('set.reset'), async () => { await A.forget(); toast(t('set.forgot')); }), sw(s.learning, () => save({ learning: !s.learning }))]),
        setRow(t('set.judge'), sw(s.judge.enabled, () => save({ judge: { enabled: !s.judge.enabled } })), t('set.judgeDesc')),
        s.judge.enabled ? setRow(t('set.judgeModel'), judgeSel) : null),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.app') }),
        setRow(t('set.startup'), sw(s.startWithWindows, () => save({ startWithWindows: !s.startWithWindows }))),
        setRow(t('set.tray'), sw(s.closeToTray, () => save({ closeToTray: !s.closeToTray }))),
        setRow(t('set.logDays'), num(s.logDays, 1, 365, 'logDays', t('set.days'))),
        setRow(t('set.api'), sw(s.api, () => save({ api: !s.api })), `127.0.0.1:${snap.apiPort}`),
        setRow(t('set.verify'), btn(t('set.verify'), async () => { const r = await A.verifyLog(); modal(t('set.verify'), r.ok ? t('set.verifyOk', { n: r.lines }) : t('set.verifyBad', { n: r.line })); }))));
  }

  // ---------- main render ----------
  function render() {
    renderChrome();
    renderRing();
    renderStatus();
    if (view === 'overview') { renderLive(); renderWatchers(); renderEvents(); }
    else if (snap && snap.events) snap.events.forEach((e) => seenEvents.add(e.hash));
    if (view === 'agents') renderAgents();
    if (view === 'mcp') renderMcp();
    if (view === 'files') renderFiles();
    if (view === 'models') renderModels();
    if (view === 'network') renderNetwork();
    if (view === 'log') renderLog();
    if (view === 'settings') renderSettings();
  }

  async function init() {
    let ui = {};
    try { ui = (A.uiState && (await A.uiState())) || {}; } catch (_) {}
    let local = {};
    try { local = JSON.parse(localStorage.getItem('agathos-ui') || '{}'); } catch (_) {}
    const guess = (navigator.language || 'en').slice(0, 2).toLowerCase();
    lang = ui.lang || local.lang || (window.I18N[guess] ? guess : 'en');
    theme = ui.theme || local.theme || 'dark';
    if (!ui.lang && A.ui) A.ui({ lang, theme });
    render();
    A.onUpdate((s) => { snap = s; render(); });
    const s = await A.snapshot();
    if (s && s.ready) { snap = s; render(); }
  }
  init();
})();
