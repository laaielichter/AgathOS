// AgathOS - the window. Renders the engine snapshot; every button calls the engine
// through the small, fixed bridge in preload.js. Data never becomes HTML.
(() => {
  const A = window.agathos;
  const $ = (id) => document.getElementById(id);
  const WATCHERS = ['gate', 'files', 'net', 'keys', 'traps', 'proc'];
  const VIEWS = ['overview', 'agents', 'mcp', 'files', 'models', 'network', 'check', 'log', 'settings'];
  const RANK = { calm: 0, watch: 1, alarm: 2 };

  let snap = null;
  let lang = 'en';
  let theme = 'dark';
  let view = 'overview';
  let fileTab = 'instruction';
  let introDone = false;
  let mode = 'advanced';          // advanced (default) | simple
  let welcomed = true;
  let fresh = false;              // a scan just finished with findings: the fix panel pulses once
  const SIMPLE_VIEWS = ['overview', 'agents', 'check', 'log', 'settings'];
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
    if (p.fix) p.fix = t('fixact.' + p.fix);
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
  // Windows has AgathOS Guard (firewall, deep logging); a Mac uses its built-in tools only.
  const platform = () => (snap && !snap.demo && snap.platform) || (A.platform === 'darwin' ? 'darwin' : (snap && snap.platform) || A.platform || 'win32');
  const isMac = () => platform() === 'darwin';
  const startupLabel = () => (isMac() ? t('wel.startupMac') : t('set.startup'));
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
    for (const k of kids.flat(Infinity)) if (k != null && k !== false) n.appendChild(typeof k === 'string' ? document.createTextNode(k) : k);
    return n;
  }
  const svg = (tag, attrs) => { const n = document.createElementNS('http://www.w3.org/2000/svg', tag); for (const [k, v] of Object.entries(attrs || {})) n.setAttribute(k, v); return n; };
  const fill = (el, ...kids) => { el.textContent = ''; for (const k of kids.flat(Infinity)) if (k) el.appendChild(k); };

  // ---------- modal / toast ----------
  function modal(title, body) {
    $('modalTitle').textContent = title;
    $('modalBody').textContent = body;
    $('modalClose').textContent = t('ok');
    if (!$('modal').open) $('modal').showModal();
  }
  $('modalClose').addEventListener('click', () => $('modal').close());
  // Every window on top can be closed: the X, Esc, or a click next to it.
  for (const d of document.querySelectorAll('dialog')) {
    const x = d.querySelector('.dlg-x');
    if (x) x.addEventListener('click', () => d.close());
    d.addEventListener('click', (e) => {
      if (e.target !== d) return;
      const r = d.getBoundingClientRect();
      if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) d.close();
    });
  }
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
    const shown = mode === 'simple' ? SIMPLE_VIEWS : VIEWS;
    fill($('nav'), shown.map((v) => {
      const list = b[v] || [];
      return h('li', null, h('button', { class: `nav-item${v === view ? ' is-active' : ''}`, type: 'button', onclick: () => show(v) },
        h('span', { text: t('nav.' + v) }), badge(worst(list.map((x) => x.state)), list.length)));
    }));
  }
  function show(v) {
    if (!VIEWS.includes(v)) return;
    if (mode === 'simple' && !SIMPLE_VIEWS.includes(v)) v = 'overview';
    view = v;
    document.querySelectorAll('.view').forEach((n) => n.classList.toggle('is-active', n.id === `view-${v}`));
    $('main').scrollTop = 0;
    render();
  }
  if (A.onNavigate) A.onNavigate((v) => {
    // From the mini pop-up: "Fix all" opens the overview with the fix dialog.
    if (v === 'fix') { show('overview'); if (snap) openFix(planOf().some((x) => x.cat !== 'manual' && x.action !== 'off') ? 'all' : 'choose'); return; }
    show(v);
  });

  // ---------- chrome ----------
  function renderChrome() {
    document.documentElement.lang = lang;
    document.documentElement.dataset.theme = theme;
    document.documentElement.dataset.mode = mode;
    document.documentElement.dataset.platform = platform();
    document.querySelectorAll('[data-t]').forEach((n) => { n.textContent = t(n.dataset.t); });
    document.querySelectorAll('.dlg-x').forEach((n) => { n.setAttribute('aria-label', t('close')); n.title = t('close'); });
    const realtime = !!(snap && snap.settings.realtime);
    const live = realtime && (snap.platform === 'win32' || snap.platform === 'darwin' || snap.demo);
    const pill = $('livePill');
    pill.classList.toggle('is-live', !!live);
    pill.setAttribute('aria-checked', realtime ? 'true' : 'false');
    pill.title = realtime ? t('live.onHint') : t('live.offHint');
    $('liveText').textContent = `${t('live.scanner')} · ${realtime ? t('on') : t('off')}${snap && snap.demo ? ` · ${t('pill.demo')}` : ''}`;
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
    if (patch.mode) mode = patch.mode === 'simple' ? 'simple' : 'advanced';
    try { localStorage.setItem('agathos-ui', JSON.stringify({ lang, theme, mode, welcomed })); } catch (_) {}
    if (A.ui) A.ui(patch);
    render();
  }

  function toggleLive() { if (snap) save({ realtime: !snap.settings.realtime }); }
  $('livePill').addEventListener('click', toggleLive);

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
      if (s.platform !== 'win32' && s.platform !== 'darwin' && !s.demo) sub += ' ' + t('notWindows');
    }
    $('statusLine').textContent = line;
    $('statusSub').textContent = sub;
    const btn = $('scanBtn');
    const scanning = s && s.scanning;
    btn.disabled = !!scanning;
    btn.textContent = scanning ? t('scanning') : t('scan');
    $('lastScan').textContent = scanning ? t('scanPhase', { w: t(`w.${scanning.watcher}.name`) }) : s && s.lastScan ? t('lastScan', { t: clock(s.lastScan) }) : t('never');
    const rt = !!(s && s.settings.realtime);
    fill($('liveSwitch'), sw(rt, toggleLive), h('span', { text: t('live.scanner') }), h('span', { class: rt ? 'on-text' : 'off-text', text: rt ? t('on') : t('off') }));
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
    if (e.sev !== 'calm' && !/^(fix|pause|fw\.(blocked|unblocked|localOnly|lockdown))/.test(e.key)) out.push({ label: t('fix.why'), fn: () => analyseEvent(e) });
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

  // ---------- analysis: what a finding could be, why it matters, what to do ----------
  const AN_CAT = {
    hidden: ['file.hiddenTags', 'file.hidden', 'file.bidi'],
    inject: ['file.injectionPhrase'],
    secret: ['file.secret', 'mcp.inlineSecret'],
    mcpBad: ['mcp.malicious'],
    supply: ['mcp.unpinned', 'mcp.new', 'mcp.oddPath', 'mcp.shellPipe', 'mcp.added', 'agent.installed', 'proc.unknownLauncher', 'proc.download'],
    remote: ['mcp.remoteHttp', 'mcp.remote'],
    hijack: ['mcp.changed', 'mcp.defChanged', 'proc.configChange', 'config.repoHooks'],
    approve: ['config.autoApprove', 'flag.dangerous'],
    baseUrl: ['config.baseUrl'],
    model: ['model.pickleDanger', 'model.pickle', 'model.pickleUnknown', 'model.unreadable', 'model.flagged'],
    port: ['port.open'],
    destroy: ['proc.destructive', 'mass.delete'],
    persist: ['proc.persistence', 'auto.hiddenScript', 'auto.tempPath', 'auto.scriptRuntime', 'auto.added'],
    cred: ['proc.credential', 'proc.sensitive'],
    secOff: ['proc.securityOff', 'fw.changed'],
    exfil: ['proc.exfil', 'intent.trifecta', 'intent.twoOfThree'],
    chain: ['intent.chainDone', 'intent.chain', 'intent.predict'],
    odd: ['intent.baseline', 'intent.raised'],
    honesty: ['honesty.claimNoTest', 'honesty.claimFailed', 'honesty.testsEdited', 'honesty.silent', 'honesty.thought'],
    tamper: ['log.tampered'],
  };
  const KEY_CAT = {};
  for (const [c, keys] of Object.entries(AN_CAT)) for (const k of keys) KEY_CAT[k] = c;

  const planOf = () => (snap && snap.fixPlan) || [];
  const stepBy = (ids) => planOf().find((s) => ids.includes(s.id)) || null;
  const firstReason = (s) => (s.reasons && s.reasons[0] ? tp(s.reasons[0].key, s.reasons[0].params) : '');
  const stepAction = (s) => (s.cat === 'manual' ? 'guide' : s.action !== 'off' ? s.action : s.preset);
  const sec = (title, ...kids) => h('div', { class: 'an-sec' }, h('h3', { text: title }), ...kids);

  // How sure AgathOS is per kind of finding, and the matching public technique IDs
  // (MITRE ATT&CK for classic attacks, MITRE ATLAS for attacks on AI systems).
  const CONF = { mcpBad: 'high', hidden: 'high', model: 'high', port: 'high', secret: 'high', approve: 'high', baseUrl: 'high', tamper: 'high',
    inject: 'medium', hijack: 'medium', persist: 'medium', cred: 'medium', exfil: 'medium', destroy: 'medium', secOff: 'medium', honesty: 'medium', supply: 'medium', remote: 'medium',
    chain: 'low', odd: 'low', generic: 'low' };
  const MITRE = { hidden: 'AML.T0051.001 · T1027', inject: 'AML.T0051.001', secret: 'T1552.001', mcpBad: 'T1195.002 · AML.T0053', supply: 'T1195.002 · T1195.001',
    remote: 'AML.T0053 · AML.T0051', hijack: 'AML.T0053 · T1546', approve: 'T1562.001', baseUrl: 'T1557', model: 'AML.T0010.003 · T1204.002', port: 'T1133',
    destroy: 'T1485', persist: 'T1053.005 · T1543.001 · T1547.001', cred: 'T1555 · T1552', secOff: 'T1562.001 · T1562.004', exfil: 'AML.T0057 · T1567 · T1041',
    chain: 'AML.T0051 · T1059', tamper: 'T1070' };
  let anLevel = null;     // 'simple' | 'deep'; follows the view until you pick a tab

  // Evidence rows for the item behind a fix step (or an inventory item).
  function detailsFor(key) {
    if (!snap || !key) return [];
    const [kind, ...rest] = String(key).split(':');
    const id = rest.join(':');
    const out = [];
    const add = (label, value) => { if (value != null && value !== '') out.push([label, String(value)]); };
    if (kind === 'mcp') {
      const m = snap.mcp.find((x) => x.id === id);
      if (m) { add(t('ev.app'), m.app); if (m.transport === 'http') add(t('ev.url'), m.url); else add(t('ev.command'), [m.command, ...(m.args || [])].join(' ')); add(t('ev.file'), m.file); }
    } else if (kind === 'file') {
      const f = snap.files.find((x) => x.id === id);
      if (f) add(t('ev.file'), f.path);
    } else if (kind === 'model') {
      const m = snap.models.find((x) => planOf().some((s) => s.tkey === key && s.target && s.target.path === x.path)) || null;
      if (m) { add(t('ev.file'), m.path); add(t('ev.format'), m.format); add(t('ev.size'), `${(m.size / 1048576).toFixed(1)} MB`); }
    } else if (kind === 'port') {
      const p = snap.ports.find((x) => String(x.port) === id);
      if (p) { add(t('ev.address'), `${p.addr}:${p.port}`); add(t('ev.process'), `${p.process || '?'} · PID ${p.pid}`); }
    } else if (kind === 'auto') {
      const a = snap.autostarts.find((x) => x.id === id);
      if (a) { add(t('ev.command'), a.command); add(t('ev.where'), a.where); }
    } else if (kind === 'agent') {
      const a = snap.agents.find((x) => x.id === id);
      const r = a && a.running[0];
      if (a) {
        if (r) { add('PID', r.pid); add(t('card.parent'), r.parent); add(t('card.signer'), r.signer ? (r.signer.valid ? r.signer.signer : `${t('card.unsigned')} (${r.signer.status})`) : ''); add(t('ev.command'), r.cmd); }
        add(t('card.task'), a.task);
        const on = ['untrusted', 'private', 'exit'].filter((k) => a.labels && a.labels[k]).map((k) => t('label.' + k));
        if (on.length) add(t('card.labels'), on.join(' + '));
        if (a.prediction) add(t('card.next'), `${t('act.' + a.prediction.action)} · ${Math.round(a.prediction.p * 100)}%`);
        add(t('card.score'), a.score);
        if (a.actions && a.actions.length) add(t('card.recent'), a.actions.slice(0, 6).map((x) => `${clock(x.ts)} ${t('act.' + x.action)} ${x.detail || ''}`).join('\n'));
      }
    }
    return out;
  }
  const keyOfItem = (kind, x) => (kind === 'model' ? (planOf().find((s) => s.target && s.target.path === x.path) || {}).tkey : `${kind}:${kind === 'port' ? x.port : x.id}`);

  function rawParams(r) {
    const p = Object.entries(r.params || {}).filter(([, v]) => v != null && v !== '' && String(v).length < 300);
    return p.length ? p.map(([k, v]) => `${k}: ${v}`).join('\n') : '';
  }

  function analyse(item, step) {
    const all = item.reasons || [];
    const reasons = all.filter((r) => r.sev !== 'calm').length ? all.filter((r) => r.sev !== 'calm') : all;
    const cats = [...new Set(reasons.map((r) => KEY_CAT[r.key] || 'generic'))].slice(0, 3);
    if (!cats.length) cats.push('generic');
    const sev = item.sev || worst(reasons.map((r) => r.sev));
    const act = step ? stepAction(step) : null;
    const canFix = step && act && act !== 'off' && act !== 'guide';
    const key = (step && step.tkey) || item.key || null;
    const level = anLevel || (mode === 'simple' ? 'simple' : 'deep');
    const conf = cats.map((c) => CONF[c] || 'low').reduce((a, b) => ({ high: 3, medium: 2, low: 1 }[b] > { high: 3, medium: 2, low: 1 }[a] ? b : a), 'low');
    const todo = (c) => t(c === 'port' && isMac() ? 'an.port.todoMac' : `an.${c}.todo`);
    const tabs = h('div', { class: 'seg an-tabs', role: 'tablist' }, ['simple', 'deep'].map((l) => h('button', {
      class: `seg-btn${level === l ? ' is-active' : ''}`, type: 'button', role: 'tab', 'aria-selected': level === l ? 'true' : 'false',
      text: t('an.tab.' + l), onclick: () => { anLevel = l; analyse(item, step); } })));
    const details = item.details || detailsFor(key);
    const body = level === 'simple' ? [
      h('p', { class: 'an-simple', text: cats.map((c) => t(`an.${c}.simple`)).join(' ') }),
      sec(t('an.todo'), cats.map((c) => h('p', { text: todo(c) }))),
      act ? sec(t('an.fix'), h('p', { text: t('fixdesc.' + act) })) : null,
    ] : [
      sec(t('an.seen'), h('ul', { class: 'reasons' }, reasons.map((r) => h('li', null, h('span', { class: `dot ${r.sev}` }),
        h('div', null, h('div', { text: tp(r.key, r.params) }), rawParams(r) ? h('div', { class: 'code', text: rawParams(r) }) : null))))),
      details.length ? sec(t('an.evidence'), h('dl', { class: 'an-ev' }, details.map(([k, v]) => [h('dt', { text: k }), h('dd', { class: k === t('ev.command') || k === t('card.recent') ? 'mono' : '', text: v })]))) : null,
      sec(t('an.how'), cats.map((c) => h('p', { text: t(`an.${c}.deep`) }))),
      sec(t('an.maybe'), cats.map((c) => h('p', { text: t(`an.${c}.maybe`) }))),
      sec(t('an.risk'), cats.map((c) => h('p', { text: t(`an.${c}.risk`) }))),
      h('div', { class: 'an-meta' },
        h('div', null, h('h3', { text: t('an.confidence') }), h('span', { class: `an-conf ${conf}`, text: t('an.conf.' + conf) })),
        cats.some((c) => MITRE[c]) ? h('div', null, h('h3', { text: t('an.mitre') }), h('span', { class: 'mono', text: cats.map((c) => MITRE[c]).filter(Boolean).join(' · ') })) : null),
      sec(t('an.steps'), h('ol', { class: 'an-steps' }, cats.map((c) => h('li', { text: todo(c) })), act && act !== 'guide' ? h('li', { text: `${t('fix.title')}: ${t('fixact.' + act)}. ${t('fixdesc.' + act)}` }) : null)),
    ];
    fill($('anBody'),
      h('div', { class: 'sheet-head' },
        h('div', null, h('h2', { class: 'modal-title', text: item.name || t('an.title') }), h('span', { class: `an-sev ${sev}`, text: t('an.sev.' + sev) })),
        tabs),
      item.where ? h('div', { class: 'code', text: item.where }) : null,
      ...body,
      h('div', { class: 'sheet-foot' },
        key && A.fixDismiss ? h('button', { class: 'btn-ghost', type: 'button', text: t('fix.dismiss'), title: t('fix.dismissHint'),
          onclick: async () => { $('anDlg').close(); const r = await A.fixDismiss(key); if (r && r.ok) { toast(t('fix.dismissed', { name: item.name || '' })); dropRow(key); } } }) : null,
        h('span', { class: 'grow' }),
        canFix ? h('button', { class: `btn-primary${act === 'kill' ? ' danger' : ''}`, type: 'button', text: `${t('fix.title')}: ${t('fixact.' + act)}`,
          onclick: async () => {
            $('anDlg').close();
            const res = await A.fixApply([{ id: step.id, action: act }]);
            const r = res && res[0];
            toast(r && r.ok ? `${t('fix.ok')}: ${step.name}` : `${t('fix.fail')}: ${step.name}${r ? ' · ' + failText(r) : ''}`);
          } }) : null,
        h('button', { class: 'btn-ghost', type: 'button', text: t('close'), onclick: () => $('anDlg').close() })));
    if (!$('anDlg').open) { $('anDlg').showModal(); $('anBody').scrollTop = 0; }
  }
  // After a dismiss inside the fix dialog: take the row out.
  function dropRow(key) {
    if (!$('fixDlg').open || fixResults) return;
    fixRows = fixRows.filter((s) => s.tkey !== key);
    renderFixDlg();
  }

  // An event in the log: use the inventory item it points at when there is one.
  function analyseEvent(e) {
    const tg = e.target || {};
    let reasons = [{ key: e.key, params: e.params, sev: e.sev }];
    let name = tp(e.key, e.params).slice(0, 90);
    let where = '';
    let step = null;
    const merge = (list) => { for (const r of list || []) if (r.sev !== 'calm' && !reasons.some((x) => x.key === r.key)) reasons.push(r); };
    if (tg.type === 'mcp') {
      const m = snap.mcp.find((x) => x.id === tg.id);
      if (m) { name = m.name; where = `${m.app} · ${m.file || ''}`; merge(m.reasons); }
      step = stepBy([`mcp:${tg.id}`]);
    } else if (tg.type === 'file') {
      const f = snap.files.find((x) => x.id === tg.id);
      if (f) { name = f.path.split(/[\\/]/).pop(); where = f.short || f.path; reasons = []; merge(f.reasons); }
      step = stepBy([`inject:${tg.id}`, `hidden:${tg.id}`, `manual:${tg.id}`]);
    } else if (tg.type === 'port') {
      step = stepBy([`port:${tg.port}`]);
    } else if (tg.type === 'auto') {
      step = stepBy([`auto:${tg.id}`, `manual:${tg.id}`]);
    }
    if (!step && e.agentId) {
      const a = snap.agents.find((x) => x.id === e.agentId);
      if (a) { where = a.name; merge(a.reasons); }
      step = stepBy([`agent:${e.agentId}`, `manual:flag:${e.agentId}`]);
    }
    const key = (step && step.tkey) || (tg.type === 'mcp' || tg.type === 'file' || tg.type === 'auto' ? `${tg.type}:${tg.id}` : tg.type === 'port' ? `port:${tg.port}` : e.agentId ? `agent:${e.agentId}` : null);
    analyse({ name, where, sev: e.sev, reasons, key }, step);
  }

  async function restoreKey(key) {
    const r = await A.fixRestore(key);
    if (r && r.ok) toast(t('fix.restore'));
    if ($('fixDlg').open && fixMode === 'dismissed') { fixRows = fixRows.filter((x) => x.key !== key); renderFixDlg(); }
  }

  function failText(r) {
    if (r.needGuard) return t('fix.needGuard');
    if (r.error === 'jsonc') return t('fix.err.jsonc');
    if (r.error === 'changed since') return t('fix.err.changed');
    return t('fix.err.other');
  }

  // ---------- fix it: panel on the overview ----------
  function renderFix() {
    const p = $('fixPanel');
    if (!snap || !snap.lastScan) { p.hidden = true; return; }
    p.hidden = false;
    const plan = planOf();
    const a = plan.filter((s) => s.sev === 'alarm' && s.cat !== 'manual').length;
    const w = plan.filter((s) => s.sev === 'watch' && s.cat !== 'manual').length;
    const m = plan.filter((s) => s.cat === 'manual').length;
    const state = plan.some((s) => s.sev === 'alarm') ? 'alarm' : plan.length ? 'watch' : 'calm';
    p.className = `fix-panel ${state}${fresh ? ' is-fresh' : ''}`;
    const fix = snap.settings.fix || {};
    const picks = plan.filter((s) => s.cat !== 'manual' && s.action !== 'off');
    const title = !plan.length ? t('fix.none') : plan.length === 1 ? t('fix.one') : t('fix.many', { n: plan.length });
    const kids = [
      h('div', { class: 'fix-head' },
        h('div', null, h('h2', { text: title }), plan.length ? h('p', { text: t('fix.sub', { a, w, m }) }) : null),
        plan.length ? h('div', { class: 'fix-btns' },
          picks.length ? h('button', { class: `btn-primary${state === 'alarm' ? ' danger' : ''}`, type: 'button', text: `${t('fix.all')} (${picks.length})`, onclick: () => openFix('all') }) : null,
          h('button', { class: 'btn-ghost small', type: 'button', text: t('fix.choose'), onclick: () => openFix('choose') })) : null),
      h('div', { class: 'fix-auto' },
        h('span', { class: fix.auto ? 'on' : '', text: t('set.fixAuto') }),
        autoSeg(fix, fix.level === 'custom'),
        h('button', { class: 'link', type: 'button', text: t('fix.autoSet'), onclick: () => { show('settings'); setTimeout(() => { const g = $('setFix'); if (g) g.scrollIntoView({ block: 'start', behavior: 'smooth' }); }, 60); } })),
    ];
    if (mode === 'simple' && plan.length) {
      kids.push(h('ul', { class: 'fix-list' }, plan.slice(0, 8).map((s) => h('li', null,
        h('span', { class: `dot ${s.sev}` }),
        h('span', null, h('b', { text: s.name }), ` · ${firstReason(s)}`),
        btn(t('fix.why'), () => analyse(s, s))))));
    }
    const dis = snap.dismissed || [];
    if (dis.length) kids[1].appendChild(h('button', { class: 'link', type: 'button', text: t('fix.dismissedList', { n: dis.length }), onclick: () => openFix('dismissed') }));
    const recent = (snap.remedies || []).filter((r) => Date.now() - r.at < 86400000 && !r.undone).slice(0, 3);
    if (recent.length) {
      kids.push(h('div', null, h('div', { class: 'field-label', text: t('fix.recent') }), h('ul', { class: 'fix-recent' }, recent.map((r) => h('li', null,
        h('span', { class: 'dot calm' }),
        h('span', { class: 'what', text: `${clock(r.at)} · ${t('fixact.' + r.action)}: ${r.name}` }),
        r.canUndo ? btn(t('fix.undo'), () => undoFix(r.rid)) : h('span', { class: 'chip', text: t('fix.noUndo') }))))));
    }
    fill(p, kids);
  }

  // Auto-fix in one control: Off, or the level it works at. Off is the default.
  function autoSeg(fix, withCustom) {
    const cur = fix.auto ? fix.level : 'off';
    const opts = ['off', 'gentle', 'firm', 'max', ...(withCustom ? ['custom'] : [])];
    return h('div', { class: 'seg', role: 'group', 'aria-label': t('set.fixAuto') }, opts.map((l) => h('button', {
      class: `seg-btn${cur === l ? ' is-active' : ''}`, type: 'button', 'aria-pressed': cur === l ? 'true' : 'false',
      text: l === 'off' ? t('off') : t('fix.level.' + l),
      onclick: () => save({ fix: l === 'off' ? { auto: false } : { auto: true, level: l } }),
    })));
  }

  async function undoFix(rid) {
    const r = await A.fixUndo(rid);
    toast(r && r.ok ? t('fix.undone') : `${t('fix.fail')}${r && r.error ? ' · ' + failText(r) : ''}`);
    if (fixResults) { const x = fixResults.find((y) => y.rid === rid); if (x && r && r.ok) { x.undone = true; renderFixDlg(); } }
  }

  // ---------- fix it: the dialog ----------
  let fixMode = 'choose';
  let fixRows = [];
  let fixSel = {};
  let fixResults = null;
  function openFix(m) {
    fixMode = m;
    fixResults = null;
    const plan = planOf();
    fixRows = m === 'dismissed' ? (snap.dismissed || []).slice() : m === 'all' ? plan.filter((s) => s.cat !== 'manual' && s.action !== 'off') : plan;
    fixSel = {};
    for (const s of plan) fixSel[s.id] = s.action;
    renderFixDlg();
    if (!$('fixDlg').open) $('fixDlg').showModal();
  }
  function renderFixDlg() {
    const level = ((snap && snap.settings.fix) || {}).level || 'firm';
    const chosen = fixRows.filter((s) => s.cat !== 'manual' && fixSel[s.id] && fixSel[s.id] !== 'off');
    const sub = fixResults ? t('fix.results')
      : fixMode === 'all' ? t('fix.allConfirm', { n: chosen.length, level: t('fix.level.' + level) })
        : `${t('fix.level')}: ${t('fix.level.' + level)} · ${t(`fix.level.${level}Desc`)}`;
    if (fixMode === 'dismissed') {
      fill($('fixBody'),
        h('div', { class: 'sheet-head' }, h('div', null, h('h2', { class: 'modal-title', text: t('fix.dismissedList', { n: fixRows.length }) }), h('p', { class: 'sheet-sub', text: t('fix.dismissHint') }))),
        fixRows.length ? h('ul', { class: 'steps' }, fixRows.map((d) => h('li', { class: 'step' }, h('span', { class: `dot ${d.sev || 'watch'}` }),
          h('div', null, h('div', { class: 'step-name', text: d.name }), h('div', { class: 'step-why', text: new Date(d.at).toLocaleString(lang) })),
          h('div', { class: 'step-ctl' }, btn(t('fix.restore'), () => restoreKey(d.key)))))) : h('p', { class: 'sheet-sub', text: t('fix.none') }),
        h('div', { class: 'sheet-foot' }, h('button', { class: 'btn-ghost', type: 'button', text: t('close'), onclick: () => $('fixDlg').close() })));
      return;
    }
    const dismissBtn = (s) => (s.tkey && A.fixDismiss ? btn(t('fix.dismiss'), async () => { const r = await A.fixDismiss(s.tkey); if (r && r.ok) { toast(t('fix.dismissed', { name: s.name })); dropRow(s.tkey); } }) : null);
    const rows = fixRows.map((s) => {
      const res = fixResults && fixResults.find((r) => r.stepId === s.id);
      const cls = `step${res ? (res.ok ? ' done' : ' failed') : ''}`;
      let ctl;
      if (fixResults) {
        ctl = [res && res.ok && res.undo && !res.undone ? btn(t('fix.undo'), () => undoFix(res.rid)) : null, btn(t('fix.why'), () => analyse(s, s))];
      } else if (s.cat === 'manual') {
        ctl = [h('span', { class: 'manual', text: t('fix.manual') }), btn(t('fix.why'), () => analyse(s, s)), dismissBtn(s)];
      } else if (fixMode === 'all') {
        ctl = [h('span', { class: 'manual', text: t('fixact.' + fixSel[s.id]) }), btn(t('fix.why'), () => analyse(s, s)), dismissBtn(s)];
      } else {
        ctl = [h('select', { 'aria-label': s.name, onchange: (e) => { fixSel[s.id] = e.target.value; renderFixDlg(); } },
          s.options.map((o) => h('option', { value: o, selected: fixSel[s.id] === o, text: t('fixact.' + o) }))), btn(t('fix.why'), () => analyse(s, s)), dismissBtn(s)];
      }
      const why = res ? (res.ok ? `${t('fix.ok')}: ${t('fixact.' + res.action)}${res.needGuard ? ' · ' + t('fix.needGuard') : ''}${res.undone ? ' · ' + t('fix.undone') : ''}` : `${t('fix.fail')}: ${failText(res)}`)
        : [firstReason(s), s.where].filter(Boolean).join(' · ');
      return h('li', { class: cls }, h('span', { class: `dot ${s.sev}` }), h('div', null, h('div', { class: 'step-name', text: s.name }), h('div', { class: 'step-why', text: why })), h('div', { class: 'step-ctl' }, ctl));
    });
    fill($('fixBody'),
      h('div', { class: 'sheet-head' }, h('div', null, h('h2', { class: 'modal-title', text: t('fix.title') }), h('p', { class: 'sheet-sub', text: sub }))),
      rows.length ? h('ul', { class: 'steps' }, rows) : h('p', { class: 'sheet-sub', text: t('fix.none') }),
      h('div', { class: 'sheet-foot' },
        fixResults ? null : h('span', { class: 'grow', text: chosen.length ? '' : t('fix.applyNone') }),
        h('button', { class: 'btn-ghost', type: 'button', text: fixResults ? t('close') : t('cancel'), onclick: () => $('fixDlg').close() }),
        fixResults ? null : h('button', { class: `btn-primary${chosen.some((s) => fixSel[s.id] === 'kill') ? ' danger' : ''}`, type: 'button', disabled: !chosen.length,
          text: t('fix.apply', { n: chosen.length }),
          onclick: async (e) => {
            e.target.disabled = true;
            e.target.textContent = t('scanning');
            const res = await A.fixApply(chosen.map((s) => ({ id: s.id, action: fixSel[s.id] })));
            fixResults = Array.isArray(res) ? res : [];
            renderFixDlg();
          } })));
  }

  // ---------- agents ----------
  function reasonList(reasons) {
    if (!reasons || !reasons.length) return h('div', { class: 'field-value', style: 'color:var(--dim)', text: t('card.noReasons') });
    return h('ul', { class: 'reasons' }, reasons.map((r) => h('li', null, h('span', { class: `dot ${r.sev}` }), h('span', { text: tp(r.key, r.params) }))));
  }
  function field(label, ...value) { return h('div', null, h('div', { class: 'field-label', text: label }), ...value); }
  const adv = (n) => { if (n) n.classList.add('adv'); return n; };
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
        body.push(adv(field(t('card.parent'), h('div', { class: 'field-value', text: run0.parent || '?' }))));
        body.push(adv(field(t('card.signer'), h('div', { class: 'field-value', text: run0.signer ? (run0.signer.valid ? run0.signer.signer : `${t('card.unsigned')} (${run0.signer.status})`) : '…' }))));
        body.push(adv(h('div', { style: 'grid-column:1/-1' }, field('PID ' + run0.pid, h('div', { class: 'code', text: run0.cmd || run0.exe || '' })))));
        if (run0.flags && run0.flags.length) body.push(field(t('card.flags'), h('div', { class: 'flag', text: run0.flags.join(' ') })));
      }
      if (a.task) body.push(field(t('card.task'), h('div', { class: 'field-value', text: a.task })));
      body.push(adv(field(t('card.labels'), trifecta(a.labels))));
      if (a.prediction) body.push(adv(field(t('card.next'), h('div', { class: 'field-value', text: `${t('act.' + a.prediction.action)} · ${Math.round(a.prediction.p * 100)}%` }))));
      body.push(h('div', { style: 'grid-column:1/-1' }, field(t('card.why'), reasonList(a.reasons))));
      if (a.domains && a.domains.length) body.push(adv(h('div', { style: 'grid-column:1/-1' }, field(t('card.domains'), h('div', { class: 'domains' }, a.domains.map((d) => h('span', { class: 'chip', text: d }))))))) ;
      if (a.actions && a.actions.length) {
        body.push(adv(h('div', { style: 'grid-column:1/-1' }, field(t('card.recent'), h('ul', { class: 'actions-list' },
          a.actions.slice(0, 20).map((x) => h('li', null, h('span', { text: clock(x.ts) }), h('span', { class: 'a', text: t('act.' + x.action) }), h('span', { class: 'd', text: x.detail || '' }))))))));
      }
      if (!run0 && a.dirs.length) body.push(field(t('card.where'), h('div', { class: 'field-value', text: a.dirs.join(', ') })));
      const btns = [];
      if (a.state !== 'calm') btns.push(btn(t('fix.why'), () => analyse({ name: a.name, where: run0 ? `PID ${run0.pid}` : '', sev: a.state, reasons: a.reasons, key: `agent:${a.id}` }, stepBy([`agent:${a.id}`, `manual:flag:${a.id}`]))));
      if (run0) {
        btns.push(a.paused ? h('button', { class: 'btn-small ice', type: 'button', text: t('btn.resume'), onclick: () => run(A.resume(a.id)) })
          : h('button', { class: 'btn-small ice', type: 'button', text: t('btn.freeze'), onclick: () => run(A.freeze(a.id)) }));
        btns.push(h('button', { class: 'btn-small danger', type: 'button', text: t('btn.kill'), onclick: () => run(A.kill(a.id)) }));
        btns.push(adv(h('button', { class: 'btn-small', type: 'button', text: t('btn.block'), onclick: () => run(A.block(a.id, true)) })));
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
        h('div', { class: 'row-actions' },
          x.dismissed ? [h('span', { class: 'chip', text: t('fix.dismissedChip') }), btn(t('fix.restore'), () => restoreKey(x.dismissed)),
            btn(t('fix.why'), () => analyse({ name: opts.name(x), where: opts.where(x), sev: x.origState, reasons: x.reasons, key: x.dismissed }, null))] : null,
          !x.dismissed && x.state !== 'calm' ? btn(t('fix.why'), () => { const st = opts.step ? opts.step(x) : null; analyse({ name: opts.name(x), where: opts.where(x), sev: x.state, reasons: x.reasons, key: (st && st.tkey) || (opts.key ? opts.key(x) : null) }, st); }) : null,
          opts.actions && !x.dismissed ? opts.actions(x) : null)),
      h('span', { class: `state-text ${x.state}`, text: x.dismissed ? t('fix.dismissedChip') : t('state.' + x.state) }))));
  }
  const btn = (label, fn, cls = '') => h('button', { class: `btn-small ${cls}`, type: 'button', text: label, onclick: fn });

  function renderMcp() {
    rowList($('mcpRows'), snap ? snap.mcp : [], {
      step: (m) => stepBy([`mcp:${m.id}`]), key: (m) => `mcp:${m.id}`,
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
        name: (a) => a.name, where: (a) => a.command.slice(0, 200), step: (a) => stepBy([`auto:${a.id}`, `manual:${a.id}`]), key: (a) => `auto:${a.id}`,
        actions: (a) => (a.state !== 'calm' ? [btn(t('btn.ignore'), () => run(A.trust({ type: 'auto', id: a.id })))] : []),
      });
      return;
    }
    rowList($('fileRows'), groups[fileTab], {
      name: (f) => f.path.split(/[\\/]/).pop(), where: (f) => f.short || f.path, step: (f) => stepBy([`inject:${f.id}`, `hidden:${f.id}`, `manual:${f.id}`]), key: (f) => `file:${f.id}`,
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
      step: (m) => planOf().find((s) => s.target && s.target.path === m.path) || null,
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
      step: (p) => stepBy([`port:${p.port}`]), key: (p) => `port:${p.port}`,
      name: (p) => `${p.product} · ${p.port}`, where: (p) => `${p.addr}:${p.port} · ${p.process || ''} · PID ${p.pid}`,
      actions: (p) => (!p.exposed ? [] : isMac() ? [btn(t('btn.how'), () => modal(t('btn.how'), t('an.port.todoMac')))]
        : [btn(t('btn.localOnly'), () => run(A.localOnly(p.port, true), t('fw.localOnly', { port: p.port })), 'fix'), btn(t('btn.how'), () => modal(t('btn.how'), t('fix.port')))]),
    });
    if (isMac()) {
      fill($('networkBody'), h('div', { class: 'stack' },
        h('div', null, h('h2', { class: 'panel-title', style: 'margin-left:0', text: t('net.ports') }), ports),
        h('div', { class: 'box' }, h('div', { class: 'box-row' }, h('h2', { text: t('guard.title') })), h('p', { text: t('mac.guard') }))));
      return;
    }
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
          : btn(t('guard.install'), installGuard, 'fix'))));
  }
  async function installGuard() {
    modal(t('guard.title'), t('guard.uac'));
    const r = await A.guardInstall();
    if ($('modal').open) $('modal').close();
    modal(t('guard.title'), r && r.ok ? t('guard.done') : t('guard.failed'));
  }

  function renderLog() {
    const list = snap ? snap.events : [];
    fill($('logRows'), list.length ? list.map(eventItem) : h('li', { class: 'rows-empty', text: t('empty') }));
  }

  // ---------- settings ----------
  function sw(on, fn) { return h('button', { class: 'switch', type: 'button', role: 'switch', 'aria-checked': on ? 'true' : 'false', onclick: fn }); }
  async function save(patch) { if (!A.settings) return; await A.settings(patch); toast(t('set.saved')); }
  function setRow(label, control, small, cls) {
    return h('div', { class: cls ? `set ${cls}` : 'set' }, h('div', { class: 'set-label' }, h('span', { text: label }), small ? h('small', { text: small }) : null), h('div', { class: 'set-control' }, control));
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
    const fix = s.fix || { auto: false, level: 'firm', minSev: 'alarm', custom: {} };
    const CATS = { agent: ['off', 'freeze', 'block', 'kill'], port: ['off', 'localOnly'], mcp: ['off', 'disable'], hidden: ['off', 'clean'], inject: ['off', 'quarantine'], model: ['off', 'quarantine'], auto: ['off', 'disableTask'] };
    const fixLevel = h('div', { class: 'seg' }, ['gentle', 'firm', 'max', 'custom'].map((l) => h('button', { class: `seg-btn${fix.level === l ? ' is-active' : ''}`, type: 'button', text: t('fix.level.' + l), onclick: () => save({ fix: { level: l } }) })));
    const fixMin = h('select', { onchange: (e) => save({ fix: { minSev: e.target.value } }) }, ['alarm', 'watch'].map((n) => h('option', { value: n, selected: fix.minSev === n, text: t('set.fixMin.' + n) })));
    const custom = fix.level === 'custom' ? Object.entries(CATS).map(([cat, opts]) => setRow(t('fixcat.' + cat),
      h('select', { onchange: (e) => save({ fix: { custom: { [cat]: e.target.value } } }) }, opts.map((o) => h('option', { value: o, selected: (fix.custom || {})[cat] === o, text: t('fixact.' + o) }))))) : [];
    const modeSeg = h('div', { class: 'seg' }, ['advanced', 'simple'].map((m) => h('button', { class: `seg-btn${mode === m ? ' is-active' : ''}`, type: 'button', text: t('mode.' + m), onclick: () => setUi({ mode: m }) })));
    const g = snap.guard || {};
    const guardBtn = g.installed
      ? btn(t('guard.uninstall'), async () => { const r = await A.guardUninstall(); toast(r && r.ok ? t('guard.removed') : t('guard.failed')); })
      : btn(t('guard.install'), installGuard, 'fix');
    fill(body,
      h('section', { class: 'set-group', id: 'setFix' }, h('h2', { text: t('set.fix') }),
        setRow(t('set.fixAuto'), autoSeg(fix, true), fix.auto ? t(`fix.level.${fix.level}Desc`) : t('set.fixAutoDesc')),
        fix.auto ? null : setRow(`${t('fix.level')} · ${t('fix.title')}`, fixLevel, t(`fix.level.${fix.level}Desc`)),
        setRow(t('set.fixMin'), fixMin),
        ...custom),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.notify') }),
        setRow(t('set.notify'), notifySel),
        setRow(t('set.snooze'), h('div', { class: 'seg' },
          [['off', t('set.snoozeOff')], ['1h', t('set.snooze1h')], ['tomorrow', t('set.snoozeTomorrow')]].map(([k, label]) => h('button', {
            class: `seg-btn${k === 'off' && !(snap.snoozeUntil > Date.now()) ? ' is-active' : ''}`, type: 'button', text: label,
            onclick: async () => { await A.snooze(k); toast(t('set.saved')); } }))),
        snap.snoozeUntil > Date.now() ? t('snooze.until', { t: clock(snap.snoozeUntil) }) : null)),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.view') }),
        setRow(t('set.view'), modeSeg, t('set.modeDesc')),
        setRow(t('set.welcome'), btn(t('set.welcomeBtn'), () => openWelcome()))),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.protection') }),
        setRow(t('set.level'), levelSeg),
        setRow(t('set.autoFreeze'), sw(s.autoFreezeOnMassDelete, () => save({ autoFreezeOnMassDelete: !s.autoFreezeOnMassDelete }))),
        setRow(t('set.threshold'), num(s.massDeleteThreshold, 10, 1000, 'massDeleteThreshold', t('set.files10s')), null, 'adv'),
        setRow(t('set.portCheck'), sw(s.portCheck, () => save({ portCheck: !s.portCheck })), null, 'adv'),
        setRow(t('set.dlGuard'), sw(s.downloadGuard !== false, () => save({ downloadGuard: s.downloadGuard === false })), t('set.dlGuardDesc')),
        setRow(t('set.hotkey'), sw(s.hotkey, () => save({ hotkey: !s.hotkey })), null, 'adv'),
        isMac() ? setRow(t('guard.title'), h('span'), t('mac.guard')) : setRow(t('guard.title'), guardBtn, t('guard.desc'))),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.watching') }),
        setRow(t('set.realtime'), sw(s.realtime, () => save({ realtime: !s.realtime }))),
        setRow(t('set.poll'), num(s.pollSeconds, 2, 60, 'pollSeconds', t('set.seconds')), null, 'adv'),
        setRow(t('set.fullScan'), num(s.fullScanHours, 1, 48, 'fullScanHours', t('set.hours')), null, 'adv'),
        h('div', { class: 'set adv' }, h('div', { class: 'set-label' }, h('span', { text: t('set.roots') })), h('div', { class: 'set-control' }, btn(t('set.add'), () => A.addFolder('roots'))), folders(s.roots, 'roots')),
        h('div', { class: 'set adv' }, h('div', { class: 'set-label' }, h('span', { text: t('set.modelDirs') })), h('div', { class: 'set-control' }, btn(t('set.add'), () => A.addFolder('models'))), folders(s.modelDirs, 'models'))),
      h('section', { class: 'set-group adv' }, h('h2', { text: t('set.smart') }),
        setRow(t('set.learning'), [btn(t('set.rollback'), async () => { if (await A.rollback()) toast(t('set.rolledBack')); }), btn(t('set.reset'), async () => { await A.forget(); toast(t('set.forgot')); }), sw(s.learning, () => save({ learning: !s.learning }))]),
        setRow(t('set.judge'), sw(s.judge.enabled, () => save({ judge: { enabled: !s.judge.enabled } })), t('set.judgeDesc')),
        s.judge.enabled ? setRow(t('set.judgeModel'), judgeSel) : null),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.updates') }),
        setRow(t('set.version', { v: (snap.update && snap.update.current) || A.version || '' }), btn(t('set.updatesNow'), async (e) => {
          e.target.textContent = t('upd.checking');
          const u = await A.checkUpdate();
          e.target.textContent = t('set.updatesNow');
          modal(t('set.updates'), !u || u.status === 'unreachable' ? t('upd.unreachable') : u.status === 'newer' ? t('upd.available', { v: u.version }) : t('upd.latest', { v: u.current }));
        }), snap.update && snap.update.status === 'newer' ? t('upd.available', { v: snap.update.version }) : null),
        setRow(t('set.updatesAuto'), sw(s.updates !== false, () => save({ updates: s.updates === false })))),
      h('section', { class: 'set-group' }, h('h2', { text: t('set.app') }),
        setRow(startupLabel(), sw(s.startWithWindows, () => save({ startWithWindows: !s.startWithWindows }))),
        setRow(t('set.tray'), sw(s.closeToTray, () => save({ closeToTray: !s.closeToTray }))),
        setRow(t('set.logDays'), num(s.logDays, 1, 365, 'logDays', t('set.days')), null, 'adv'),
        setRow(t('set.api'), sw(s.api, () => save({ api: !s.api })), `127.0.0.1:${snap.apiPort}`, 'adv'),
        setRow(t('report.save'), btn(t('report.save'), async () => { const r = await A.saveReport(); if (r && r.ok) toast(t('report.saved')); }), t('report.desc')),
        setRow(t('set.verify'), btn(t('set.verify'), async () => { const r = await A.verifyLog(); modal(t('set.verify'), r.ok ? t('set.verifyOk', { n: r.lines }) : t('set.verifyBad', { n: r.line })); }), null, 'adv')));
  }

  // ---------- check text: paste anything before an agent reads it ----------
  let checkRes = null;
  $('checkRun').addEventListener('click', async () => {
    const text = $('checkInput').value;
    if (!text.trim() || !A.checkText) return;
    checkRes = await A.checkText(text);
    renderCheck();
  });
  $('checkClean').addEventListener('click', async () => { if (checkRes && A.copyText) { await A.copyText(checkRes.clean); toast(t('check.copied')); } });
  $('checkInput').addEventListener('input', () => { $('checkCount').textContent = t('check.chars', { n: [...$('checkInput').value].length }); });
  function renderCheck() {
    $('checkInput').placeholder = t('check.placeholder');
    const box = $('checkResult');
    if (!checkRes) { fill(box); $('checkClean').hidden = true; return; }
    const r = checkRes;
    const found = r.reasons.filter((x) => x.sev !== 'calm');
    $('checkClean').hidden = !r.removed;
    if (!found.length) { fill(box, h('div', { class: 'check-ok', text: t('check.ok') })); return; }
    fill(box, h('div', { class: `box check-out ${r.sev}` },
      h('div', { class: 'box-row' }, h('h2', { text: t('check.found') }), h('span', { class: `an-sev ${r.sev}`, text: t('an.sev.' + r.sev) })),
      reasonList(found),
      r.decoded ? sec(t('check.hiddenText'), h('div', { class: 'code', text: r.decoded })) : null,
      r.removed ? h('p', { text: t('check.removed', { n: r.removed }) }) : null,
      r.secrets && r.secrets.length ? sec(t('check.secrets'), h('div', { class: 'code', text: r.secrets.map((x) => `${x.kind}: ${x.masked}`).join('\n') })) : null,
      h('div', { class: 'event-actions' }, btn(t('fix.why'), () => analyse({ name: t('nav.check'), sev: r.sev, reasons: found }, null)))));
  }

  // ---------- update banner and report ----------
  let updHidden = false;
  function renderUpdate() {
    const u = snap && snap.update;
    const b = $('updBanner');
    if (!u || u.status !== 'newer' || updHidden) { b.hidden = true; return; }
    b.hidden = false;
    fill(b, h('span', { class: 'upd-dot' }), h('span', { text: t('upd.available', { v: u.version }) }),
      h('button', { class: 'btn-small fix', type: 'button', text: isMac() ? t('upd.open') : t('upd.install'), onclick: async () => { toast(t('upd.downloading', { v: u.version })); const r = await A.installUpdate(); if (r && r.ok === false) modal(t('set.updates'), t('upd.failed')); } }),
      h('button', { class: 'btn-small', type: 'button', text: t('upd.later'), onclick: () => { updHidden = true; renderUpdate(); } }));
  }
  $('reportBtn').addEventListener('click', async () => { const r = await A.saveReport(); if (r && r.ok) toast(t('report.saved')); });

  // ---------- welcome: language, view, live scanner, Guard, auto-fix ----------
  const wel = { mode: 'advanced', live: true, startup: true, guard: false, fix: false, level: 'firm' };
  function brandSvg() {
    const n = svg('svg', { viewBox: '-42 -42 84 84', 'aria-hidden': 'true' });
    n.appendChild(svg('path', { d: 'M-35 35 L-35 -35 L35 -35 L35 35 L-21 35 L-21 -21 L21 -21 L21 21 L-7 21 L-7 -7 L7 -7', fill: 'none', stroke: 'currentColor', 'stroke-width': '8', pathLength: '100' }));
    return n;
  }
  function openWelcome() {
    if (snap) {
      const s = snap.settings;
      Object.assign(wel, { mode, live: s.realtime !== false, startup: welcomed ? !!s.startWithWindows : true, guard: false, fix: !!(s.fix && s.fix.auto), level: (s.fix && s.fix.level !== 'custom' && s.fix.level) || 'firm' });
    }
    renderWelcome();
    if (!$('welcome').open) $('welcome').showModal();
  }
  function renderWelcome() {
    const seg = (opts, cur, pick, label) => h('div', { class: 'seg' }, opts.map((o) => h('button', { class: `seg-btn${o === cur ? ' is-active' : ''}`, type: 'button', text: label(o), onclick: () => { pick(o); renderWelcome(); } })));
    const toggle = (k) => sw(wel[k], () => { wel[k] = !wel[k]; renderWelcome(); });
    const langSel = h('select', { class: 'lang-select', 'aria-label': t('wel.lang'), onchange: (e) => { setUi({ lang: e.target.value }); renderWelcome(); } },
      window.LANGS.filter((l) => window.I18N[l.code]).map((l) => h('option', { value: l.code, lang: l.code, selected: l.code === lang, text: l.label })));
    fill($('welBody'),
      h('div', { class: 'wel-brand' }, brandSvg(), h('h2', { class: 'modal-title', text: t('wel.title') })),
      h('p', { class: 'sheet-sub', text: t('wel.sub') }),
      h('div', { class: 'wel-grid' },
        setRow(t('wel.lang'), langSel),
        setRow(t('wel.mode'), seg(['advanced', 'simple'], wel.mode, (v) => { wel.mode = v; }, (v) => (v === 'advanced' ? `${t('mode.advanced')} · ${t('recommended')}` : t('mode.simple'))), wel.mode === 'advanced' ? t('wel.modeAdv') : t('wel.modeSimple')),
        setRow(t('wel.live'), toggle('live'), t('wel.liveDesc')),
        setRow(isMac() ? t('wel.startupMac') : t('wel.startup'), toggle('startup'), t('wel.startupDesc')),
        isMac() ? null : setRow(t('wel.guard'), toggle('guard'), t('wel.guardDesc')),
        setRow(t('wel.fix'), seg(['off', 'gentle', 'firm', 'max'], wel.fix ? wel.level : 'off', (v) => { if (v === 'off') wel.fix = false; else { wel.fix = true; wel.level = v; } },
          (v) => (v === 'off' ? t('off') : t('fix.level.' + v))), wel.fix ? t(`fix.level.${wel.level}Desc`) : t('wel.fixDesc'))),
      h('div', { class: 'sheet-foot' }, h('button', { class: 'btn-primary', type: 'button', text: t('wel.start'), onclick: finishWelcome })));
  }
  // Closing the welcome screen (X, Esc or a click next to it) keeps the safe defaults.
  $('welcome').addEventListener('close', () => {
    if (welcomed) return;
    welcomed = true;
    setUi({ mode: wel.mode, welcomed: true });
  });
  async function finishWelcome() {
    $('welcome').close();
    const first = !welcomed;
    welcomed = true;
    await setUi({ mode: wel.mode, welcomed: true });
    if (A.settings) await A.settings({ realtime: wel.live, startWithWindows: wel.startup, fix: { auto: wel.fix, level: wel.level } });
    toast(t('set.saved'));
    if (wel.guard && !(snap && snap.guard && snap.guard.installed)) await installGuard();
    else if (first && snap && snap.lastScan && planOf().length) { fresh = true; render(); setTimeout(() => { fresh = false; }, 2600); }
  }

  // ---------- main render ----------
  function render() {
    renderChrome();
    renderRing();
    renderStatus();
    if (view === 'overview') { renderFix(); renderLive(); renderWatchers(); renderEvents(); }
    else if (snap && snap.events) snap.events.forEach((e) => seenEvents.add(e.hash));
    if (view === 'agents') renderAgents();
    if (view === 'mcp') renderMcp();
    if (view === 'files') renderFiles();
    if (view === 'models') renderModels();
    if (view === 'network') renderNetwork();
    if (view === 'log') renderLog();
    if (view === 'check') renderCheck();
    renderUpdate();
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
    mode = (ui.mode || local.mode) === 'simple' ? 'simple' : 'advanced';
    welcomed = !!(ui.welcomed || local.welcomed);
    if (!ui.lang && A.ui) A.ui({ lang, theme });
    render();
    A.onUpdate((s) => {
      // A scan that ends with things to fix makes the fix panel pulse once.
      if (snap && snap.scanning && !s.scanning && (s.fixPlan || []).length) { fresh = true; setTimeout(() => { fresh = false; }, 2600); }
      snap = s;
      render();
    });
    const s = await A.snapshot();
    if (s && s.ready) { snap = s; render(); }
    if (!welcomed) openWelcome();
  }
  init();
})();
