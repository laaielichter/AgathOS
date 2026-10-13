'use strict';
// AgathOS - safety report: one self-contained HTML page (no scripts, no external files)
// with the status, all findings, agents, fixes and the last 24 hours. Texts in your language.

const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

function build(snap, tt, lang = 'en', dir = 'ltr') {
  const pad = (n) => String(n).padStart(2, '0');
  const when = (ts) => { const d = new Date(ts); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}`; };
  const tr = (key, params) => {
    const p = { ...(params || {}) };
    if (p.action) p.action = tt('act.' + p.action);
    if (p.fix) p.fix = tt('fixact.' + p.fix);
    if (p.chain) p.chain = tt('chain.' + p.chain);
    if (p.labels) p.labels = String(p.labels).split('+').map((l) => tt('label.' + l)).join(' + ');
    return tt(key, p).replace(/\s{2,}/g, ' ').trim();
  };
  const reasons = (list) => (list || []).filter((r) => r.sev !== 'calm').map((r) => `<li class="${esc(r.sev)}">${esc(tr(r.key, r.params))}</li>`).join('');
  const watchers = (snap.watchers || []).map((w) => `<tr><td><span class="dot ${esc(w.state)}"></span>${esc(tt(`w.${w.id}.name`))}</td><td>${esc(tt('state.' + w.state))}</td><td>${w.issues}</td></tr>`).join('');
  const plan = snap.fixPlan || [];
  const findings = plan.map((s) => `<tr><td><span class="dot ${esc(s.sev)}"></span><b>${esc(s.name)}</b><div class="dim">${esc(s.where || '')}</div></td><td><ul>${reasons(s.reasons)}</ul></td><td>${esc(tt('fixact.' + (s.cat === 'manual' ? 'guide' : s.action)))}</td></tr>`).join('');
  const agents = (snap.agents || []).filter((a) => a.running.length || a.state !== 'calm').map((a) => `<tr><td><span class="dot ${esc(a.state)}"></span><b>${esc(a.name)}</b>${a.version ? ` <span class="dim">${esc(a.version)}</span>` : ''}</td><td>${a.running.length ? `PID ${a.running[0].pid}` : '-'}</td><td>${a.score}</td><td><ul>${reasons(a.reasons)}</ul></td></tr>`).join('');
  const fixes = (snap.remedies || []).map((r) => `<tr><td>${esc(when(r.at))}</td><td>${esc(tt('fixact.' + r.action))}</td><td>${esc(r.name)}</td><td>${r.undone ? esc(tt('fix.undone')) : r.ok ? '✓' : '✕'}</td></tr>`).join('');
  const dismissed = (snap.dismissed || []).map((d) => `<tr><td>${esc(when(d.at))}</td><td>${esc(tt('fix.dismiss'))}</td><td>${esc(d.name)}</td><td></td></tr>`).join('');
  const since = Date.now() - 24 * 3600 * 1000;
  const events = (snap.events || []).filter((e) => e.ts >= since && e.sev !== 'calm').slice(0, 200)
    .map((e) => `<tr><td>${esc(when(e.ts))}</td><td><span class="dot ${esc(e.sev)}"></span>${esc(tr(e.key, e.params))}</td></tr>`).join('');
  const none = `<p class="dim">${esc(tt('report.none'))}</p>`;
  const table = (head, rows) => (rows ? `<table><thead><tr>${head.map((x) => `<th>${esc(x)}</th>`).join('')}</tr></thead><tbody>${rows}</tbody></table>` : none);
  return `<!doctype html>
<html lang="${esc(lang)}" dir="${esc(dir)}"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${esc(tt('report.title'))}</title>
<style>
body{font-family:"Segoe UI Variable Text","Segoe UI",system-ui,sans-serif;margin:32px auto;max-width:1000px;padding:0 20px;color:#151A2E;background:#fff;line-height:1.5}
h1{font-family:Georgia,serif;font-weight:400;font-size:32px;margin:0 0 4px}h2{font-family:Georgia,serif;font-weight:400;font-size:22px;margin:28px 0 8px;border-bottom:2px solid #D9A93A;padding-bottom:4px}
table{width:100%;border-collapse:collapse;font-size:14px}th,td{text-align:start;vertical-align:top;padding:7px 8px;border-bottom:1px solid #DCE0EC}th{color:#5A6282;font-weight:600;font-size:12px}
ul{margin:0;padding-inline-start:18px}li.alarm{color:#B4233F}li.watch{color:#975B0A}.dim{color:#5A6282;font-size:12px}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:#17936A;margin-inline-end:8px}.dot.watch{background:#B86E0E}.dot.alarm{background:#D23A57}
.status{font-size:20px;margin:8px 0}.brand{color:#B88A1E;font-weight:700}
</style></head><body>
<h1>${esc(tt('report.title'))}</h1>
<div class="dim">${esc(tt('report.generated', { t: when(Date.now()) }))} · <span class="brand">AgathOS</span> · ${esc(snap.platform || '')}</div>
<p class="status">${esc(snap.statusLine || '')}</p>
<h2>${esc(tt('watchers.title'))}</h2>${table([tt('watchers.title'), tt('report.state'), tt('report.count')], watchers)}
<h2>${esc(tt('report.findings'))} (${plan.length})</h2>${table([tt('report.what'), tt('an.seen'), tt('fix.title')], findings)}
<h2>${esc(tt('report.agents'))}</h2>${table([tt('report.agents'), 'PID', tt('card.score'), tt('card.why')], agents)}
<h2>${esc(tt('report.fixes'))}</h2>${table([tt('report.when'), tt('fix.title'), tt('report.what'), ''], fixes + dismissed)}
<h2>${esc(tt('report.events'))}</h2>${table([tt('report.when'), tt('report.what')], events)}
</body></html>`;
}

module.exports = { build, esc };
