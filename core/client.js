'use strict';
// AgathOS - the side of an AI program: asking a running AgathOS on this PC, or, when none answers, doing the checks itself.
//
// Connected: the questions go to the local API (api.js) with the key that was given to this program (AGATHOS_TOKEN, or AGATHOS_TOKEN_FILE
// for a file that holds it). Only ever to 127.0.0.1. The key is never looked for in the data folder of AgathOS: a program that was not
// given a key does not get the owner key.
// Alone: a text, a file or a step is checked with the code in ask.js. That needs no AgathOS and no key, but it does not know what runs on
// this PC, so status, findings and reports need the app.
// Whatever comes back, from the app or from ask.js, is cleaned once more before it is handed on (untrusted.js).
const http = require('http');
const fs = require('fs');
const Ask = require('./ask');
const Z = require('./untrusted');

const DEFAULT_PORT = 47612;
const BIG = { items: 200, max: 240 };

function settings(env = process.env) {
  let token = String(env.AGATHOS_TOKEN || '').trim();
  const file = String(env.AGATHOS_TOKEN_FILE || '').trim();
  if (!token && file) { try { token = fs.readFileSync(file, 'utf8').trim(); } catch (_) { token = ''; } }
  const port = Number(env.AGATHOS_PORT);
  return { token: token.slice(0, 200), port: Number.isInteger(port) && port > 0 && port < 65536 ? port : DEFAULT_PORT };
}

// One request to the API. Resolves { status, json } or { error }. Never throws.
function request(method, urlPath, { body, token, port = DEFAULT_PORT, timeout = 4000 } = {}) {
  return new Promise((resolve) => {
    const data = body === undefined ? null : JSON.stringify(body);
    let done = false;
    const end = (r) => { if (!done) { done = true; resolve(r); } };
    const headers = { ...(token ? { Authorization: `Bearer ${token}` } : {}), ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) };
    const req = http.request({ host: '127.0.0.1', port, method, path: urlPath, headers, timeout }, (res) => {
      const chunks = [];
      let size = 0;
      res.on('data', (d) => {
        size += d.length;
        if (size > 4 * 1024 * 1024) { res.destroy(); end({ error: 'toobig' }); } else chunks.push(d);
      });
      res.on('end', () => {
        try { end({ status: res.statusCode, headers: res.headers, json: JSON.parse(Buffer.concat(chunks).toString('utf8')) }); } catch (_) { end({ status: res.statusCode, error: 'badjson' }); }
      });
      res.on('error', () => end({ error: 'unreachable' }));
    });
    req.on('timeout', () => { req.destroy(); end({ error: 'timeout' }); });
    req.on('error', () => end({ error: 'unreachable' }));
    if (data) req.write(data);
    req.end();
  });
}

const WHY = {
  nokey: 'No key was given to this program. Make one in AgathOS under Settings > Agent access and give it to this program as AGATHOS_TOKEN.',
  unreachable: 'AgathOS is not running, or its local API is switched off.',
  timeout: 'AgathOS did not answer in time.',
  key: 'AgathOS does not know this key. It may have been taken back.',
  scope: 'This key may not do that.',
  rate: 'This key has asked too often. Wait a moment.',
  other: 'AgathOS gave an answer this program does not understand.',
};

// The API's answer as { ok, data } or { ok: false, error, message }.
function outcome(r) {
  if (r.error) return { ok: false, error: r.error === 'toobig' || r.error === 'badjson' ? 'other' : r.error, message: WHY[r.error === 'toobig' || r.error === 'badjson' ? 'other' : r.error] || WHY.other };
  if (r.status === 401) return { ok: false, error: 'key', message: WHY.key };
  if (r.status === 403) return { ok: false, error: 'scope', message: r.json && r.json.message ? Z.text(r.json.message, 160) : WHY.scope };
  if (r.status === 429) return { ok: false, error: 'rate', message: WHY.rate, retryMs: r.json && Number(r.json.retryMs) > 0 ? Number(r.json.retryMs) : undefined };
  if (r.status !== 200 || !r.json) return { ok: false, error: 'other', message: WHY.other };
  return { ok: true, data: r.json.untrusted === true ? r.json.data : r.json };
}

function create(env = process.env, { timeout } = {}) {
  const cfg = settings(env);
  const api = async (method, urlPath, body) => {
    if (!cfg.token) return { ok: false, error: 'nokey', message: WHY.nokey };
    return outcome(await request(method, urlPath, { body, token: cfg.token, port: cfg.port, timeout }));
  };
  const clean = (x) => Z.value(x, BIG);
  const done = (mode, data, note) => ({ ok: true, mode, ...clean(data), ...(note ? { note: Z.text(note, 200) } : {}) });
  // A question the app can answer and this code can answer too: the app first, ask.js when the app does not.
  const either = async (ask, local) => {
    const r = await ask();
    if (r.ok) return done('app', r.data);
    const l = local();
    return l.ok === false ? { ...clean(l), mode: 'standalone' } : done('standalone', l, cfg.token ? `${r.message} The checks of this program alone were used.` : '');
  };
  const needsApp = async (ask) => {
    const r = await ask();
    return r.ok ? done('app', r.data) : { ok: false, error: r.error, message: r.message };
  };
  return {
    connected: !!cfg.token,
    port: cfg.port,
    checkText: (text, source) => either(() => api('POST', '/v1/check-text', { text, source }), () => Ask.checkText(text, { file: source })),
    checkFile: (p) => either(() => api('POST', '/v1/check-file', { path: p }), () => Ask.checkFile(p)),
    checkAction: async (tool, input, cwd, agent) => {
      const r = await api('POST', '/v1/check', { agent, tool, input, cwd });
      if (r.ok && r.data && typeof r.data.decision === 'string') return done('app', r.data);
      return done('standalone', Ask.checkAction({ tool, input, cwd }), cfg.token ? `${r.message || WHY.other} The checks of this program alone were used.` : '');
    },
    status: () => needsApp(() => api('GET', '/v1/status')),
    agents: () => needsApp(() => api('GET', '/v1/agents')),
    findings: (limit) => needsApp(() => api('GET', `/v1/findings?limit=${Math.max(1, Math.min(200, Number(limit) || 50))}`)),
    report: (note) => needsApp(() => api('POST', '/v1/report', { note })),
    me: () => needsApp(() => api('GET', '/v1/me')),
  };
}

module.exports = { create, settings, request, outcome, WHY, DEFAULT_PORT };
