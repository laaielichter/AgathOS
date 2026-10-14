'use strict';
// AgathOS - the local API on 127.0.0.1 (never on the network).
//
// For programs of the person who runs AgathOS and for AI programs. What a program may do depends on its key (see agentaccess.js):
//   read     GET   /v1/me  /v1/status  /v1/agents  /v1/findings  /v1/events
//   ask      POST  /v1/check (may I do this step?)  /v1/check-text  /v1/check-file
//   report   POST  /v1/report (tell the person about a worry)
//   pause    POST  /v1/pause-all   (the owner key only)
// There is no route that resumes agents, approves or releases anything or changes a setting: that is for a person in the window.
// POST /v1/resume-all answers that, whoever asks. Every request is written to a log that cannot be changed unnoticed. Answers say that
// they are data (untrusted.js), and the sentences that gave a finding away are never in them (agentview.js).
const http = require('http');
const crypto = require('crypto');
const { AgentAccess } = require('./agentaccess');
const Ask = require('./ask');
const View = require('./agentview');
const Z = require('./untrusted');

const PORT = 47612;
const KB = 1024;
const HOST_OK = /^(?:127\.0\.0\.1|localhost|\[::1\])(?::\d{1,5})?$/i;
const LOOPBACK = /^(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$/;
const BIG = { items: 200, max: 240 };

// Compare the digests, not the texts: timingSafeEqual throws when the two byte lengths differ
// (a header with accented letters has as many characters as the token but more bytes), and a throw
// here would take the whole app down.
const digest = (s) => crypto.createHash('sha256').update(String(s)).digest();
function authOk(header, token) {
  const given = String(header || '').replace(/^Bearer\s+/i, '');
  return !!token && crypto.timingSafeEqual(digest(given), digest(token));
}

function reply(res, code, obj, extra) {
  const body = JSON.stringify(obj);
  res.writeHead(code, {
    'Content-Type': 'application/json; charset=utf-8', 'Content-Length': Buffer.byteLength(body), 'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff', ...(extra || {}),
  });
  res.end(body);
}

// The body of a request, at most `max` bytes. A longer one is not read on.
function readBody(req, max) {
  return new Promise((resolve) => {
    if (Number(req.headers['content-length']) > max) return resolve({ tooBig: true });
    const chunks = [];
    let size = 0;
    let done = false;
    const end = (r) => { if (!done) { done = true; resolve(r); } };
    req.on('data', (d) => {
      size += d.length;
      if (size > max) { chunks.length = 0; end({ tooBig: true }); } else if (!done) chunks.push(d);
    });
    req.on('end', () => end({ text: Buffer.concat(chunks).toString('utf8') }));
    req.on('error', () => end({ failed: true }));
    req.on('close', () => end({ failed: true }));
  });
}

const oneOf = (v, list, other) => (list.includes(v) ? v : other);
const num = (v, min, max, other) => { const n = Number(v); return Number.isFinite(n) ? Math.max(min, Math.min(max, n)) : other; };

// `access` is an AgentAccess, or the data folder to make one in. opts.port: 0 picks a free port (tests).
function start(engine, access, opts = {}) {
  if (typeof access === 'string') access = new AgentAccess(access, { onEvent: (e) => engine.event(e) });
  const port = opts.port === undefined ? PORT : opts.port;

  // scope: what the key must be allowed. cls: the limit that counts it (see agentaccess.js). max: the longest body, in bytes.
  const routes = new Map([
    ['GET /v1/me', { scope: 'read', cls: 'read', run: ({ who }) => ({ body: Z.envelope({ name: who.name, kind: who.kind, scopes: who.scopes }) }) }],
    ['GET /v1/status', { scope: 'read', cls: 'read', run: () => ({ body: Z.envelope(View.status(engine.snapshot())) }) }],
    ['GET /v1/agents', { scope: 'read', cls: 'read', run: () => ({ body: Z.envelope(View.agents(engine.snapshot()), BIG) }) }],
    ['GET /v1/findings', { scope: 'read', cls: 'read', run: ({ url }) => ({ body: Z.envelope(View.findings(engine.snapshot(), { limit: num(url.searchParams.get('limit'), 1, 200, 50) }), BIG) }) }],
    ['GET /v1/events', {
      scope: 'read', cls: 'read',
      run: ({ url }) => ({ body: Z.envelope(View.events(engine.store.events, { since: num(url.searchParams.get('since'), 0, Number.MAX_SAFE_INTEGER, 0), limit: num(url.searchParams.get('limit'), 1, 200, 100) }), BIG) }),
    }],
    ['POST /v1/check', {
      scope: 'ask', cls: 'ask', max: 64 * KB,
      run: ({ who, j }) => {
        const tool = Z.text(j.tool, 100);
        let r;
        try {
          r = engine.checkToolCall({ agent: Z.text(j.agent, 40) || who.name, tool, input: j.input && typeof j.input === 'object' ? j.input : {}, cwd: typeof j.cwd === 'string' ? j.cwd.slice(0, 1000) : undefined });
        } catch (_) {
          r = { decision: 'ask', action: 'UNKNOWN', reason: 'AgathOS could not tell what this step does.' };   // when in doubt, ask the person
        }
        const decision = oneOf(r.decision, ['allow', 'ask', 'deny'], 'ask');
        return { body: { decision, action: Z.text(r.action, 40), ...(r.reason ? { reason: Z.text(r.reason, 200) } : {}) }, info: `${tool} > ${decision}` };
      },
    }],
    ['POST /v1/check-text', {
      scope: 'ask', cls: 'scan', max: 1536 * KB,
      run: ({ j }) => {
        if (typeof j.text !== 'string') return { code: 400, body: { error: 'text' } };
        const r = Ask.checkText(j.text, { file: typeof j.source === 'string' ? j.source : '' });
        return { body: Z.envelope(r, BIG), info: `text ${r.length} > ${r.verdict}` };
      },
    }],
    ['POST /v1/check-file', {
      scope: 'ask', cls: 'scan', max: 8 * KB,
      run: ({ j }) => {
        const r = Ask.checkFile(j.path);
        return { body: Z.envelope(r, BIG), info: `file ${r.file || ''} > ${r.verdict || r.error}` };
      },
    }],
    ['POST /v1/report', {
      scope: 'report', cls: 'report', max: 8 * KB,
      run: ({ who, j }) => {
        engine.event({ key: 'api.report', sev: 'watch', watcher: 'gate', params: { name: who.name, note: Z.text(j.note, 200) } });
        return { body: Z.envelope({ received: true }), info: 'report' };
      },
    }],
    ['POST /v1/pause-all', {
      scope: 'pause', cls: 'admin',
      run: async () => { await engine.pauseAll('api'); return { body: Z.envelope({ pausedAll: true }) }; },
    }],
  ]);

  async function handle(req, res) {
    const t0 = Date.now();
    if (!LOOPBACK.test(req.socket.remoteAddress || '')) return reply(res, 403, { error: 'local only' });
    // A web page in a browser can send requests to 127.0.0.1 too, under a name of its own (DNS rebinding) or with an Origin header.
    if (!HOST_OK.test(String(req.headers.host || ''))) return reply(res, 403, { error: 'host' });
    if (req.headers.origin || req.headers['sec-fetch-site']) return reply(res, 403, { error: 'no browsers' });
    let url;
    try { url = new URL(req.url, 'http://127.0.0.1'); } catch (_) { return reply(res, 400, { error: 'url' }); }
    const where = Z.text(url.pathname, 60);

    const who = access.authenticate(req.headers.authorization);
    if (!who) {
      access.problem('bad');
      access.recordBad({ who: 'unknown', method: Z.text(req.method, 8), path: where, status: 401 });
      return reply(res, 401, { error: 'token' });
    }
    const log = (status, info) => access.record({ who: who.kind, id: who.id, name: who.name, method: req.method, path: where, status, ...(info ? { info: Z.text(info, 80) } : {}), ms: Date.now() - t0 });

    if (req.method === 'POST' && url.pathname === '/v1/resume-all') {
      log(403, 'resume refused');
      return reply(res, 403, { error: 'person only', message: 'Agents can only be resumed by a person in the AgathOS window.' });
    }
    const route = routes.get(`${req.method} ${url.pathname}`);
    if (!route) { log(404); return reply(res, 404, { error: 'unknown' }); }
    if (!who.scopes.includes(route.scope)) { log(403, `needs ${route.scope}`); return reply(res, 403, { error: 'scope', need: route.scope }); }
    const turn = access.take(who, route.cls);
    if (!turn.ok) {
      access.problem('limit', who.name);
      access.recordBad({ who: who.kind, id: who.id, name: who.name, method: req.method, path: where, status: 429 });
      return reply(res, 429, { error: 'rate', retryMs: turn.retryMs }, { 'Retry-After': String(Math.ceil(turn.retryMs / 1000)) });
    }

    let j = {};
    if (req.method === 'POST') {
      const b = await readBody(req, route.max || 64 * KB);
      if (b.tooBig) {
        log(413);
        res.on('finish', () => { try { req.socket.destroy(); } catch (_) { /* gone */ } });
        return reply(res, 413, { error: 'too big' }, { Connection: 'close' });
      }
      if (b.failed) return undefined;
      try { j = b.text ? JSON.parse(b.text) : {}; } catch (_) { log(400, 'json'); return reply(res, 400, { error: 'json' }); }
      if (!j || typeof j !== 'object' || Array.isArray(j)) { log(400, 'json'); return reply(res, 400, { error: 'json' }); }
    }
    const out = await route.run({ who, j, url });
    access.touch(who);
    log(out.code || 200, out.info);
    return reply(res, out.code || 200, out.body);
  }

  const server = http.createServer((req, res) => {
    handle(req, res).catch(() => { try { if (!res.headersSent) reply(res, 500, { error: 'failed' }); else res.end(); } catch (_) { /* gone */ } });
  });
  server.headersTimeout = 10000;
  server.requestTimeout = 20000;
  server.keepAliveTimeout = 5000;
  server.maxConnections = 64;
  server.on('clientError', (_e, socket) => { try { socket.end('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n'); } catch (_) { /* gone */ } });
  server.on('error', () => {});
  server.on('close', () => access.stop());
  server.access = access;
  server.listen(port, '127.0.0.1');
  return server;
}

module.exports = { start, authOk, PORT };
