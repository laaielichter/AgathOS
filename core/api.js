'use strict';
// AgathOS - local API on 127.0.0.1 (never on the network).
// Lets other local tools read the status, ask "is this tool call OK?" before running it,
// and press the pause button. Basis for phone/router/smart-home add-ons later.
// Every request needs the token in <userData>/api-token.txt.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = 47612;

// Compare the digests, not the texts: timingSafeEqual throws when the two byte lengths differ
// (a header with accented letters has as many characters as the token but more bytes), and a throw
// here would take the whole app down.
const digest = (s) => crypto.createHash('sha256').update(String(s)).digest();
function authOk(header, token) {
  const given = String(header || '').replace(/^Bearer\s+/i, '');
  return !!token && crypto.timingSafeEqual(digest(given), digest(token));
}

function start(engine, dir) {
  const file = path.join(dir, 'api-token.txt');
  let token;
  try { token = fs.readFileSync(file, 'utf8').trim(); } catch (_) {}
  if (!token) { token = crypto.randomBytes(24).toString('hex'); try { fs.writeFileSync(file, token); } catch (_) {} }

  const server = http.createServer((req, res) => {
    const send = (code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
    const addr = req.socket.remoteAddress || '';
    if (!/^(127\.0\.0\.1|::1|::ffff:127\.0\.0\.1)$/.test(addr)) return send(403, { error: 'local only' });
    // Browsers send an Origin header; local tools do not. Refuse web pages.
    if (req.headers.origin) return send(403, { error: 'no browsers' });
    if (!authOk(req.headers.authorization, token)) return send(401, { error: 'token' });
    let body = '';
    req.on('data', (d) => { body += d; if (body.length > 65536) req.destroy(); });
    req.on('end', async () => {
      let j = {};
      try { j = body ? JSON.parse(body) : {}; } catch (_) { return send(400, { error: 'json' }); }
      try {
        const url = new URL(req.url, 'http://127.0.0.1');
        if (req.method === 'GET' && url.pathname === '/v1/status') return send(200, engine.publicStatus());
        if (req.method === 'GET' && url.pathname === '/v1/agents') return send(200, engine.snapshot().agents);
        if (req.method === 'GET' && url.pathname === '/v1/events') {
          const since = Number(url.searchParams.get('since') || 0);
          return send(200, engine.store.events.filter((e) => e.ts > since).slice(-500));
        }
        if (req.method === 'POST' && url.pathname === '/v1/check') return send(200, engine.checkToolCall(j));
        if (req.method === 'POST' && url.pathname === '/v1/pause-all') return send(200, await engine.pauseAll('api'));
        if (req.method === 'POST' && url.pathname === '/v1/resume-all') return send(200, await engine.resumeAll());
        return send(404, { error: 'unknown' });
      } catch (e) {
        return send(500, { error: 'failed' });
      }
    });
  });
  server.on('error', () => {});
  server.listen(PORT, '127.0.0.1');
  return server;
}

module.exports = { start, authOk, PORT };
