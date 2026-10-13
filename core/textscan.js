'use strict';
// AgathOS - text checks for instruction files, skills and configs:
// invisible Unicode, hidden "tag" text, reversed (bidi) text, attack phrases and secrets.
const { INJECTION_PHRASES } = require('./catalog');

// Zero-width and other invisible characters.
const ZERO_WIDTH = /[​-‍⁠-⁤﻿᠎­]/g;
// Bidirectional overrides and isolates (can show text in a different order than it is read).
const BIDI = /[‪-‮⁦-⁩]/g;
// Unicode "Tags" block U+E0000–U+E007F: invisible copies of ASCII. Models read them, people do not.
const TAGS = /[\u{E0000}-\u{E007F}]/gu;

function hiddenUnicode(text) {
  if (!text) return null;
  const zw = text.match(ZERO_WIDTH) || [];
  const bidi = text.match(BIDI) || [];
  const tags = text.match(TAGS) || [];
  // A single BOM at the very start is normal.
  let zwCount = zw.length;
  if (text.charCodeAt(0) === 0xfeff) zwCount -= 1;
  // Decode tag characters back to the ASCII text they hide.
  let decoded = '';
  if (tags.length) {
    for (const ch of tags) {
      const cp = ch.codePointAt(0) - 0xe0000;
      if (cp >= 0x20 && cp < 0x7f) decoded += String.fromCharCode(cp);
    }
  }
  // Zero-width "binary" encodings: long runs of 200B/200C mean hidden data.
  const zwRun = /[​‌‍]{8,}/.test(text);
  if (zwCount <= 0 && !bidi.length && !tags.length) return null;
  return { zeroWidth: Math.max(0, zwCount), bidi: bidi.length, tags: tags.length, decoded: decoded.trim().slice(0, 160), zwRun };
}

function injectionPhrases(text) {
  if (!text) return [];
  const hits = [];
  // Look at the text as the model sees it: with hidden tag text decoded in place.
  const visible = text.replace(TAGS, (ch) => {
    const cp = ch.codePointAt(0) - 0xe0000;
    return cp >= 0x20 && cp < 0x7f ? String.fromCharCode(cp) : '';
  }).replace(ZERO_WIDTH, '');
  for (const re of INJECTION_PHRASES) {
    const m = visible.match(re);
    if (m) hits.push(snippet(visible, m.index, m[0].length));
    if (hits.length >= 3) break;
  }
  return hits;
}

function snippet(text, index, len) {
  const s = Math.max(0, index - 20);
  const e = Math.min(text.length, index + len + 20);
  return text.slice(s, e).replace(/\s+/g, ' ').trim().slice(0, 120);
}

// ---------- Secrets ----------
const SECRET_PATTERNS = [
  { kind: 'Anthropic', re: /\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{20,}/g },
  { kind: 'OpenAI', re: /\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}/g },
  { kind: 'GitHub', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b|\bgithub_pat_[A-Za-z0-9_]{60,}/g },
  { kind: 'AWS', re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { kind: 'Google', re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: 'Hugging Face', re: /\bhf_[A-Za-z0-9]{34,}\b/g },
  { kind: 'Slack', re: /\bxox[abpors]-[A-Za-z0-9-]{10,}/g },
  { kind: 'Stripe', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g },
  { kind: 'GitLab', re: /\bglpat-[A-Za-z0-9_-]{20,}/g },
  { kind: 'npm', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { kind: 'Private key', re: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY( BLOCK)?-----/g },
  { kind: 'Telegram bot', re: /\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b/g },
  { kind: 'Discord webhook', re: /https:\/\/(?:ptb\.|canary\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/g },
];

function findSecrets(text) {
  if (!text) return [];
  const found = [];
  for (const p of SECRET_PATTERNS) {
    const m = text.match(p.re);
    if (m) for (const v of m) found.push({ kind: p.kind, masked: mask(v) });
  }
  return dedupe(found);
}

const mask = (v) => (v.length <= 12 ? '••••' : v.slice(0, 6) + '…' + v.slice(-3));
function dedupe(list) {
  const seen = new Set();
  return list.filter((x) => (seen.has(x.masked) ? false : seen.add(x.masked)));
}

// One call that returns all findings for a text file, as reason objects for the UI.
function scanText(text) {
  const reasons = [];
  let sev = 'calm';
  const bump = (s) => { if (s === 'alarm' || (s === 'watch' && sev === 'calm')) sev = s; };
  const h = hiddenUnicode(text);
  if (h) {
    if (h.tags) {
      reasons.push({ key: 'file.hiddenTags', params: { n: h.tags, text: h.decoded || '…' }, sev: 'alarm' });
      bump('alarm');
    }
    if (h.zeroWidth) {
      const s = h.zwRun || h.zeroWidth > 20 ? 'alarm' : 'watch';
      reasons.push({ key: 'file.hidden', params: { n: h.zeroWidth }, sev: s });
      bump(s);
    }
    if (h.bidi) { reasons.push({ key: 'file.bidi', params: { n: h.bidi }, sev: 'alarm' }); bump('alarm'); }
  }
  for (const s of injectionPhrases(text)) {
    reasons.push({ key: 'file.injectionPhrase', params: { text: s }, sev: 'alarm' });
    bump('alarm');
  }
  const secrets = findSecrets(text);
  if (secrets.length) {
    reasons.push({ key: 'file.secret', params: { n: secrets.length, kinds: [...new Set(secrets.map((x) => x.kind))].join(', ') }, sev: 'watch' });
    bump('watch');
  }
  return { sev, reasons, secrets };
}

module.exports = { hiddenUnicode, injectionPhrases, findSecrets, scanText };
