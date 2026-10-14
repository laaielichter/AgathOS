'use strict';
// AgathOS - AI browser extensions.
// In 2026 two Chrome extensions posing as AI helpers (about 900,000 users) copied ChatGPT and
// DeepSeek chats and all open tabs to a server. An extension that is about AI and may read every
// website you open is worth a look. AgathOS reads the extension folders of Chrome, Edge and Brave
// (manifest.json only, nothing is run, nothing leaves the PC) and lists those extensions.
// It cannot tell good from bad: it shows what each one is allowed to do and warns when that is a lot.
const fs = require('fs');
const path = require('path');
const U = require('./util');

const BROWSERS = [
  { id: 'chrome', name: 'Chrome', win: ['Google', 'Chrome', 'User Data'], mac: ['Google', 'Chrome'] },
  { id: 'edge', name: 'Edge', win: ['Microsoft', 'Edge', 'User Data'], mac: ['Microsoft Edge'] },
  { id: 'brave', name: 'Brave', win: ['BraveSoftware', 'Brave-Browser', 'User Data'], mac: ['BraveSoftware', 'Brave-Browser'] },
];

const AI_WORDS = /\b(ai|a\.i\.|chat\s?gpt|gpt|claude|gemini|deepseek|copilot|openai|llm|grok|perplexity|mistral)\b/i;
const AI_CHAT_SITES = /(chatgpt\.com|chat\.openai\.com|claude\.ai|gemini\.google\.com|chat\.deepseek\.com|perplexity\.ai|copilot\.microsoft\.com|grok\.com|poe\.com)/i;
const ALL_SITES = /^(<all_urls>|(\*|https?|\*):\/\/\*\/(\*)?)$/i;
// Permissions that let an extension see more than the page it is on.
const WIDE_PERMS = ['tabs', 'history', 'cookies', 'webRequest', 'webRequestBlocking', 'clipboardRead', 'debugger', 'nativeMessaging'];

const stripBom = (s) => String(s || '').replace(/^﻿/, '');
function readJson(file) {
  const txt = U.readText(file, 1024 * 1024);
  if (txt == null) return null;
  try { return JSON.parse(U.stripJsonComments(stripBom(txt))); } catch (_) { return null; }
}

function cmpVer(a, b) {
  const pa = String(a).match(/\d+/g) || [];
  const pb = String(b).match(/\d+/g) || [];
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) { const d = (+pa[i] || 0) - (+pb[i] || 0); if (d) return d; }
  return 0;
}

// A manifest is written by the extension's author: any field can hold anything. Lists must be lists.
const list = (v) => (Array.isArray(v) ? v : []);

// "__MSG_appName__" means: look it up in _locales/<language>/messages.json.
function localized(dir, manifest, value) {
  const m = /^__MSG_(.+)__$/.exec(String(value || ''));
  if (!m) return String(value || '');
  // The language is a folder name: only plain names, never a path.
  for (const l of [manifest.default_locale, 'en', 'en_US', 'en_GB'].filter((x) => typeof x === 'string' && /^[A-Za-z0-9_-]{1,20}$/.test(x))) {
    const j = readJson(path.join(dir, '_locales', l, 'messages.json'));
    if (!j) continue;
    const key = Object.keys(j).find((k) => k.toLowerCase() === m[1].toLowerCase());
    if (key && j[key] && j[key].message) return String(j[key].message);
  }
  return m[1];
}

// Looks at one manifest. Returns null when the extension has nothing to do with AI.
function analyse(manifest, dir) {
  const name = (localized(dir, manifest, manifest.name) || '?').slice(0, 80);
  const text = [name, localized(dir, manifest, manifest.short_name), localized(dir, manifest, manifest.description)].join(' ');
  const perms = list(manifest.permissions).concat(list(manifest.optional_permissions)).filter((p) => typeof p === 'string');
  const hosts = []
    .concat(list(manifest.host_permissions), list(manifest.optional_host_permissions))
    .concat(perms.filter((p) => /[:*]/.test(p)))
    .concat(...list(manifest.content_scripts).map((c) => (c && typeof c === 'object' ? list(c.matches) : [])))
    .filter((h) => typeof h === 'string');
  const aiTheme = AI_WORDS.test(text);
  const chatSites = [...new Set(hosts.map((h) => (h.match(AI_CHAT_SITES) || [])[1]).filter(Boolean).map((s) => s.toLowerCase()))];
  if (!aiTheme && !chatSites.length) return null;
  const allSites = hosts.some((h) => ALL_SITES.test(h));
  const wide = WIDE_PERMS.filter((p) => perms.includes(p));
  const sev = allSites ? 'watch' : 'calm';
  const reasons = [];
  if (aiTheme) reasons.push({ key: 'ext.aiTheme', params: {}, sev: 'calm' });
  if (chatSites.length) reasons.push({ key: 'ext.aiChats', params: { sites: chatSites.slice(0, 3).join(', ') }, sev });
  if (allSites) reasons.push({ key: 'ext.allSites', params: {}, sev: 'watch' });
  if (wide.length) reasons.push({ key: 'ext.reads', params: { perms: wide.join(', ') }, sev });
  return { name, state: sev, reasons, perms: wide, allSites, chatSites };
}

function defaultRoots() {
  if (!U.IS_WIN && !U.IS_MAC) return [];
  return BROWSERS.map((b) => ({ browser: b.name, dir: path.join(U.LOCALAPPDATA, ...(U.IS_WIN ? b.win : b.mac)) })).filter((r) => U.exists(r.dir));
}

// All AI-related extensions in every profile of every browser. `roots` is for tests.
function scan(roots = defaultRoots()) {
  const out = [];
  for (const root of roots) {
    let profiles = [];
    try { profiles = fs.readdirSync(root.dir).filter((n) => n === 'Default' || /^Profile \d+$/.test(n)); } catch (_) { continue; }
    for (const profile of profiles) {
      const extDir = path.join(root.dir, profile, 'Extensions');
      let ids = [];
      try { ids = fs.readdirSync(extDir); } catch (_) { continue; }
      for (const extId of ids) {
        let versions = [];
        try { versions = fs.readdirSync(path.join(extDir, extId)); } catch (_) { continue; }
        const version = versions.sort(cmpVer).pop();
        if (!version) continue;
        const dir = path.join(extDir, extId, version);
        const manifest = readJson(path.join(dir, 'manifest.json'));
        if (!manifest || typeof manifest !== 'object') continue;
        const a = analyse(manifest, dir);
        if (!a) continue;
        out.push({
          id: U.sha256(`${root.browser}|${profile}|${extId}`).slice(0, 16),
          browser: root.browser, profile, extId, version: String(manifest.version || version), path: dir,
          name: a.name, state: a.state, reasons: a.reasons,
          hash: U.sha256(JSON.stringify([manifest.version, a.perms, a.allSites, a.chatSites])).slice(0, 16),
        });
      }
    }
  }
  return out;
}

module.exports = { scan, analyse, defaultRoots, BROWSERS };
