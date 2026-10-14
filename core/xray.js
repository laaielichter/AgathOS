'use strict';
// AgathOS - Model X-ray. Looks inside AI model files and the folders that come with them, without
// loading a model and without running any code of it:
//  * GGUF: the table of settings (the chat template is a small program for a template engine, and a
//    template can hide instructions for the model or try to break out of the engine), the table of
//    tensors (impossible numbers crash programs that read the file; data behind the last tensor hides things)
//  * safetensors: the header (does the list of tensors fit the file, is something hidden behind the last tensor,
//    do the free text fields hold hidden text)
//  * programs that carry a model name (an .exe or a script called model.gguf)
//  * Keras (Lambda layers hold code), ONNX (data files outside the model's folder), NumPy (objects load through pickle)
//  * the folder of a Hugging Face model (Python code that runs when the model is loaded with trust_remote_code,
//    the chat template in tokenizer_config.json) and the layers of an Ollama model (system prompt, template)
// Weights themselves cannot be judged here: a model that was trained to misbehave looks like any other model.
// Everything is read in small parts with limits, so a hostile file cannot make this slow or crash it.
const fs = require('fs');
const path = require('path');
const T = require('./textscan');
const zip = require('./zipread');

class XErr extends Error { constructor(code) { super(code); this.code = code; } }

// ---------- reading ----------
// A sliding window over a file: numbers and strings of a binary header without reading all of it.
class Reader {
  constructor(fd, size, { le = true, window = 1 << 20, budget = 256 * 1024 * 1024, ops = 20e6 } = {}) {
    this.fd = fd; this.size = size; this.le = le; this.win = window; this.budget = budget; this.read = 0;
    this.opsLeft = ops; this.buf = Buffer.alloc(0); this.base = 0; this.pos = 0;
  }
  at(pos) { this.pos = pos; return this; }
  left() { return this.size - this.pos; }
  // makes sure n bytes at the current place are in the window (without counting an operation)
  _fill(n) {
    if (n < 0 || this.pos + n > this.size) throw new XErr('eof');
    if (this.pos >= this.base && this.pos + n <= this.base + this.buf.length) return;
    const len = Math.min(Math.max(n, this.win), this.size - this.pos);
    this.read += len;
    if (this.read > this.budget) throw new XErr('budget');
    const b = Buffer.alloc(len);
    const got = fs.readSync(this.fd, b, 0, len, this.pos);
    if (got < n) throw new XErr('eof');
    this.buf = got === len ? b : b.subarray(0, got);
    this.base = this.pos;
  }
  _have(n) {
    if (--this.opsLeft < 0) throw new XErr('budget');
    this._fill(n);
  }
  u8() { this._have(1); const v = this.buf[this.pos - this.base]; this.pos += 1; return v; }
  u16() { this._have(2); const o = this.pos - this.base; const v = this.le ? this.buf.readUInt16LE(o) : this.buf.readUInt16BE(o); this.pos += 2; return v; }
  u32() { this._have(4); const o = this.pos - this.base; const v = this.le ? this.buf.readUInt32LE(o) : this.buf.readUInt32BE(o); this.pos += 4; return v; }
  // 64-bit numbers: never throw for a big one, stop at the largest exact number (a size that big is "impossible" anyway)
  u64() {
    this._have(8); const o = this.pos - this.base;
    const v = this.le ? this.buf.readBigUInt64LE(o) : this.buf.readBigUInt64BE(o);
    this.pos += 8;
    return v > 9007199254740991n ? Number.MAX_SAFE_INTEGER : Number(v);
  }
  bytes(n) { this._have(n); const o = this.pos - this.base; const v = this.buf.subarray(o, o + n); this.pos += n; return v; }
  skip(n) { if (!(n >= 0) || this.pos + n > this.size) throw new XErr('eof'); this.pos += n; }
  // n strings in a row, each with its length (8 bytes) in front. Skipped without making a number object of each length, and
  // the count is paid in advance, so a made-up count of a billion strings stops at once instead of after a long loop.
  skipStrings(n) {
    if (!(n >= 0) || n > this.opsLeft) throw new XErr('budget');
    this.opsLeft -= n;
    for (let i = 0; i < n; i++) {
      this._fill(8);
      const o = this.pos - this.base;
      const lo = this.le ? this.buf.readUInt32LE(o) : this.buf.readUInt32BE(o + 4);
      const hi = this.le ? this.buf.readUInt32LE(o + 4) : this.buf.readUInt32BE(o);
      this.pos += 8;
      if (hi >= 256) throw new XErr('table');              // 2^40 and up is no length
      const len = hi * 4294967296 + lo;
      if (len > this.size - this.pos) throw new XErr('eof');
      this.pos += len;
    }
  }
  varint() {
    let r = 0; let mul = 1;
    for (let i = 0; i < 10; i++) { const b = this.u8(); r += (b & 0x7f) * mul; if (!(b & 0x80)) return r; mul *= 128; }
    throw new XErr('varint');
  }
}

const readAt = zip.readAt;

// ---------- showing what is found ----------
const ZW = /[\u200B-\u200D\u2060-\u2064\uFEFF\u180E\u00AD]/gu;
const BIDI = /[\u202A-\u202E\u2066-\u2069]/gu;
const TAG = /[\u{E0000}-\u{E007F}]/gu;
const mark = (ch) => `‹U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}›`;
// Text of a file for the window: invisible characters are made visible, control characters are dots, long text is cut.
function excerpt(text, max = 1500) {
  const s = String(text == null ? '' : text).slice(0, max * 2).replace(ZW, mark).replace(BIDI, mark).replace(TAG, mark).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/g, '·');
  return s.length > max ? s.slice(0, max) + '…' : s;
}
// A short plain piece of a file for a message: no hidden characters, no line breaks, no control characters.
const clean = (s, n = 80) => T.stripHidden(String(s == null ? '' : s)).replace(/[\u0000-\u001f\u007f]/g, ' ').replace(/\s+/g, ' ').trim().slice(0, n);
const word = (s, n = 60) => String(s == null ? '' : s).replace(/[^\w.\-:/\\ ]/g, '').slice(0, n);
const hostOf = (url) => { try { return new URL(url).hostname.toLowerCase().replace(/[^a-z0-9.\-:[\]]/g, '').slice(0, 80); } catch (_) { return ''; } };
const worstOf = (list) => (list.some((r) => r.sev === 'alarm') ? 'alarm' : list.some((r) => r.sev === 'watch') ? 'watch' : 'calm');
const snip = (text, index, len) => text.slice(Math.max(0, index - 20), Math.min(text.length, index + len + 20)).replace(/\s+/g, ' ').trim().slice(0, 120);

// ---------- words: text that goes to a model (template, system prompt, descriptions) ----------
// Instructions aimed at the model that nobody should find in a file that formats a conversation, besides the
// attack phrases that the instruction-file check already knows.
const STEER = [
  [/(always|every time|in every (reply|answer|response)|whenever)[^.\n]{0,120}\b(include|insert|add|append|put|show|output|print|embed)\b[^.\n]{0,120}(https?:\/\/|www\.)/i, 'alarm'],
  [/!\[[^\]\n]{0,80}\]\(\s*https?:\/\/[^)\s]*(\{\{|\?|&)/i, 'alarm'],
  [/<(script|iframe)\b|javascript:|onerror\s*=/i, 'alarm'],
  [/\b(send|post|forward|leak|upload|exfiltrate)\b[^.\n]{0,60}\b(conversation|chat|messages?|history|user'?s? (data|input|messages?|prompts?))\b[^.\n]{0,60}\b(to|at|via)\s+(https?:\/\/|the (url|address|server))/i, 'alarm'],
  [/\b(do not|don'?t|never)\s+(reveal|disclose|mention|tell|show|say|admit)\b[^.\n]{0,80}\b(these|this|the|my|your)\s+(hidden\s+|secret\s+)?(instructions?|prompt|rules|message|directive)/i, 'watch'],
  [/\b(secretly|silently|covertly)\b|\bwithout (the user|them|anyone) (knowing|noticing|seeing)\b/i, 'watch'],
];
const URL_RE = /\bhttps?:\/\/[^\s"'<>)\]}`\\]+/gi;
const BLOB_RE = /[A-Za-z0-9+/=_-]{240,}/;

// part: 'template' | 'system' | 'meta' | 'messages' ...  Returns reason objects.
function words(text, part, { urls = true } = {}) {
  const out = [];
  const s = String(text == null ? '' : text).slice(0, 1024 * 1024);
  const add = (key, params, sev) => out.push({ key, params: { part, ...params }, sev });
  const hid = T.hiddenUnicode(s);
  if (hid) {
    if (hid.tags && hid.decoded) add('xray.hiddenTags', { n: hid.tags, text: clean(hid.decoded, 120) }, 'alarm');
    else if (hid.tags) add('xray.hidden', { n: hid.tags }, 'alarm');
    if (hid.zeroWidth) add('xray.hidden', { n: hid.zeroWidth }, hid.zwRun || hid.zeroWidth > 20 ? 'alarm' : 'watch');
    if (hid.bidi) add('xray.hidden', { n: hid.bidi }, 'alarm');
  }
  const seen = new Set();
  const order = (text2, sev) => { const k = text2.toLowerCase(); if (seen.has(k) || seen.size >= 3) return; seen.add(k); add('xray.orders', { text: clean(text2, 120) }, sev); };
  for (const sn of T.injectionPhrases(s)) order(sn, 'alarm');
  for (const [re, sev] of STEER) { const m = s.match(re); if (m) order(snip(s, m.index, m[0].length), sev); }
  if (urls) {
    const hosts = [...new Set((s.match(URL_RE) || []).map(hostOf).filter(Boolean))].slice(0, 3);
    if (hosts.length) add('xray.url', { host: hosts.join(', ') }, 'watch');
  }
  if (BLOB_RE.test(s)) add('xray.blob', {}, 'watch');
  if (s.length > 20000) add('xray.big', { n: s.length }, 'watch');
  return out;
}

// What a chat template must not do: reach the inside of the template engine (the known way to run commands
// through a template, in programs that do not run templates in a sandbox), or load other files.
const ESCAPES = [
  /__[A-Za-z_]{2,}__/g, /\\x5f\\x5f|\\u005f\\u005f|\\137\\137/gi, /\|\s*attr\s*\(/g, /\.\s*mro\s*\(/g,
  /\b(?:os|sys|subprocess|builtins|importlib|socket)\s*\.\s*[A-Za-z_]\w*/g,
  /\b(?:popen|system|eval|exec|getattr|setattr|globals|locals|subclasses)\(/g,
  /\{%-?\s*(?:import|include|extends|from)\b/g,
];
function jinjaCode(text) {
  const parts = [];
  const re = /\{\{[\s\S]*?\}\}|\{%[\s\S]*?%\}/g;
  let m;
  while ((m = re.exec(text))) parts.push(m[0]);
  return parts.join('\n');
}
function escapes(code) {
  const found = [];
  for (const re of ESCAPES) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(code)) && found.length < 12) { const w = clean(m[0], 40); if (w && !found.includes(w)) found.push(w); }
  }
  return found;
}
function template(text, part = 'template') {
  const s = String(text == null ? '' : text).slice(0, 1024 * 1024);
  const out = words(s, part, { urls: true });
  const esc = escapes(jinjaCode(s));
  if (esc.length) out.unshift({ key: 'xray.escape', params: { part, calls: esc.slice(0, 4).join(', ') }, sev: 'alarm' });
  return out;
}
// A free text field of a file (name, description, author ...): only hidden characters and attack text count, links are normal there.
function field(key, value) {
  const out = [];
  const s = String(value == null ? '' : value).slice(0, 256 * 1024);
  const k = word(key, 60);
  const hid = T.hiddenUnicode(s);
  if (hid) {
    const n = hid.zeroWidth + hid.bidi + hid.tags;
    out.push({ key: 'xray.metaHidden', params: { key: k, n }, sev: hid.tags || hid.bidi || hid.zwRun || hid.zeroWidth > 20 ? 'alarm' : 'watch' });
  }
  const inj = T.injectionPhrases(s);
  if (inj.length) out.push({ key: 'xray.metaOrders', params: { key: k, text: clean(inj[0], 120) }, sev: 'alarm' });
  return out;
}

// ---------- the result of one file ----------
function done(format, found, facts, texts) {
  const reasons = found.length ? found : [{ key: 'xray.clean', params: { format }, sev: 'calm' }];
  return { format, state: worstOf(reasons), reasons, x: { facts: facts || {}, texts: texts || [] } };
}
const PART_CHARS = (text) => String(text).length;

// ---------- GGUF ----------
const GGUF_FIXED = { 0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8 };
// llama.cpp's own names for the file type (general.file_type)
const QUANT = { 0: 'F32', 1: 'F16', 2: 'Q4_0', 3: 'Q4_1', 7: 'Q8_0', 8: 'Q5_0', 9: 'Q5_1', 10: 'Q2_K', 11: 'Q3_K_S', 12: 'Q3_K_M', 13: 'Q3_K_L', 14: 'Q4_K_S', 15: 'Q4_K_M', 16: 'Q5_K_S', 17: 'Q5_K_M', 18: 'Q6_K', 19: 'IQ2_XXS', 20: 'IQ2_XS', 21: 'Q2_K_S', 22: 'IQ3_XS', 23: 'IQ3_XXS', 24: 'IQ1_S', 25: 'IQ4_NL', 26: 'IQ3_S', 27: 'IQ3_M', 28: 'IQ2_S', 29: 'IQ2_M', 30: 'IQ4_XS', 31: 'IQ1_M', 32: 'BF16' };
// tensor type -> [elements per block, bytes per block]; only the ones that are known for sure
const GGML = { 0: [1, 4], 1: [1, 2], 2: [32, 18], 3: [32, 20], 6: [32, 22], 7: [32, 24], 8: [32, 34], 9: [32, 36], 10: [256, 84], 11: [256, 110], 12: [256, 144], 13: [256, 176], 14: [256, 210], 15: [256, 292], 16: [256, 66], 17: [256, 74], 18: [256, 98], 19: [256, 50], 20: [32, 18], 21: [256, 110], 22: [256, 82], 23: [256, 136], 24: [1, 1], 25: [1, 2], 26: [1, 4], 27: [1, 8], 28: [1, 8], 29: [256, 56], 30: [1, 2] };
const IMPOSSIBLE = 2 ** 40;     // a length, count or offset above one terabyte in a file is not a real one

function gguf(fd, size, head) {
  let le = true;
  let version = head.readUInt32LE(4);
  if (version > 0xffff) { const be = head.readUInt32BE(4); if (be === 2 || be === 3) { le = false; version = be; } }
  if (version !== 2 && version !== 3) return null;           // version 1 is not read by llama.cpp any more, a newer one is not known: never guessed
  const found = [];
  const facts = { version };
  const texts = [];
  const R = new Reader(fd, size, { le });
  let bad = null;                                              // 'table' (impossible numbers) | 'short' (the file ends too early)
  const fail = (code) => new XErr(code);
  try {
    R.at(8);
    const nTensors = R.u64();
    const nKV = R.u64();
    if (nTensors > 5e5 || nKV > 1e6 || nKV * 13 > size || nTensors * 24 > size) throw fail('table');
    const str = (cap) => {
      const n = R.u64();
      if (n >= IMPOSSIBLE) throw fail('table');
      if (n > R.left()) throw fail('eof');
      const take = Math.min(n, cap);
      const text = R.bytes(take).toString('utf8');
      if (n > take) R.skip(n - take);
      return { text, n };
    };
    const skipArray = (depth) => {
      const et = R.u32();
      const n = R.u64();
      if (n > 1e9) throw fail('table');
      if (GGUF_FIXED[et]) { const b = n * GGUF_FIXED[et]; if (b > R.left()) throw fail('eof'); R.skip(b); return; }
      if (et === 8) { R.skipStrings(n); return; }
      if (et === 9) { if (depth > 3 || n > 1e6) throw fail('table'); for (let i = 0; i < n; i++) skipArray(depth + 1); return; }
      throw fail('table');
    };
    const meta = {};
    const tpl = [];
    let alignment = 32;
    let strings = 0;
    for (let i = 0; i < nKV; i++) {
      const k = str(512).text;
      const ty = R.u32();
      if (ty === 8) {
        const isTpl = k === 'tokenizer.chat_template' || k.startsWith('tokenizer.chat_template.');
        const v = str(isTpl ? 1024 * 1024 : 64 * 1024);
        if (isTpl) tpl.push({ name: k.slice('tokenizer.chat_template'.length).replace(/^\./, ''), text: v.text, length: v.n });
        else {
          if (strings++ < 400) found.push(...field(k, v.text));
          if (/^general\.(architecture|name|size_label|basename)$|^tokenizer\.ggml\.model$/.test(k)) meta[k] = clean(v.text, 80);
        }
      } else if (ty === 9) {
        skipArray(0);
      } else if (GGUF_FIXED[ty]) {
        const wantNum = /^general\.(file_type|alignment)$|\.(block_count|context_length)$/.test(k);
        if (!wantNum) R.skip(GGUF_FIXED[ty]);
        else if (GGUF_FIXED[ty] === 4) meta[k] = R.u32();
        else if (GGUF_FIXED[ty] === 8) meta[k] = R.u64();
        else R.skip(GGUF_FIXED[ty]);
      } else throw fail('table');
    }
    if (Number.isInteger(meta['general.alignment']) && meta['general.alignment'] > 0 && meta['general.alignment'] <= 65536 && (meta['general.alignment'] & (meta['general.alignment'] - 1)) === 0) alignment = meta['general.alignment'];
    const arch = meta['general.architecture'] || '';
    // the tensors
    let params = 0;
    let maxEnd = 0;
    let known = true;
    let beyond = false;
    const tensors = [];
    for (let i = 0; i < nTensors; i++) {
      const name = str(256).text;
      const nd = R.u32();
      if (nd > 8) throw fail('table');
      let elems = 1n;
      for (let d = 0; d < nd; d++) { const v = R.u64(); elems *= BigInt(v); if (elems > 2n ** 50n) throw fail('table'); }
      const type = R.u32();
      const offset = R.u64();
      if (offset >= IMPOSSIBLE) throw fail('table');
      tensors.push({ name, elems: Number(elems), type, offset });
      params += Number(elems);
    }
    const dataStart = Math.ceil(R.pos / alignment) * alignment;
    for (const t of tensors) {
      const g = GGML[t.type];
      if (!g || t.elems % g[0] !== 0) { known = false; continue; }
      const end = t.offset + (t.elems / g[0]) * g[1];
      if (end > maxEnd) maxEnd = end;
    }
    if (dataStart > size || dataStart + maxEnd > size) beyond = true;
    if (beyond) bad = 'short';
    else if (known && tensors.length) {
      const expected = Math.ceil((dataStart + maxEnd) / alignment) * alignment;
      const extra = size - expected;
      if (extra > Math.max(alignment, 4096)) found.push({ key: 'xray.bad.trailing', params: { n: extra }, sev: 'watch' });
    }
    facts.tensors = nTensors;
    if (params) facts.params = params;
    if (arch) facts.arch = arch;
    if (meta['general.name']) facts.name = meta['general.name'];
    if (meta[`${arch}.block_count`]) facts.layers = meta[`${arch}.block_count`];
    if (meta[`${arch}.context_length`]) facts.ctx = meta[`${arch}.context_length`];
    if (QUANT[meta['general.file_type']]) facts.quant = QUANT[meta['general.file_type']];
    // chat templates
    for (const tp of tpl) {
      const part = 'template';
      const rs = template(tp.text, part);
      if (tp.length > 1024 * 1024) rs.push({ key: 'xray.big', params: { part, n: tp.length }, sev: 'watch' });
      found.push(...rs);
      texts.push({ part, name: word(tp.name, 30), chars: PART_CHARS(tp.text), text: excerpt(tp.text) });
    }
    if (tpl.length) facts.template = PART_CHARS(tpl[0].text);
  } catch (e) {
    if (!(e instanceof XErr)) throw e;
    bad = e.code === 'eof' ? 'short' : 'table';
  }
  if (bad === 'table') found.unshift({ key: 'xray.bad.table', params: {}, sev: 'alarm' });
  else if (bad === 'short') found.push({ key: 'xray.bad.short', params: {}, sev: 'watch' });
  return done('GGUF', found, facts, texts);
}

// ---------- safetensors ----------
const ST_SIZE = { BOOL: 1, U8: 1, I8: 1, F8_E5M2: 1, F8_E4M3: 1, F8_E8M0: 1, I16: 2, U16: 2, F16: 2, BF16: 2, I32: 4, U32: 4, F32: 4, F64: 8, I64: 8, U64: 8 };

function safetensors(fd, size, head, ext) {
  if (head.length < 9) return undefined;
  const nBig = head.readBigUInt64LE(0);
  if (nBig < 2n || nBig > 100n * 1024n * 1024n || head[8] !== 0x7b) return undefined;
  const n = Number(nBig);
  const found = [];
  if (8 + n > size) return done('safetensors', [{ key: 'xray.bad.short', params: {}, sev: 'watch' }], {}, []);
  // No real model has a list of tensors this long (it would be about a quarter of a million tensors in one file): not read,
  // because reading it is what a file like this is made for.
  if (n > 32 * 1024 * 1024) return done('safetensors', [{ key: 'xray.bad.table', params: {}, sev: 'watch' }], {}, []);
  let obj;
  try { obj = JSON.parse(readAt(fd, 8, n).toString('utf8')); } catch (_) { obj = null; }
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
    return ext === '.safetensors' ? done('safetensors', [{ key: 'xray.st.json', params: {}, sev: 'watch' }], {}, []) : undefined;
  }
  const dataSize = size - 8 - n;
  const list = [];
  let layout = false;
  let params = 0;
  const dtypes = new Set();
  for (const k of Object.keys(obj)) {
    if (k === '__metadata__') continue;
    const v = obj[k];
    if (!v || typeof v !== 'object' || typeof v.dtype !== 'string' || !Array.isArray(v.shape) || !Array.isArray(v.data_offsets) || v.data_offsets.length !== 2
      || !v.data_offsets.every((x) => Number.isInteger(x) && x >= 0) || !v.shape.every((x) => Number.isInteger(x) && x >= 0)) { layout = true; continue; }
    const [b, e] = v.data_offsets;
    const elems = v.shape.reduce((a, x) => a * x, 1);
    const unit = ST_SIZE[v.dtype];
    if (unit && elems * unit !== e - b) layout = true;
    if (e < b) layout = true;
    dtypes.add(v.dtype);
    params += elems;
    list.push({ b, e });
  }
  list.sort((a, c) => a.b - c.b);
  let cursor = 0;
  let truncated = false;
  for (const t of list) {
    if (t.e > dataSize) truncated = true;
    if (t.b !== cursor) layout = true;
    cursor = Math.max(cursor, t.e);
  }
  if (truncated) found.push({ key: 'xray.bad.short', params: {}, sev: 'watch' });
  else {
    if (layout) found.push({ key: 'xray.st.layout', params: {}, sev: 'watch' });
    const extra = dataSize - cursor;
    if (extra > 0 && list.length) found.push({ key: 'xray.bad.trailing', params: { n: extra }, sev: extra >= 1024 ? 'alarm' : 'watch' });
  }
  const meta = obj.__metadata__;
  if (meta && typeof meta === 'object') for (const k of Object.keys(meta).slice(0, 400)) found.push(...field(k, typeof meta[k] === 'string' ? meta[k] : ''));
  const facts = { tensors: list.length };
  if (params) facts.params = params;
  if (dtypes.size) facts.dtype = [...dtypes].slice(0, 3).map((d) => word(d, 12)).join('/');
  return done('safetensors', found, facts, []);
}

// ---------- programs with a model's name ----------
const STRICT_EXT = new Set(['.gguf', '.safetensors', '.pt', '.pth', '.ckpt', '.pkl', '.pickle', '.joblib', '.onnx', '.h5', '.hdf5', '.keras', '.npy', '.tflite']);
const isStrictName = (file) => {
  const ext = path.extname(file).toLowerCase();
  if (STRICT_EXT.has(ext)) return true;
  const base = path.basename(file).toLowerCase();
  if (ext === '.bin') {
    if (/^(pytorch_model|model|adapter_model|ggml-|tf_model|flax_model|consolidated)/.test(base)) return true;
    try { return fs.existsSync(path.join(path.dirname(file), 'config.json')); } catch (_) { return false; }
  }
  return false;
};
const LLAMAFILE = /\.llamafile(\.exe)?$/i;

function programKind(fd, size, head) {
  if (head.length < 4) return null;
  if (head[0] === 0x4d && head[1] === 0x5a) {            // MZ: a Windows program, if a PE header is where the MZ header says
    try {
      if (size > 0x40) {
        const lf = readAt(fd, 0x3c, 4).readUInt32LE(0);
        if (lf > 0 && lf < size - 4 && readAt(fd, lf, 4).toString('latin1') === 'PE\0\0') return 'Windows';
      }
    } catch (_) { /* not a program we can show */ }
    return null;
  }
  if (head[0] === 0x7f && head[1] === 0x45 && head[2] === 0x4c && head[3] === 0x46) return 'Linux';
  const m = head.readUInt32BE(0);
  if (m === 0xfeedface || m === 0xfeedfacf || m === 0xcefaedfe || m === 0xcffaedfe) return 'macOS';
  if (head[0] === 0x23 && head[1] === 0x21 && head[2] > 0x20) return 'script';
  return null;
}

function program(fd, size, head, file) {
  if (LLAMAFILE.test(file)) return done('llamafile', [{ key: 'xray.llamafile', params: {}, sev: 'watch' }], {}, []);
  if (!isStrictName(file)) return undefined;
  const kind = programKind(fd, size, head);
  if (!kind) return undefined;
  if (kind === 'script') return done('script', [{ key: 'xray.script', params: {}, sev: 'alarm' }], {}, []);
  return done(`program (${kind})`, [{ key: 'xray.prog', params: { kind }, sev: 'alarm' }], {}, []);
}

// ---------- Keras ----------
function kerasLambdas(node, depth = 0, count = { n: 0, seen: 0 }) {
  if (!node || typeof node !== 'object' || depth > 40 || count.seen++ > 200000) return count.n;
  if (Array.isArray(node)) { for (const x of node) kerasLambdas(x, depth + 1, count); return count.n; }
  if (node.class_name === 'Lambda' || node.class_name === '__lambda__') count.n++;
  for (const k of Object.keys(node)) { const v = node[k]; if (v && typeof v === 'object') kerasLambdas(v, depth + 1, count); }
  return count.n;
}
function keras(fd, size, head, ext) {
  if (head.length >= 8 && head[0] === 0x89 && head.toString('latin1', 1, 4) === 'HDF') {
    // HDF5: the model's configuration is a text near the start of the file
    const text = readAt(fd, 0, Math.min(size, 4 * 1024 * 1024)).toString('latin1');
    const found = [];
    const n = (text.match(/"class_name"\s*:\s*"Lambda"/g) || []).length;
    if (n) found.push({ key: 'xray.keras.lambda', params: { n }, sev: 'alarm' });
    return done('Keras (HDF5)', found, n ? { code: n } : {}, []);
  }
  if (ext === '.keras' && head.length >= 4 && head[0] === 0x50 && head[1] === 0x4b) {
    const ents = zip.entries(fd, size, (name) => name === 'config.json', 16 * 1024 * 1024);
    if (!ents || !ents.length) return undefined;
    let cfg = null;
    try { cfg = ents[0].data ? JSON.parse(ents[0].data.toString('utf8')) : null; } catch (_) { cfg = null; }
    if (!cfg) return done('Keras', [{ key: 'model.unreadable', params: {}, sev: 'watch' }], {}, []);
    const n = kerasLambdas(cfg);
    return done('Keras', n ? [{ key: 'xray.keras.lambda', params: { n }, sev: 'alarm' }] : [], n ? { code: n } : {}, []);
  }
  return undefined;
}

// ---------- ONNX ----------
// A model in the ONNX format may keep its numbers in a separate file, named inside the model. A name that leads
// out of the model's folder (../ or a full path) makes a program read some other file.
function onnx(fd, size) {
  const R = new Reader(fd, size, { window: 8192, budget: 512 * 1024 * 1024, ops: 8e6 });
  const found = [];
  let tensors = 0;
  const msg = (end, on) => {
    while (R.pos < end) {
      const tag = R.varint();
      const fno = Math.floor(tag / 8);
      const wt = tag % 8;
      if (wt === 0) R.varint();
      else if (wt === 1) R.skip(8);
      else if (wt === 5) R.skip(4);
      else if (wt === 2) {
        const len = R.varint();
        if (R.pos + len > end) throw new XErr('table');
        const stop = R.pos + len;
        on(fno, len);
        if (R.pos < stop) R.skip(stop - R.pos);
      } else throw new XErr('table');
    }
  };
  const ext = (len) => {
    let key = '';
    let value = '';
    msg(R.pos + len, (f, l) => { if (f === 1 && l < 4096) key = R.bytes(l).toString('utf8'); else if (f === 2 && l < 4096) value = R.bytes(l).toString('utf8'); });
    if (key === 'location') {
      const v = value.replace(/\\/g, '/');
      if (/^(\/|[A-Za-z]:)/.test(v) || v.split('/').includes('..') || /[\u0000-\u001f]/.test(v) || T.hiddenUnicode(v)) {
        if (!found.some((r) => r.key === 'xray.onnx.path')) found.push({ key: 'xray.onnx.path', params: { path: clean(value, 80) }, sev: 'alarm' });
      }
    }
  };
  const tensor = (len) => { tensors++; msg(R.pos + len, (f, l) => { if (f === 13) ext(l); }); };
  const graph = (len) => msg(R.pos + len, (f, l) => { if (f === 5 || f === 15) tensor(l); });
  const props = (len) => {
    let key = ''; let value = '';
    msg(R.pos + len, (f, l) => { if (f === 1 && l < 4096) key = R.bytes(l).toString('utf8'); else if (f === 2 && l < 65536) value = R.bytes(l).toString('utf8'); });
    found.push(...field(key || 'metadata', value));
  };
  try {
    R.at(0);
    msg(size, (f, l) => {
      if (f === 7) graph(l);
      else if (f === 14) props(l);
      else if (f === 6 && l < 65536) found.push(...field('doc_string', R.bytes(l).toString('utf8')));
    });
  } catch (e) {
    if (!(e instanceof XErr)) throw e;
    if (!found.length) return undefined;                    // no ONNX we can read: not judged
  }
  return done('ONNX', found, tensors ? { tensors } : {}, []);
}

// ---------- NumPy ----------
function npy(fd, size, head) {
  if (head.length < 10 || head[0] !== 0x93 || head.toString('latin1', 1, 6) !== 'NUMPY') return undefined;
  try {
    const major = head[6];
    const hl = major === 1 ? head.readUInt16LE(8) : readAt(fd, 8, 4).readUInt32LE(0);
    const start = (major === 1 ? 10 : 12) + hl;
    if (hl > 65536 || start > size) return undefined;
    const header = readAt(fd, major === 1 ? 10 : 12, hl).toString('latin1');
    if (!/['"][<>|=]?O['"]/.test(header)) return undefined;      // numbers only: no code
    const M = require('./models');                                                               // the pickle walker lives there
    const data = readAt(fd, start, Math.min(size - start, 64 * 1024 * 1024));
    const g = M.pickleGlobals(data);
    const { danger } = M.classifyGlobals(g.globals);
    const found = [{ key: 'xray.npy.object', params: {}, sev: 'watch' }];
    if (danger.length) found.unshift({ key: 'model.pickleDanger', params: { calls: danger.slice(0, 4).join(', ') }, sev: 'alarm' });
    if (!g.ok) found.push({ key: 'model.unreadable', params: {}, sev: 'alarm' });
    return done('NumPy (objects)', found, {}, []);
  } catch (_) {
    return undefined;                                             // a header we cannot read: not judged
  }
}

// ---------- one file: the entry point of models.js ----------
// -> undefined: not for us (models.js goes on with its own checks), null: a format we know but cannot read
//    (models.js falls back to what it did before), otherwise { format, state, reasons, x }.
function inspect(file, fd, size, head) {
  const ext = path.extname(file).toLowerCase();
  const prog = program(fd, size, head, file);
  if (prog) return prog;
  if (head.length >= 8 && head.toString('latin1', 0, 4) === 'GGUF') return gguf(fd, size, head);
  const st = safetensors(fd, size, head, ext);
  if (st) return st;
  const k = keras(fd, size, head, ext);
  if (k) return k;
  if (ext === '.onnx') return onnx(fd, size);
  return npy(fd, size, head);
}

// ---------- folders ----------
const SKIP = new Set(['.git', 'node_modules', '__pycache__', '.venv', 'venv', 'site-packages']);
function collectDirs(root, { maxDepth = 6, maxDirs = 20000 } = {}) {
  const out = [];
  const stack = [[root, 0]];
  let seen = 0;
  while (stack.length && seen < maxDirs) {
    const [dir, depth] = stack.pop();
    seen++;
    let ents;
    try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    const entries = [];
    for (const e of ents) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (depth < maxDepth && !SKIP.has(e.name)) stack.push([full, depth + 1]); }
      else if (e.isFile() || e.isSymbolicLink()) entries.push({ name: e.name, full, link: e.isSymbolicLink() });
    }
    out.push({ dir, entries });
  }
  return out;
}
const statFile = (full) => { try { const s = fs.statSync(full); return s.isFile() ? s : null; } catch (_) { return null; } };
const readJson = (full, max = 4 * 1024 * 1024) => {
  const s = statFile(full);
  if (!s || s.size > max) return null;
  try { return JSON.parse(fs.readFileSync(full, 'utf8')); } catch (_) { return null; }
};
const readText = (full, max = 1024 * 1024) => {
  const s = statFile(full);
  if (!s) return null;
  try { const fd = fs.openSync(full, 'r'); try { const b = Buffer.alloc(Math.min(s.size, max)); fs.readSync(fd, b, 0, b.length, 0); return b.toString('utf8'); } finally { fs.closeSync(fd); } } catch (_) { return null; }
};

// Python code that is part of a model folder. It runs when the model is loaded with trust_remote_code.
const CODE_ALARM = [
  ['os.system', /\bos\s*\.\s*(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?|startfile)\s*\(/],
  ['subprocess', /\bsubprocess\b/], ['eval(', /(?<![\w.])eval\s*\(/], ['exec(', /(?<![\w.])exec\s*\(/], ['__import__', /__import__\s*\(/],
  ['pickle', /\b(?:pickle|cPickle|dill|cloudpickle|marshal)\s*\.\s*loads?\b/], ['ctypes', /\b(?:ctypes|cffi)\b/],
];
const CODE_NET = [
  ['socket', /\bimport\s+socket\b|\bsocket\s*\.\s*(?:socket|create_connection)\b/], ['urllib', /\burllib\s*\.\s*request\b|\bfrom\s+urllib\.request\b|\burlopen\s*\(/],
  ['requests', /\brequests\s*\.\s*(?:get|post|put|request|Session)\b|\bimport\s+requests\b/], ['http', /\bhttp\.client\b|\bhttpx\b|\baiohttp\b/],
  ['ftp/smtp', /\b(?:ftplib|smtplib|paramiko|telnetlib)\b/], ['base64', /\bbase64\s*\.\s*(?:b64decode|decodebytes|urlsafe_b64decode|a85decode)\b/],
];
function codeFindings(dir, names) {
  const found = [];
  const pyFiles = names.filter((n) => /\.py$/i.test(n)).slice(0, 40);
  const danger = [];
  const net = [];
  let dangerFile = '';
  let netFile = '';
  for (const n of pyFiles) {
    const text = readText(path.join(dir, n), 1024 * 1024);
    if (text == null) continue;
    const code = text.split('\n').filter((l) => !/^\s*#/.test(l)).join('\n');
    for (const [name, re] of CODE_ALARM) if (re.test(code)) { if (!danger.includes(name)) danger.push(name); if (!dangerFile) dangerFile = n; }
    for (const [name, re] of CODE_NET) if (re.test(code)) { if (!net.includes(name)) net.push(name); if (!netFile) netFile = n; }
    if (/\bbase64\b/.test(code) && /(?<![\w.])(?:exec|eval|compile)\s*\(|marshal/.test(code) && !danger.includes('base64+exec')) { danger.push('base64+exec'); if (!dangerFile) dangerFile = n; }
  }
  if (danger.length) found.push({ key: 'xray.code.danger', params: { calls: danger.slice(0, 4).join(', '), file: word(dangerFile, 60) }, sev: 'alarm' });
  if (net.length) found.push({ key: 'xray.code.net', params: { calls: net.slice(0, 4).join(', '), file: word(netFile, 60) }, sev: 'watch' });
  if (pyFiles.length && !danger.length && !net.length) found.push({ key: 'xray.code.present', params: { n: pyFiles.length }, sev: 'watch' });
  return { found, files: pyFiles.length };
}

// The templates a Hugging Face folder holds: tokenizer_config.json, chat_template.jinja, chat_template.json
function templatesOf(dir, names) {
  const list = [];
  const push = (t) => { if (typeof t === 'string' && t) list.push(t); };
  const fromValue = (v) => { if (typeof v === 'string') push(v); else if (Array.isArray(v)) for (const x of v.slice(0, 8)) push(x && x.template); };
  if (names.includes('tokenizer_config.json')) { const j = readJson(path.join(dir, 'tokenizer_config.json')); if (j) fromValue(j.chat_template); }
  if (names.includes('chat_template.json')) { const j = readJson(path.join(dir, 'chat_template.json')); if (j) fromValue(j.chat_template); }
  if (names.includes('chat_template.jinja')) push(readText(path.join(dir, 'chat_template.jinja')));
  return list;
}

function hfName(dir) {
  const m = /models--([^\\/]+)--([^\\/]+)/.exec(dir);
  if (m) return `${m[1]}/${m[2]}`;
  return path.basename(dir);
}

function hfFolder(dir, entries) {
  const all = entries.map((e) => e.name);
  if (!all.includes('config.json') && !all.includes('tokenizer_config.json')) return null;
  const names = entries.filter((e) => statFile(e.full)).map((e) => e.name);
  const cfg = names.includes('config.json') ? readJson(path.join(dir, 'config.json')) : null;
  const tok = names.includes('tokenizer_config.json') ? readJson(path.join(dir, 'tokenizer_config.json')) : null;
  const looksLikeModel = (cfg && (cfg.model_type || cfg.architectures || cfg.auto_map)) || (tok && (tok.tokenizer_class || tok.model_max_length || tok.chat_template));
  if (!looksLikeModel) return null;
  const found = [];
  const facts = {};
  const texts = [];
  const code = codeFindings(dir, names);
  found.push(...code.found);
  if (code.files) facts.code = code.files;
  if (cfg && cfg.auto_map && typeof cfg.auto_map === 'object') {
    const refs = Object.values(cfg.auto_map).flatMap((v) => (Array.isArray(v) ? v : [v])).filter((v) => typeof v === 'string');
    const other = refs.find((v) => v.includes('--'));
    if (other) found.push({ key: 'xray.code.remote', params: { repo: word(other.split('--')[0], 80) }, sev: 'watch' });
  }
  const tpls = templatesOf(dir, names);
  for (const text of tpls) {
    found.push(...template(text, 'template'));
    texts.push({ part: 'template', name: '', chars: PART_CHARS(text), text: excerpt(text) });
  }
  if (tpls.length) facts.template = PART_CHARS(tpls[0]);
  if (!found.length) return null;
  return { path: dir, size: 0, format: 'Hugging Face', name: hfName(dir), state: worstOf(found), reasons: found, x: { facts, texts } };
}

// ---------- Ollama ----------
const OLLAMA_PART = { 'application/vnd.ollama.image.template': 'template', 'application/vnd.ollama.image.system': 'system', 'application/vnd.ollama.image.messages': 'messages' };
function ollamaModels(root) {
  const out = [];
  const mdir = path.join(root, 'manifests');
  for (const { entries } of collectDirs(mdir, { maxDepth: 6, maxDirs: 4000 })) {
    for (const e of entries.slice(0, 400)) {
      const man = readJson(e.full, 256 * 1024);
      if (!man || !Array.isArray(man.layers)) continue;
      const found = [];
      const facts = {};
      const texts = [];
      for (const layer of man.layers.slice(0, 40)) {
        const part = layer && OLLAMA_PART[layer.mediaType];
        if (!part || typeof layer.digest !== 'string' || !/^sha256:[0-9a-f]{16,64}$/.test(layer.digest)) continue;
        const text = readText(path.join(root, 'blobs', layer.digest.replace(':', '-')), 256 * 1024);
        if (text == null) continue;
        if (part === 'messages') found.push(...words(text, 'messages', { urls: false }));
        else if (part === 'system') found.push(...words(text, 'system', { urls: true }));
        else found.push(...words(text, 'template', { urls: true }));
        facts[part] = PART_CHARS(text);
        if (part !== 'messages') texts.push({ part, name: '', chars: PART_CHARS(text), text: excerpt(text) });
      }
      if (!found.length) continue;
      const rel = path.relative(mdir, e.full).split(path.sep);
      const name = rel.length >= 4 ? `${rel[rel.length - 3] === 'library' ? '' : rel[rel.length - 3] + '/'}${rel[rel.length - 2]}:${rel[rel.length - 1]}` : rel.join('/');
      out.push({ path: e.full, size: 0, format: 'Ollama', name: clean(name, 80), state: worstOf(found), reasons: found, x: { facts, texts } });
    }
  }
  return out;
}

// All folders of the model directories: the folders of models and the model files behind links that a plain
// walk does not follow (the Hugging Face cache keeps its files as links to a "blobs" folder).
const MODEL_FILE = /\.(pt|pth|ckpt|bin|pkl|pickle|joblib|safetensors|gguf|model|sav|dat|onnx|h5|hdf5|keras|npy)$/i;
function folders(dirs, { onProgress } = {}) {
  const entriesOut = [];
  const files = [];
  const seenDirs = new Set();
  for (const root of dirs) {
    let isOllama = /[\\/]\.ollama[\\/]models/i.test(root);
    try { if (!isOllama && fs.statSync(path.join(root, 'manifests')).isDirectory() && fs.statSync(path.join(root, 'blobs')).isDirectory()) isOllama = true; } catch (_) { /* no Ollama here */ }
    if (isOllama) { try { entriesOut.push(...ollamaModels(root)); } catch (_) { /* nothing to report for this folder */ } }
    for (const { dir, entries } of collectDirs(root)) {
      if (seenDirs.has(dir)) continue;
      seenDirs.add(dir);
      if (isOllama && /[\\/]blobs$/.test(dir)) continue;
      for (const e of entries) if (e.link && MODEL_FILE.test(e.name)) files.push(e.full);
      try { const r = hfFolder(dir, entries); if (r) entriesOut.push(r); } catch (_) { /* a folder that cannot be read gives no finding */ }
      if (onProgress) onProgress(entriesOut.length);
    }
  }
  return { entries: entriesOut, files };
}

module.exports = {
  inspect, folders, words, template, field, excerpt, escapes, jinjaCode, gguf, safetensors, onnx, npy, keras, program, programKind, isStrictName,
  hfFolder, ollamaModels, collectDirs, Reader, XErr, MODEL_FILE, QUANT, GGML, STEER, worstOf,
};
