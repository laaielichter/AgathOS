'use strict';
// AgathOS - model file scanner.
// Pickle-based formats (.pt, .pth, .ckpt, .bin, .pkl, .joblib) can run code the moment
// they are loaded. We recognise the format by content, not by extension, walk the
// pickle opcodes ourselves (no Python needed) and list every import the file makes.
// A file we cannot read counts as suspicious (scanner bypasses like "nullifAI" relied
// on broken files that loaders still accepted).
const fs = require('fs');
const path = require('path');
const { walk } = require('./util');
const X = require('./xray');            // Model X-ray: looks inside GGUF, safetensors, Keras, ONNX, folders of models ...

const DANGEROUS = [
  /^(os|posix|nt|subprocess|pty|commands|popen2|platform)(\.|$)/, /^(socket|ssl|http|httplib|urllib|urllib2|requests|ftplib|smtplib|telnetlib|webbrowser)(\.|$)/,
  /^(runpy|importlib|imp|code|codeop|pydoc|pickle|_pickle|cPickle|marshal|shelve|dill|cloudpickle)(\.|$)/, /^(ctypes|cffi|sys|shutil|tempfile|asyncio|multiprocessing|threading)(\.|$)/,
  /^(types)\.(FunctionType|CodeType|LambdaType)$/, /^(builtins|__builtin__|__builtins__)\.(eval|exec|compile|__import__|open|getattr|setattr|delattr|globals|locals|vars|input|breakpoint|apply|execfile|file)$/,
  /^(operator)\.(attrgetter|methodcaller)$/, /^(functools)\.(partial)$/,
];
const SAFE = [
  /^torch(\.|$)/, /^collections\.(OrderedDict|defaultdict|deque|Counter)$/, /^numpy(\.|$)/, /^_codecs\.encode$/, /^builtins\.(set|frozenset|bytearray|slice|range|complex|dict|list|tuple|int|float|bool|str|bytes|object)$/,
  /^__builtin__\.(set|frozenset|bytearray|slice|complex)$/, /^copy_reg\._reconstructor$/, /^copyreg\._reconstructor$/, /^sklearn(\.|$)/, /^scipy(\.|$)/,
  /^pandas(\.|$)/, /^transformers(\.|$)/, /^tokenizers(\.|$)/, /^datetime\.(datetime|date|time|timedelta|timezone)$/, /^decimal\.Decimal$/,
  /^pathlib\.(Path|PosixPath|WindowsPath|PurePosixPath|PureWindowsPath)$/, /^argparse\.Namespace$/, /^fractions\.Fraction$/, /^joblib\.numpy_pickle(\.|$)/,
];

// ---------- Pickle opcode walker ----------
function argLen(buf, i, n) {
  if (i + n > buf.length) return -1;
  if (n === 1) return buf[i];
  if (n === 2) return buf.readUInt16LE(i);
  if (n === 4) return buf.readUInt32LE(i);
  if (n === 8) { const v = buf.readBigUInt64LE(i); return v > 0xffffffffn ? -1 : Number(v); }
  return -1;
}

function readLine(buf, i) {
  const end = buf.indexOf(0x0a, i);
  if (end === -1) return null;
  return { text: buf.toString('latin1', i, end), next: end + 1 };
}

// Returns { globals: ['module.name', ...], ok: bool }
function pickleGlobals(buf, maxOps = 2_000_000) {
  const globals = [];
  const strings = [];      // recent strings (for STACK_GLOBAL)
  const memo = new Map();  // memo index -> string
  let lastPushed = null;
  let memoCounter = 0;
  let i = 0;
  let ops = 0;
  const pushStr = (s) => { strings.push(s); if (strings.length > 8) strings.shift(); lastPushed = s; };
  while (i < buf.length && ops++ < maxOps) {
    const op = buf[i++];
    const ch = String.fromCharCode(op);
    let n;
    switch (ch) {
      case '.': return { globals, ok: true };
      case '(': case '0': case '1': case '2': case 'N': case 'Q': case 'R': case 'a': case 'b': case 'd': case '}':
      case 'e': case 'l': case ']': case 'o': case 's': case 't': case ')': case 'u':
        lastPushed = null; break;
      case 'F': case 'I': case 'L': case 'P': case 'g': case 'p': {
        const l = readLine(buf, i); if (!l) return { globals, ok: false };
        if (ch === 'g' && memo.has(l.text)) pushStr(memo.get(l.text));
        if (ch === 'p' && lastPushed != null) memo.set(l.text, lastPushed);
        i = l.next; break;
      }
      case 'S': case 'V': {
        const l = readLine(buf, i); if (!l) return { globals, ok: false };
        pushStr(l.text.replace(/^['"]|['"]$/g, '')); i = l.next; break;
      }
      case 'c': case 'i': {
        const a = readLine(buf, i); if (!a) return { globals, ok: false };
        const b = readLine(buf, a.next); if (!b) return { globals, ok: false };
        globals.push(`${a.text}.${b.text}`); i = b.next; lastPushed = null; break;
      }
      case 'J': i += 4; break;
      case 'K': i += 1; break;
      case 'M': i += 2; break;
      case 'G': i += 8; break;
      case 'h': { const k = String(buf[i]); if (memo.has(k)) pushStr(memo.get(k)); i += 1; break; }
      case 'j': { const k = String(argLen(buf, i, 4)); if (memo.has(k)) pushStr(memo.get(k)); i += 4; break; }
      case 'q': { if (lastPushed != null) memo.set(String(buf[i]), lastPushed); i += 1; break; }
      case 'r': { if (lastPushed != null) memo.set(String(argLen(buf, i, 4)), lastPushed); i += 4; break; }
      case 'T': case 'B': n = argLen(buf, i, 4); if (n < 0) return { globals, ok: false }; i += 4 + n; lastPushed = null; break;
      case 'U': case 'C': n = argLen(buf, i, 1); if (n < 0) return { globals, ok: false }; i += 1 + n; lastPushed = null; break;
      case 'X': n = argLen(buf, i, 4); if (n < 0) return { globals, ok: false }; pushStr(buf.toString('utf8', i + 4, i + 4 + n)); i += 4 + n; break;
      default:
        switch (op) {
          case 0x80: i += 1; break;                          // PROTO
          case 0x81: case 0x85: case 0x86: case 0x87: case 0x88: case 0x89: case 0x8f: case 0x90: case 0x91: case 0x92:
          case 0x97: case 0x98: lastPushed = null; break;
          case 0x82: i += 1; break; case 0x83: i += 2; break; case 0x84: i += 4; break;
          case 0x8a: n = argLen(buf, i, 1); if (n < 0) return { globals, ok: false }; i += 1 + n; break;
          case 0x8b: n = argLen(buf, i, 4); if (n < 0) return { globals, ok: false }; i += 4 + n; break;
          case 0x8c: n = argLen(buf, i, 1); if (n < 0) return { globals, ok: false }; pushStr(buf.toString('utf8', i + 1, i + 1 + n)); i += 1 + n; break;
          case 0x8d: n = argLen(buf, i, 8); if (n < 0) return { globals, ok: false }; pushStr(buf.toString('utf8', i + 8, i + 8 + n)); i += 8 + n; break;
          case 0x8e: case 0x96: n = argLen(buf, i, 8); if (n < 0) return { globals, ok: false }; i += 8 + n; break;
          case 0x93: {                                       // STACK_GLOBAL
            const name = strings[strings.length - 1];
            const mod = strings[strings.length - 2];
            globals.push(`${mod ?? '?'}.${name ?? '?'}`);
            lastPushed = null; break;
          }
          case 0x94: memo.set(String(memoCounter++), lastPushed); break;  // MEMOIZE
          case 0x95: i += 8; break;                          // FRAME
          default: return { globals, ok: false };            // unknown opcode: cannot trust the rest
        }
    }
  }
  return { globals, ok: false };
}

function classifyGlobals(globals) {
  const danger = [];
  const unknown = [];
  for (const g of new Set(globals)) {
    if (DANGEROUS.some((re) => re.test(g))) danger.push(g);
    else if (!SAFE.some((re) => re.test(g))) unknown.push(g);
  }
  return { danger, unknown };
}

// ---------- Minimal ZIP reader (PyTorch .pt files are zips with data.pkl inside) ----------
const zip = require('./zipread');
const readAt = zip.readAt;
const zipPickles = (fd, size) => zip.entries(fd, size, (name) => /\.pkl$|data\.pkl$|\.pickle$/i.test(name), 64 * 1024 * 1024);

// ---------- One file ----------
const OPAQUE_NAME = /^(sha256[-:])?[0-9a-f]{12,}$/i;
// { xray: false } skips the look inside (Settings): formats are then only recognised, as before.
function scanModel(file, { xray = true } = {}) {
  let fd;
  try {
    const st = fs.statSync(file);
    fd = fs.openSync(file, 'r');
    const head = readAt(fd, 0, 16);
    // Ollama keeps its models in files that are named after a hash. The name inside the file says more.
    const nameInside = (x) => (x && x.facts && x.facts.name && OPAQUE_NAME.test(path.basename(file)) ? { name: x.facts.name } : {});
    const r = (format, state, reasons, x) => ({ path: file, size: st.size, format, state, reasons, ...(x ? { x } : {}), ...nameInside(x) });

    if (xray) {
      let xr;
      // A file that makes the look inside fail is not "fine": it is shown as one that could not be read.
      try { xr = X.inspect(file, fd, st.size, head); } catch (_) {
        return r(head.length >= 4 && head.toString('latin1', 0, 4) === 'GGUF' ? 'GGUF' : 'model file', 'watch', [{ key: 'model.unreadable', params: {}, sev: 'watch' }]);
      }
      if (xr) return r(xr.format, xr.state, xr.reasons, xr.x);
    }

    if (head.length >= 4 && head.toString('latin1', 0, 4) === 'GGUF') {
      return r('GGUF', 'calm', [{ key: 'model.safe', params: { format: 'GGUF' }, sev: 'calm' }]);
    }
    if (head.length >= 8) {
      const n = Number(head.readBigUInt64LE(0));
      if (n > 1 && n < 100 * 1024 * 1024 && head[8] === 0x7b) {
        try {
          JSON.parse(readAt(fd, 8, n).toString('utf8'));
          return r('safetensors', 'calm', [{ key: 'model.safe', params: { format: 'safetensors' }, sev: 'calm' }]);
        } catch (_) { /* fall through */ }
      }
    }
    let pickles = null;
    let format = null;
    if (head[0] === 0x50 && head[1] === 0x4b && head[2] === 0x03 && head[3] === 0x04) {
      pickles = zipPickles(fd, st.size);
      if (!pickles || !pickles.length) return null;          // ordinary zip without pickle: not a model we judge
      format = 'PyTorch (zip + pickle)';
    } else if (head[0] === 0x80 && head[1] >= 2 && head[1] <= 5) {
      pickles = [{ name: path.basename(file), data: readAt(fd, 0, Math.min(st.size, 64 * 1024 * 1024)) }];
      format = 'pickle';
    } else if ('(c]}lSVIi'.includes(String.fromCharCode(head[0])) && /\.(pkl|pickle|joblib|bin|pt|pth|ckpt|sav|dat)$/i.test(file)) {
      // Protocol 0/1 pickles have no header byte. Only accept when the opcode walk agrees.
      const data = readAt(fd, 0, Math.min(st.size, 64 * 1024 * 1024));
      const g = pickleGlobals(data);
      if (!g.ok && !g.globals.length) return null;
      pickles = [{ name: path.basename(file), data }];
      format = 'pickle (protocol 0/1)';
    } else {
      return null;                                           // ONNX, raw weights etc.: not code-carrying formats
    }
    const all = [];
    let readable = true;
    for (const p of pickles) {
      if (!p.data) { readable = false; continue; }
      const g = pickleGlobals(p.data);
      if (!g.ok) readable = false;
      all.push(...g.globals);
    }
    const { danger, unknown } = classifyGlobals(all);
    const reasons = [{ key: 'model.pickle', params: {}, sev: 'watch' }];
    let state = 'watch';
    if (danger.length) {
      reasons.unshift({ key: 'model.pickleDanger', params: { calls: danger.slice(0, 4).join(', ') }, sev: 'alarm' });
      state = 'alarm';
    } else if (unknown.length) {
      reasons.push({ key: 'model.pickleUnknown', params: { calls: unknown.slice(0, 4).join(', ') }, sev: 'watch' });
    }
    if (!readable) {
      reasons.push({ key: 'model.unreadable', params: {}, sev: 'alarm' });
      state = 'alarm';
    }
    return r(format, state, reasons);
  } catch (_) {
    return null;
  } finally {
    if (fd !== undefined) try { fs.closeSync(fd); } catch (_) {}
  }
}

const MODEL_EXT = /\.(pt|pth|ckpt|bin|pkl|pickle|joblib|safetensors|gguf|model|sav|dat|onnx|h5|hdf5|keras|npy)$|\.llamafile(\.exe)?$/i;
// Names that anything can carry (an installer, a game file) are only looked at when they are big enough to be a model.
const BIG_ONLY = /\.(pt|pth|ckpt|bin|pkl|pickle|joblib|model|sav|dat)$/i;

// One file of a folder scan. A file that did not change since the last scan keeps its result.
const CACHE = new Map();
function scanOne(file, useX) {
  let st;
  try { st = fs.statSync(file); } catch (_) { return null; }
  if (!st.isFile() || (st.size < 64 * 1024 && BIG_ONLY.test(file))) return null;
  const sig = `${st.size}|${st.mtimeMs}|${useX ? 1 : 0}`;
  const hit = CACHE.get(file);
  if (hit && hit.sig === sig) return hit.res;
  const res = scanModel(file, { xray: useX });
  if (CACHE.size > 20000) CACHE.clear();
  CACHE.set(file, { sig, res });
  return res;
}

function scanModelDirs(dirs, { onProgress, xray = true } = {}) {
  const results = [];
  const done = new Set();
  for (const dir of dirs) {
    const isOllama = /[\\/]\.ollama[\\/]models/i.test(dir);
    const files = walk(dir, {
      maxDepth: 6, maxFiles: 5000,
      skipDirs: new Set(['.git', 'node_modules']),
      filter: (f, name) => (isOllama ? /sha256[-:]/.test(name) : MODEL_EXT.test(name)),
    });
    for (const f of files) {
      if (done.has(f)) continue;
      done.add(f);
      const res = scanOne(f, xray);
      if (res) results.push(res);
      if (onProgress) onProgress(results.length);
    }
  }
  if (xray) {
    // The folders of models (code and templates that come with them) and the files behind links, which a plain walk
    // does not follow: the Hugging Face cache keeps its files as links to a folder of nameless "blobs".
    let more = { entries: [], files: [] };
    try { more = X.folders(dirs); } catch (_) { /* no folders to report */ }
    for (const f of more.files) {
      if (done.has(f)) continue;
      done.add(f);
      const res = scanOne(f, true);
      if (res) results.push(res);
    }
    results.push(...more.entries);
    if (onProgress) onProgress(results.length);
  }
  return results;
}

module.exports = { scanModel, scanModelDirs, pickleGlobals, classifyGlobals };
