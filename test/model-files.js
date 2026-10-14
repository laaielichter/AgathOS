'use strict';
// AgathOS - builds small model files for the tests of Model X-ray: GGUF, safetensors, ONNX, NumPy and a zip
// for Keras. They are written the way the programs that make real ones write them (same layout, same padding),
// so the checks are tried on files that look like the real thing. Nothing here needs Python or a network.
const zlib = require('zlib');

const num = (bits, be) => (n) => {
  const b = Buffer.alloc(bits / 8);
  if (bits === 32) { if (be) b.writeUInt32BE(n >>> 0); else b.writeUInt32LE(n >>> 0); } else if (be) b.writeBigUInt64BE(BigInt(n)); else b.writeBigUInt64LE(BigInt(n));
  return b;
};
const u32 = num(32, false);
const u64 = num(64, false);

// ---------- GGUF ----------
// kvs: [[key, type, value]] with type 'str' | 'u32' | 'u64' | 'arrstr' | 'arrf32' (value: the number of floats) | 'arrarr'
// tensors: [{ name, dims, type = 0 (F32) }]; their data is laid out one after the other, each aligned
// options: version (2 or 3 are read; any other number is only written into the header), be (big-endian), align, extra (bytes behind the last tensor), cut (bytes cut off the end),
// counts (lie about the number of tensors and settings), padTo (zeros at the end up to a size)
function gguf({ kvs = [], tensors = [], version = 3, be = false, align = 32, extra = 0, cut = 0, counts = null, padTo = 0 } = {}) {
  const U32 = num(32, be);
  const U64 = num(64, be);
  const cnt = U64;
  const str = (s) => { const d = Buffer.from(s, 'utf8'); return Buffer.concat([cnt(d.length), d]); };
  const kv = (k, t, v) => {
    if (t === 'str') return Buffer.concat([str(k), U32(8), str(v)]);
    if (t === 'u32') return Buffer.concat([str(k), U32(4), U32(v)]);
    if (t === 'u64') return Buffer.concat([str(k), U32(10), U64(v)]);
    if (t === 'arrstr') return Buffer.concat([str(k), U32(9), U32(8), cnt(v.length), ...v.map(str)]);
    if (t === 'arrf32') return Buffer.concat([str(k), U32(9), U32(6), cnt(v), Buffer.alloc(4 * v)]);
    if (t === 'arrarr') return Buffer.concat([str(k), U32(9), U32(9), cnt(v.length), ...v.map((a) => Buffer.concat([U32(8), cnt(a.length), ...a.map(str)]))]);
    throw new Error(`kv type ${t}`);
  };
  const head = [Buffer.from('GGUF'), U32(version), cnt(counts ? counts[0] : tensors.length), cnt(counts ? counts[1] : kvs.length)];
  const body = kvs.map(([k, t, v]) => kv(k, t, v));
  const unit = { 0: [1, 4], 1: [1, 2], 8: [32, 34], 12: [256, 144], 14: [256, 210] };
  let off = 0;
  const infos = [];
  for (const t of tensors) {
    const elems = t.dims.reduce((a, b) => a * b, 1);
    const [blk, bytesPer] = unit[t.type || 0];
    const bytes = (elems / blk) * bytesPer;
    infos.push(Buffer.concat([str(t.name), U32(t.dims.length), ...t.dims.map(U64), U32(t.type || 0), U64(off)]));
    off += Math.ceil(bytes / align) * align;
  }
  let pre = Buffer.concat([...head, ...body, ...infos]);
  pre = Buffer.concat([pre, Buffer.alloc((align - (pre.length % align)) % align)]);
  let out = Buffer.concat([pre, Buffer.alloc(off), Buffer.alloc(extra, 7)]);
  if (padTo && out.length < padTo) out = Buffer.concat([out, Buffer.alloc(padTo - out.length)]);
  if (cut) out = out.subarray(0, out.length - cut);
  return out;
}

// ---------- safetensors ----------
// tensors: [{ name, shape, dtype = 'F32' }]; meta: the free text fields; extra: bytes behind the last tensor;
// gap: a hole before the second tensor; badSize: the first tensor claims four bytes too many
function safetensors({ tensors = [], meta = null, extra = 0, gap = false, badSize = false } = {}) {
  const obj = {};
  if (meta) obj.__metadata__ = meta;
  const unit = { F32: 4, F16: 2, BF16: 2, I8: 1, F64: 8 };
  let off = 0;
  for (const t of tensors) {
    const n = t.shape.reduce((a, b) => a * b, 1) * (unit[t.dtype || 'F32'] || 4);
    const b = off + (gap && t === tensors[1] ? 8 : 0);
    obj[t.name] = { dtype: t.dtype || 'F32', shape: t.shape, data_offsets: [b, b + (badSize && t === tensors[0] ? n + 4 : n)] };
    off = b + n;
  }
  let hdr = JSON.stringify(obj);
  hdr += ' '.repeat((8 - (hdr.length % 8)) % 8);
  const h = Buffer.from(hdr, 'utf8');
  return Buffer.concat([u64(h.length), h, Buffer.alloc(off), Buffer.alloc(extra, 9)]);
}

// ---------- ONNX (protobuf by hand) ----------
const vi = (n) => { const out = []; do { let b = n % 128; n = Math.floor(n / 128); if (n) b |= 0x80; out.push(b); } while (n); return Buffer.from(out); };
const pbLen = (field, buf) => Buffer.concat([vi(field * 8 + 2), vi(buf.length), buf]);
const pbVar = (field, n) => Buffer.concat([vi(field * 8), vi(n)]);
const pbStr = (field, s) => pbLen(field, Buffer.from(s, 'utf8'));
// initializers: [{ name, external: [[key, value]] }]; props: [[key, value]] (metadata_props); raw: bytes of data per initializer
function onnx({ initializers = [], props = [], raw = 0 } = {}) {
  const inits = initializers.map((init) => {
    const parts = [pbVar(1, 4), pbVar(2, 1), pbStr(8, init.name)];
    if (raw) parts.push(pbLen(9, Buffer.alloc(raw)));
    for (const [k, v] of init.external || []) parts.push(pbLen(13, Buffer.concat([pbStr(1, k), pbStr(2, v)])));
    return pbLen(5, Buffer.concat(parts));
  });
  const graph = pbLen(7, Buffer.concat([pbStr(2, 'g'), ...inits]));
  const meta = props.map(([k, v]) => pbLen(14, Buffer.concat([pbStr(1, k), pbStr(2, v)])));
  return Buffer.concat([pbVar(1, 8), pbStr(2, 'test'), graph, ...meta]);
}

// ---------- NumPy ----------
function npy(descr, payload) {
  const header = `{'descr': '${descr}', 'fortran_order': False, 'shape': (3,), }`;
  const padded = header + ' '.repeat((64 - ((10 + header.length + 1) % 64)) % 64) + '\n';
  const h = Buffer.from(padded, 'latin1');
  return Buffer.concat([Buffer.from([0x93]), Buffer.from('NUMPY'), Buffer.from([1, 0]), Buffer.from([h.length & 255, h.length >> 8]), h, payload]);
}

// ---------- zip (Keras files are zips) ----------
function zipFile(entries) {
  const locals = [];
  const cds = [];
  let off = 0;
  for (const [name, data, method = 8] of entries) {
    const nm = Buffer.from(name);
    const comp = method === 8 ? zlib.deflateRawSync(data) : data;
    const lh = Buffer.alloc(30);
    lh.writeUInt32LE(0x04034b50, 0); lh.writeUInt16LE(20, 4); lh.writeUInt16LE(method, 8); lh.writeUInt32LE(comp.length, 18); lh.writeUInt32LE(data.length, 22); lh.writeUInt16LE(nm.length, 26);
    const local = Buffer.concat([lh, nm, comp]);
    const cd = Buffer.alloc(46);
    cd.writeUInt32LE(0x02014b50, 0); cd.writeUInt16LE(20, 4); cd.writeUInt16LE(20, 6); cd.writeUInt16LE(method, 10); cd.writeUInt32LE(comp.length, 20); cd.writeUInt32LE(data.length, 24); cd.writeUInt16LE(nm.length, 28); cd.writeUInt32LE(off, 42);
    locals.push(local); cds.push(Buffer.concat([cd, nm])); off += local.length;
  }
  const cdBuf = Buffer.concat(cds);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0); eocd.writeUInt16LE(entries.length, 8); eocd.writeUInt16LE(entries.length, 10); eocd.writeUInt32LE(cdBuf.length, 12); eocd.writeUInt32LE(off, 16);
  return Buffer.concat([...locals, cdBuf, eocd]);
}

// A chat template as the common models have it (ChatML).
const CHATML = "{% for m in messages %}<|im_start|>{{ m['role'] }}\n{{ m['content'] }}<|im_end|>\n{% endfor %}{% if add_generation_prompt %}<|im_start|>assistant\n{% endif %}";

module.exports = { gguf, safetensors, onnx, npy, zipFile, u32, u64, CHATML };
