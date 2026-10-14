'use strict';
// AgathOS - a small ZIP reader for the model checks. It reads the table of contents at the end of the
// file and the few entries that are asked for, never the whole archive (PyTorch files and Keras files
// are zips of many gigabytes). Nothing is unpacked to disk and no code is run.
const fs = require('fs');
const zlib = require('zlib');

function readAt(fd, pos, len) {
  const b = Buffer.alloc(len);
  const got = fs.readSync(fd, b, 0, len, pos);
  return b.subarray(0, got);
}

// entries(fd, size, wanted, cap) -> null when the file is no zip, otherwise [{ name, data }] for every
// entry whose name `wanted(name)` accepts and whose packed size is under `cap`. data is null when the entry
// uses a method we do not read or could not be unpacked (the caller decides what that means).
function entries(fd, size, wanted, cap) {
  if (size < 22) return null;
  const out = [];
  try {
    const tailLen = Math.min(size, 66000);
    const tail = readAt(fd, size - tailLen, tailLen);
    const eocd = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));
    if (eocd < 0 || eocd + 22 > tail.length) return null;
    let count = tail.readUInt16LE(eocd + 10);
    let cdSize = tail.readUInt32LE(eocd + 12);
    let cdOff = tail.readUInt32LE(eocd + 16);
    if (cdOff === 0xffffffff || count === 0xffff) {
      const loc = tail.lastIndexOf(Buffer.from([0x50, 0x4b, 0x06, 0x07]));
      if (loc < 0) return null;
      const z64off = Number(tail.readBigUInt64LE(loc + 8));
      const z = readAt(fd, z64off, 56);
      count = Number(z.readBigUInt64LE(32));
      cdSize = Number(z.readBigUInt64LE(40));
      cdOff = Number(z.readBigUInt64LE(48));
    }
    if (cdSize > 64 * 1024 * 1024 || cdOff + cdSize > size) return null;
    const cd = readAt(fd, cdOff, cdSize);
    let p = 0;
    for (let k = 0; k < count && p + 46 <= cd.length; k++) {
      if (cd.readUInt32LE(p) !== 0x02014b50) break;
      const method = cd.readUInt16LE(p + 10);
      let csize = cd.readUInt32LE(p + 20);
      const nlen = cd.readUInt16LE(p + 28);
      const xlen = cd.readUInt16LE(p + 30);
      const clen = cd.readUInt16LE(p + 32);
      let lho = cd.readUInt32LE(p + 42);
      const name = cd.toString('utf8', p + 46, p + 46 + nlen);
      // zip64 extra field
      let x = p + 46 + nlen;
      const xend = Math.min(x + xlen, cd.length);
      while (x + 4 <= xend) {
        const id = cd.readUInt16LE(x);
        const sz = cd.readUInt16LE(x + 2);
        if (id === 0x0001) {
          let q = x + 4;
          if (cd.readUInt32LE(p + 24) === 0xffffffff) q += 8;
          if (csize === 0xffffffff) { csize = Number(cd.readBigUInt64LE(q)); q += 8; }
          if (lho === 0xffffffff) { lho = Number(cd.readBigUInt64LE(q)); }
        }
        x += 4 + sz;
      }
      if (wanted(name) && csize < cap && lho + 30 <= size) {
        const lh = readAt(fd, lho, 30);
        if (lh.length === 30 && lh.readUInt32LE(0) === 0x04034b50) {
          const dataStart = lho + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
          const raw = readAt(fd, dataStart, csize);
          try {
            out.push({ name, data: method === 0 ? raw : method === 8 ? zlib.inflateRawSync(raw, { maxOutputLength: cap * 4 }) : null });
          } catch (_) {
            out.push({ name, data: null });
          }
        }
      }
      p += 46 + nlen + xlen + clen;
    }
  } catch (_) {
    return out.length ? out : null;                             // a damaged table of contents: what was read so far, or no zip at all
  }
  return out;
}

module.exports = { entries, readAt };
