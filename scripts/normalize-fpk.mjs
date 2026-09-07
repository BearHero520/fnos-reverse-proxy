import fs from 'node:fs';
import { gunzipSync, gzipSync } from 'node:zlib';
import { createHash } from 'node:crypto';

// fnpack on Windows writes regular files as 0666. Normalize archive metadata
// before verification/publication so the privileged worker is never writable
// by other application users and its bundled ELF runtime is executable.
function normalize(tar, outer) {
  let appBytes;
  if (outer) {
    for (let offset = 0; offset + 512 <= tar.length;) {
      const name = tar.subarray(offset, offset + 100).toString().split('\0')[0].replace(/^\.\//, '');
      if (!name) break;
      const size = parseInt(tar.subarray(offset + 124, offset + 136).toString().replace(/\0/g, '').trim() || '0', 8);
      if (!Number.isSafeInteger(size) || size < 0 || offset + 512 + size > tar.length) throw new Error('Invalid outer tar');
      if (name === 'app.tgz') appBytes = gzipSync(normalize(gunzipSync(tar.subarray(offset + 512, offset + 512 + size)), false));
      offset += 512 + Math.ceil(size / 512) * 512;
    }
    if (!appBytes) throw new Error('Missing app.tgz');
  }
  const parts = [];
  for (let offset = 0; offset + 512 <= tar.length;) {
    const header = Buffer.from(tar.subarray(offset, offset + 512));
    if (header.every((b) => b === 0)) break;
    const field = (start, size) => header.subarray(start, start + size).toString().split('\0')[0];
    const name = [field(345, 155), field(0, 100)].filter(Boolean).join('/').replace(/^\.\//, '');
    const size = parseInt(field(124, 12).trim() || '0', 8);
    if (!Number.isSafeInteger(size) || size < 0 || offset + 512 + size > tar.length) throw new Error('Invalid FPK tar size');
    const type = header[156];
    let body = tar.subarray(offset + 512, offset + 512 + size);
    if (outer && name === 'app.tgz') body = appBytes;
    if (outer && name === 'manifest') {
      const manifest = body.toString();
      if (!/^checksum\s*=/m.test(manifest)) throw new Error('Missing manifest checksum');
      body = Buffer.from(manifest.replace(/^checksum\s*=.*$/m, `checksum = ${createHash('md5').update(appBytes).digest('hex')}`));
    }
    const octal = (at, length, value) => { header.fill(0, at, at + length); header.write(value.toString(8).padStart(length - 1, '0'), at, length - 1, 'ascii'); };
    const executable = outer ? name.startsWith('cmd/') : /^deployment-runtime\/(x64|arm64)\/node$/.test(name);
    octal(100, 8, type === 53 || executable ? 0o755 : type === 50 ? 0o777 : 0o644);
    octal(108, 8, 0); octal(116, 8, 0); octal(124, 12, body.length);
    header.fill(0, 265, 329); header.write('root', 265); header.write('root', 297);
    header.fill(32, 148, 156);
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    header.write(checksum.toString(8).padStart(6, '0') + '\0 ', 148, 8, 'ascii');
    parts.push(header, body, Buffer.alloc((512 - body.length % 512) % 512));
    offset += 512 + Math.ceil(size / 512) * 512;
  }
  return Buffer.concat([...parts, Buffer.alloc(1024)]);
}

export function normalizeFpk(file) {
  fs.writeFileSync(file, gzipSync(normalize(gunzipSync(fs.readFileSync(file)), true)));
}
