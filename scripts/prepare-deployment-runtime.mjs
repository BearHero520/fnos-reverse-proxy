import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';

const root = path.resolve(import.meta.dirname, '..');
const version = 'v22.23.2';
const binaries = {
  x64: '3517c2df0b2f8cd7f422b4b8450ef81c6889f08eb03e281d6de9079b15e6a327',
  arm64: '1a638b0fe2b68da0489276aca95526c5122fc61ba54d6a2d0d00c1c92ab7b876',
};
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');
const cache = path.join(root, '.tools', 'deployment-node');
const target = path.join(root, 'App.Native.ReverseProxy', 'app', 'deployment-runtime');
fs.mkdirSync(cache, { recursive: true });
for (const [arch, expected] of Object.entries(binaries)) {
  const out = path.join(target, arch, 'node');
  if (!fs.existsSync(out) || digest(fs.readFileSync(out)) !== expected || !fs.existsSync(path.join(target, 'LICENSE'))) {
    const name = `node-${version}-linux-${arch}`;
    const archive = path.join(cache, `${name}.tar.xz`);
    if (!fs.existsSync(archive)) {
      const response = await fetch(`https://nodejs.org/dist/${version}/${name}.tar.xz`);
      if (!response.ok) throw new Error('无法下载官方部署运行时');
      fs.writeFileSync(archive, Buffer.from(await response.arrayBuffer()));
    }
    const bytes = execFileSync('tar', ['-xOf', archive, `${name}/bin/node`], { maxBuffer: 160 * 1024 * 1024 });
    if (digest(bytes) !== expected) throw new Error(`${arch} 部署运行时校验失败`);
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.writeFileSync(out, bytes);
    fs.writeFileSync(path.join(target, 'LICENSE'), execFileSync('tar', ['-xOf', archive, `${name}/LICENSE`], { maxBuffer: 2 * 1024 * 1024 }));
  }
  fs.chmodSync(out, 0o755);
}
console.log(`独立部署运行时 ${version}（x64 / arm64）SHA-256 校验通过`);
