import fs from 'node:fs';
import http from 'node:http';
import { FnosDeploymentEngine, DEPLOY_ERRORS } from './lib/fnos-deployment-engine.js';

// No TCP listener, shell endpoint, user-controlled path, or third-party module.
if (process.platform !== 'linux' || process.getuid?.() !== 0) throw new Error('This optional helper requires fnOS root lifecycle permission.');
const socketPath = '/run/reverse-proxy-cert-deployer/control.sock';
const stateDir = '/var/lib/reverse-proxy-cert-deployer';
for (const directory of [stateDir, '/run/reverse-proxy-cert-deployer']) {
  const stat = fs.lstatSync(directory);
  if (!stat.isDirectory() || stat.isSymbolicLink() || stat.uid !== 0 || stat.mode & 0o022) throw new Error('Unsafe helper directory');
}
const engine = new FnosDeploymentEngine();
engine.busy = true;
let recovering = true;
if (fs.existsSync(socketPath)) {
  const stat = fs.lstatSync(socketPath);
  if (!stat.isSocket() || stat.uid !== 0) throw new Error('Unsafe helper socket');
  fs.unlinkSync(socketPath);
}
const server = http.createServer(async (req, res) => {
  const reply = (status, body) => { if (!res.destroyed) { res.writeHead(status, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' }); res.end(JSON.stringify(body)); } };
  if (req.method !== 'POST' || !['/status', '/prepare', '/deploy'].includes(req.url)) return reply(404, { code: 'UNAVAILABLE' });
  if (recovering) return reply(409, { code: 'BUSY' });
  try {
    const chunks = []; let size = 0;
    for await (const chunk of req) { size += chunk.length; if (size > 1024 * 1024) { reply(413, { code: 'INVALID' }); req.destroy(); return; } chunks.push(chunk); }
    const input = JSON.parse(Buffer.concat(chunks).toString() || '{}');
    const result = req.url === '/status' ? await engine.status() : req.url === '/prepare' ? await engine.prepare(input) : await engine.deploy(input);
    reply(200, result);
  } catch (error) { reply(error.status || 503, { code: DEPLOY_ERRORS[error.code] ? error.code : 'INCOMPATIBLE', stage: error.stage }); }
});
server.requestTimeout = 15000; server.headersTimeout = 10000;
server.listen(socketPath, () => {
  fs.chmodSync(socketPath, 0o660); fs.chownSync(socketPath, 0, fs.statSync('/run/reverse-proxy-cert-deployer').gid);
  void engine.recover().finally(() => { recovering = false; engine.busy = false; });
});
for (const signal of ['SIGTERM', 'SIGINT']) process.on(signal, () => server.close(() => process.exit(0)));
