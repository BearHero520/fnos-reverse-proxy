import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { once } from 'node:events';
import fs from 'node:fs/promises';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';

const backendDir = path.resolve(import.meta.dirname, '..');
const serverFile = path.join(backendDir, 'server.js');
const gatewayPrefix = '/app/reverse-proxy';

function request({ socketPath, port, pathname, method = 'GET', headers = {}, body = '' }) {
  return new Promise((resolve, reject) => {
    const req = http.request({
      method,
      path: pathname,
      headers,
      ...(socketPath ? { socketPath } : { host: '127.0.0.1', port }),
    }, (res) => {
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => resolve({
        status: res.statusCode,
        body: Buffer.concat(chunks).toString('utf8'),
        headers: res.headers,
      }));
    });
    req.on('error', reject);
    req.end(body);
  });
}

async function waitForServer(target, expectedStatus) {
  let lastError;
  for (let attempt = 0; attempt < 100; attempt += 1) {
    try {
      const response = await request({
        ...target,
        pathname: `${gatewayPrefix}/api/status`,
      });
      if (response.status === expectedStatus) return;
      lastError = new Error(`服务已响应，但状态码为 ${response.status}`);
    } catch (error) {
      lastError = error;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw lastError || new Error('等待服务启动超时');
}

async function freeTcpPort() {
  const probe = net.createServer();
  probe.unref();
  await new Promise((resolve, reject) => {
    probe.once('error', reject);
    probe.listen(0, '127.0.0.1', resolve);
  });
  const { port } = probe.address();
  await new Promise((resolve, reject) => probe.close((error) => error ? reject(error) : resolve()));
  return port;
}

async function startServer({ socketPath = '', port = '' }) {
  const dataDir = await fs.mkdtemp(path.join(os.tmpdir(), 'reverse-proxy-auth-'));
  const child = spawn(process.execPath, [serverFile], {
    cwd: backendDir,
    env: {
      ...process.env,
      DATA_DIR: dataDir,
      FRONTEND_DIST: path.join(dataDir, 'missing-frontend'),
      FNOS_SYSTEM_CERT_CONFIG: path.join(dataDir, 'missing-system-certificates.json'),
      FNOS_SYSTEM_CERT_REFRESH_SECONDS: '3600',
      GATEWAY_PREFIX: gatewayPrefix,
      PORT: String(port),
      SOCKET_PATH: socketPath,
    },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let diagnostics = '';
  child.stdout.on('data', (chunk) => { diagnostics += chunk; });
  child.stderr.on('data', (chunk) => { diagnostics += chunk; });
  child.once('exit', (code, signal) => {
    if (code && !diagnostics) diagnostics = `server exited with code ${code}, signal ${signal}`;
  });
  return { child, dataDir, diagnostics: () => diagnostics };
}

async function stopServer(instance) {
  if (instance.child.exitCode === null && instance.child.signalCode === null) {
    instance.child.kill('SIGTERM');
    await Promise.race([
      once(instance.child, 'exit'),
      new Promise((resolve) => setTimeout(resolve, 3_000)),
    ]);
    if (instance.child.exitCode === null && instance.child.signalCode === null) instance.child.kill('SIGKILL');
  }
  await fs.rm(instance.dataDir, { recursive: true, force: true });
}

test('UDS 统一网关模式要求已登录的 fnOS 管理员头', { timeout: 20_000 }, async (t) => {
  const socketPath = process.platform === 'win32'
    ? `\\\\.\\pipe\\reverse-proxy-${process.pid}-${randomUUID()}`
    : path.join(os.tmpdir(), `reverse-proxy-${process.pid}-${randomUUID()}.sock`);
  const instance = await startServer({ socketPath });
  t.after(() => stopServer(instance));

  try { await waitForServer({ socketPath }, 401); }
  catch (error) { throw new Error(`${error.message}\n${instance.diagnostics()}`); }

  const missingIdentity = await request({ socketPath, pathname: `${gatewayPrefix}/api/rules` });
  assert.equal(missingIdentity.status, 401);
  assert.match(missingIdentity.body, /fnOS/);
  assert.equal(missingIdentity.headers['cache-control'], 'no-store');
  assert.match(missingIdentity.headers['content-type'], /^application\/json\b/);

  const malformedBeforeAuth = await request({
    socketPath,
    pathname: `${gatewayPrefix}/api/rules`,
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: '{',
  });
  assert.equal(malformedBeforeAuth.status, 401, '未鉴权请求不应先解析大请求体');

  const missingAdmin = await request({
    socketPath,
    pathname: `${gatewayPrefix}/api/status`,
    headers: { 'X-Trim-Userid': '1000' },
  });
  assert.equal(missingAdmin.status, 403);

  for (const value of ['false', '1', 'yes']) {
    const rejected = await request({
      socketPath,
      pathname: `${gatewayPrefix}/api/status`,
      headers: { 'X-Trim-Userid': '1000', 'X-Trim-Isadmin': value },
    });
    assert.equal(rejected.status, 403, `X-Trim-Isadmin=${JSON.stringify(value)} 不应通过`);
  }

  const duplicatedAdmin = await request({
    socketPath,
    pathname: `${gatewayPrefix}/api/status`,
    headers: { 'X-Trim-Userid': '1000', 'X-Trim-Isadmin': ['true', 'false'] },
  });
  assert.equal(duplicatedAdmin.status, 403);

  const admin = await request({
    socketPath,
    pathname: `${gatewayPrefix}/api/status`,
    headers: { 'X-Trim-Userid': '1000', 'X-Trim-Isadmin': 'TrUe' },
  });
  assert.equal(admin.status, 200);
  assert.equal(JSON.parse(admin.body).ok, true);
  assert.equal(admin.headers['cache-control'], 'no-store');

  const bareApi = await request({
    socketPath,
    pathname: '/api/status',
    headers: { 'X-Trim-Userid': '1000', 'X-Trim-Isadmin': 'true' },
  });
  assert.equal(bareApi.status, 404);
});

test('本地 TCP 模式仅绑定回环地址且保留无头 API 调试访问', { timeout: 20_000 }, async (t) => {
  const port = await freeTcpPort();
  const instance = await startServer({ port });
  t.after(() => stopServer(instance));

  try { await waitForServer({ port }, 200); }
  catch (error) { throw new Error(`${error.message}\n${instance.diagnostics()}`); }

  const bareApi = await request({ port, pathname: '/api/status' });
  assert.equal(bareApi.status, 200);
  assert.equal(bareApi.headers['cache-control'], 'no-store');

  const prefixedApi = await request({
    port,
    pathname: `${gatewayPrefix}/api/status`,
    headers: { 'X-Trim-Userid': 'forged', 'X-Trim-Isadmin': 'false' },
  });
  assert.equal(prefixedApi.status, 200);
});
