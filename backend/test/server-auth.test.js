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

async function startServer({ socketPath = '', port = '', demoMode = false }) {
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
      DEMO_MODE: demoMode ? '1' : '0',
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

  for (const route of ['ddns', 'certificate-issuance', 'fnos-deployment']) {
    const anonymous = await request({ socketPath, pathname: `${gatewayPrefix}/api/integrations/${route}` });
    assert.equal(anonymous.status, 401);
    const allowed = await request({ socketPath, pathname: `${gatewayPrefix}/api/integrations/${route}`, headers: { 'X-Trim-Userid': '1000', 'X-Trim-Isadmin': 'true' } });
    assert.equal(allowed.status, 200);
    assert.equal(allowed.headers['cache-control'], 'no-store');
  }
  for (const action of ['test', 'sync', 'detect']) {
    const denied = await request({ socketPath, pathname: `${gatewayPrefix}/api/integrations/ddns/${action}`, method: 'POST' });
    assert.equal(denied.status, 401);
  }
  for (const scope of ['ddns', 'certificate-issuance']) {
    const pathname = `${gatewayPrefix}/api/integrations/${scope}/aliyun/resolve-zone`;
    assert.equal((await request({ socketPath, pathname, method: 'POST' })).status, 401);
    assert.equal((await request({ socketPath, pathname, method: 'POST', headers: { 'X-Trim-Userid': '1000', 'X-Trim-Isadmin': 'false' } })).status, 403);
  }
  for (const action of ['refresh', 'prepare', 'deploy']) {
    assert.equal((await request({ socketPath, pathname: `${gatewayPrefix}/api/integrations/fnos-deployment/${action}`, method: 'POST' })).status, 401);
    assert.equal((await request({ socketPath, pathname: `${gatewayPrefix}/api/integrations/fnos-deployment/${action}`, method: 'POST', headers: { 'X-Trim-Userid': '1000', 'X-Trim-Isadmin': 'false' } })).status, 403);
  }
  assert.equal((await request({ socketPath, pathname: `${gatewayPrefix}/api/integrations/fnos-deployment`, method: 'PUT' })).status, 401);

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

test('separate integration APIs persist independently and demo issuance never claims a real certificate', { timeout: 20_000 }, async (t) => {
  const port = await freeTcpPort();
  const instance = await startServer({ port, demoMode: true });
  t.after(() => stopServer(instance));
  await waitForServer({ port }, 200);
  const send = async (route, method = 'GET', body = {}) => request({ port, pathname: `${gatewayPrefix}/api/integrations/${route}`, method, headers: { 'Content-Type': 'application/json' }, body: method === 'GET' ? '' : JSON.stringify(body) });
  const missing = await send('certificate-issuance/issue', 'POST');
  assert.equal(missing.status, 400);
  const configured = await send('certificate-issuance', 'PUT', { provider: 'aliyun-free', aliyun: { accessKeyId: 'test-only-id', accessKeySecret: 'test-only-secret', domain: 'home.example.com', dnsZone: 'example.com' } });
  assert.equal(configured.status, 200);
  assert.equal(configured.body.includes('test-only-secret'), false);
  const ddns = await send('ddns', 'PUT', { recordName: 'other.example.com' });
  assert.equal(ddns.status, 200);
  const issuance = JSON.parse((await send('certificate-issuance')).body).integration;
  assert.equal(issuance.aliyun.domain, 'home.example.com');
  const accepted = await send('certificate-issuance/issue', 'POST');
  assert.equal(accepted.status, 202);
  assert.equal(JSON.parse(accepted.body).result.demoMode, true);
  assert.equal(JSON.parse(accepted.body).integration.aliyun.lastSuccessAt, null);
  assert.equal(JSON.parse(accepted.body).integration.aliyun.certificateId, null);
  assert.equal((await send('domain-automation')).status, 404);
  for (const [provider, config] of [
    ['aliyun', { accessKeyId: 'ddns-only-id', accessKeySecret: 'ddns-only-secret', dnsZone: 'example.com' }],
    ['dnspod', { secretId: 'dnspod-only-id', secretKey: 'dnspod-only-secret', dnsZone: 'example.com' }],
  ]) {
    const saved = await send('ddns', 'PUT', { provider, [provider]: config, enabled: true });
    assert.equal(saved.status, 200);
    assert.equal(JSON.parse(saved.body).integration.provider, provider);
    assert.equal(saved.body.includes('ddns-only-secret'), false);
    assert.equal(saved.body.includes('dnspod-only-secret'), false);
    for (const action of ['test', 'sync']) {
      const checked = await send(`ddns/${action}`, 'POST');
      assert.equal(checked.status, 200);
      assert.equal(JSON.parse(checked.body).result.demoMode, true);
      assert.equal(JSON.parse(checked.body).integration.lastSuccessAt, null);
    }
  }
  assert.equal(JSON.parse((await send('certificate-issuance')).body).integration.aliyun.accessKeyId, 'test-only-id');
  for (const scope of ['ddns', 'certificate-issuance']) {
    const beforeLookup = (await send(scope)).body;
    const lookup = await send(`${scope}/aliyun/resolve-zone`, 'POST', { domain: 'home.example.com', accessKeyId: 'unsaved-draft-id', accessKeySecret: 'unsaved-draft-secret' });
    assert.equal(lookup.status, 200); assert.equal(lookup.headers['cache-control'], 'no-store');
    assert.equal(JSON.parse(lookup.body).result.demoMode, true); assert.equal(JSON.parse(lookup.body).result.dnsZone, null);
    assert.equal(lookup.body.includes('unsaved-draft-secret'), false);
    assert.equal((await send(scope)).body, beforeLookup, '识别不得隐式保存草稿、密钥或修改运行状态');
    assert.equal((await send(`${scope}/aliyun/resolve-zone`, 'POST', { domain: 'bad' })).status, 400);
    assert.equal((await send(`${scope}/aliyun/resolve-zone`, 'POST', { domain: 'home.example.com', accessKeyId: 'new-id' })).status, 400);
  }
  assert.equal((await send('ddns', 'PUT', { provider: 'unrecognized' })).status, 400);
  const detected = await send('ddns/detect', 'POST', { recordType: 'A' });
  assert.equal(detected.status, 200); assert.equal(JSON.parse(detected.body).result.demoMode, true); assert.equal(JSON.parse(detected.body).result.ip, undefined);
  assert.equal((await send('ddns/detect', 'POST', { recordType: 'invalid' })).status, 400);
  const deployment = await send('fnos-deployment/refresh', 'POST');
  assert.equal(JSON.parse(deployment.body).integration.helper.available, false);
  assert.equal((await send('fnos-deployment/prepare', 'POST')).status, 400);
  assert.equal((await send('fnos-deployment/deploy', 'POST', { confirmed: true, token: 'forged' })).status, 409);
});
