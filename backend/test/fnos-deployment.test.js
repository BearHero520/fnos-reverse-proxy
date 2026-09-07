import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import forge from 'node-forge';
import { X509Certificate } from 'node:crypto';
import tls from 'node:tls';
import { FnosDeploymentEngine, verifyFnosWebUser, inspectDeploymentCertificate, assertPublicTrust, probeTls } from '../lib/fnos-deployment-engine.js';
import { FnosDeploymentService } from '../lib/fnos-deployment.js';
import { ConfigStore } from '../lib/config-store.js';

const keys = forge.pki.rsa.generateKeyPair(2048);
function certificate(serial, { domain = 'nas.example.com', days = 60, ca = false } = {}) {
  const cert = forge.pki.createCertificate(); cert.publicKey = keys.publicKey; cert.serialNumber = serial;
  cert.validity.notBefore = new Date(Date.now() - 86400000); cert.validity.notAfter = new Date(Date.now() + days * 86400000);
  cert.setSubject([{ name: 'commonName', value: domain }]); cert.setIssuer([{ name: 'commonName', value: domain }]);
  cert.setExtensions([{ name: 'subjectAltName', altNames: [{ type: 2, value: domain }] }, { name: 'basicConstraints', cA: ca }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { certificatePem: forge.pki.certificateToPem(cert), privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}
const oldCert = certificate('01', { days: 30 }); const newCert = certificate('02');
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-deploy-test-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const certRoot = path.join(dir, 'system-certificates'); fs.mkdirSync(certRoot);
  const crt = path.join(certRoot, 'cert.crt'); const key = path.join(certRoot, 'private.key');
  fs.writeFileSync(crt, oldCert.certificatePem); fs.writeFileSync(key, oldCert.privateKeyPem);
  const leaf = new X509Certificate(oldCert.certificatePem);
  let row = { id: 12, domain: 'nas.example.com', san: 'nas.example.com', valid_from: Date.parse(leaf.validFrom), valid_to: Date.parse(leaf.validTo), source: 'upload', certificate: crt, private_key: key, encrypt_type: 'RSA', issued_by: 'nas.example.com', status: 'suc', updated_time: 1234 };
  const indexPath = path.join(dir, 'index.json'); const gatewayPath = path.join(dir, 'gateway.json');
  fs.writeFileSync(indexPath, JSON.stringify([{ certificate: crt, privateKey: key, validFrom: row.valid_from, validTo: row.valid_to, sum: 'preserve-this', futureField: [1, 2] }]));
  fs.writeFileSync(gatewayPath, JSON.stringify([{ cert: crt, key, host: 'nas.example.com' }]));
  const calls = [];
  const adapter = {
    keyPermissions: async () => ({ mode: 0o640, gid: 712 }),
    rows: async () => [structuredClone(row)],
    cas: async (before, after) => { assert.deepEqual(row, before); row = structuredClone(after); calls.push('cas'); },
    restart: async () => { calls.push('restart'); },
    probe: async (host, port, expected) => { calls.push('probe'); assert.equal(host, 'nas.example.com'); assert.equal(port, 5667); assert.equal(new X509Certificate(fs.readFileSync(crt)).fingerprint256, expected); },
  };
  const options = { adapter, certRoot, indexPath, gatewayPath, stateDir: path.join(dir, 'state'), secure: false };
  const engine = new FnosDeploymentEngine(options);
  const input = { targetId: '12', probeHost: 'nas.example.com', probePort: 5667, ...newCert };
  return { dir, crt, key, indexPath, gatewayPath, options, engine, input, adapter, calls, row: () => row, changeRow: (next) => { row = { ...row, ...next }; } };
}

test('fnOS read-only status and preflight redact paths and keys and never mutate', async (t) => {
  const { engine, input, calls, crt, key, row } = fixture(t);
  const status = await engine.status(); const preview = await engine.prepare(input);
  assert.equal(status.targets.length, 1); assert.equal(preview.target.id, '12');
  assert.deepEqual(calls, ['probe']); assert.equal(row().updated_time, 1234);
  const raw = JSON.stringify({ status, preview });
  for (const secret of [crt, key, 'BEGIN PRIVATE', 'BEGIN RSA', oldCert.privateKeyPem]) assert.equal(raw.includes(secret), false);
});

test('system certificate discovery verifies listening ports and reports excluded certificates safely', async (t) => {
  const { engine, adapter, crt, key, row, calls } = fixture(t);
  adapter.detectPorts = async () => [5000, 5001, 443];
  adapter.probe = async (host, port, fingerprint) => { assert.equal(host, 'nas.example.com'); assert.equal(fingerprint, new X509Certificate(oldCert.certificatePem).fingerprint256); if (port === 5000) throw new Error('not TLS'); };
  adapter.rows = async () => [row(), { ...row(), id: 13, source: 'system' }, { ...row(), id: 14, san: 'wrong.example.com' }];
  const status = await engine.status();
  assert.deepEqual(status.targets[0].verifiedPorts, [5001, 443]);
  assert.equal(status.targets[0].bound, true);
  assert.equal(status.targets[0].probeHost, 'nas.example.com');
  assert.equal(status.unavailableTargets.length, 2);
  assert.match(status.unavailableTargets[0].reason, /自带证书/);
  assert.match(status.unavailableTargets[1].reason, /不兼容/);
  assert.equal(JSON.stringify(status).includes(crt), false);
  assert.equal(JSON.stringify(status).includes(key), false);
  assert.deepEqual(calls, []);
});

test('replacement plans accept fnOS imported file modes and restrict newly written private keys', async (t) => {
  const { engine, input, key } = fixture(t);
  fs.chmodSync(key, 0o755);
  const plan = await engine.plan(input);
  assert.equal(plan.files.find((file) => file.file === key).nextMode, 0o640);
  const preview = await engine.prepare(input);
  await engine.deploy({ ...input, planId: preview.planId });
  if (process.platform !== 'win32') assert.equal(fs.statSync(key).mode & 0o777, 0o640);
});
test('fnOS deploy backs up, CAS-updates only selected metadata, replaces cert/key, and verifies HTTPS', async (t) => {
  const { engine, input, row, indexPath, gatewayPath, crt, options, calls } = fixture(t);
  const gateway = fs.readFileSync(gatewayPath);
  const preview = await engine.prepare(input);
  const result = await engine.deploy({ ...input, planId: preview.planId });
  assert.equal(result.ok, true); assert.equal(result.fingerprint, new X509Certificate(newCert.certificatePem).fingerprint256);
  assert.equal(new X509Certificate(fs.readFileSync(crt)).fingerprint256, result.fingerprint);
  assert.equal(row().id, 12); assert.equal(row().valid_to, Date.parse(new X509Certificate(newCert.certificatePem).validTo));
  assert.deepEqual(JSON.parse(fs.readFileSync(indexPath))[0].futureField, [1, 2]);
  assert.equal(JSON.parse(fs.readFileSync(indexPath))[0].sum, 'preserve-this');
  assert.deepEqual(fs.readFileSync(gatewayPath), gateway);
  assert.equal(fs.readdirSync(options.stateDir).filter((name) => name.startsWith('backup-')).length, 1);
  assert.equal(fs.existsSync(path.join(options.stateDir, 'active.json')), false);
  assert.deepEqual(calls, ['probe', 'probe', 'cas', 'restart', 'probe']);
});
test('fnOS refuses built-in certs, wrong domains, expired source, and stale plan without writes', async (t) => {
  const f = fixture(t);
  f.changeRow({ source: 'system' }); await assert.rejects(f.engine.prepare(f.input), { code: 'PROTECTED' });
  f.changeRow({ source: 'upload' });
  await assert.rejects(f.engine.prepare({ ...f.input, ...certificate('03', { domain: 'else.example.com' }) }), { code: 'DOMAIN' });
  await assert.rejects(f.engine.prepare({ ...f.input, ...certificate('04', { days: -0.5 }) }), { code: 'INVALID' });
  const preview = await f.engine.prepare(f.input); f.changeRow({ updated_time: 999 });
  await assert.rejects(f.engine.deploy({ ...f.input, planId: preview.planId }), { code: 'CONFLICT' });
  assert.equal(f.calls.includes('cas'), false); assert.equal(f.calls.includes('restart'), false);
  assert.equal(fs.readFileSync(f.crt, 'utf8'), oldCert.certificatePem);
});
test('fnOS refuses unbound HTTPS endpoints and mismatched fingerprint before mutation', async (t) => {
  const f = fixture(t);
  await assert.rejects(f.engine.prepare({ ...f.input, expectedFingerprint: 'changed' }), { code: 'CONFLICT' });
  fs.writeFileSync(f.gatewayPath, '[]');
  await assert.rejects(f.engine.prepare(f.input), { code: 'INCOMPATIBLE' });
  assert.deepEqual(f.calls, []);
});
test('fnOS TLS failure restores original files/index/database and verifies the old certificate', async (t) => {
  const f = fixture(t); const oldRow = structuredClone(f.row()); const index = fs.readFileSync(f.indexPath);
  const originalProbe = f.adapter.probe;
  f.adapter.probe = async (...args) => { if (args[2] === new X509Certificate(newCert.certificatePem).fingerprint256) throw new Error('TLS failed'); await originalProbe(...args); };
  const preview = await f.engine.prepare(f.input);
  await assert.rejects(f.engine.deploy({ ...f.input, planId: preview.planId }), { code: 'ROLLED_BACK', stage: 'verify' });
  const journal = JSON.parse(fs.readFileSync(path.join(f.options.stateDir, fs.readdirSync(f.options.stateDir).find((name) => name.startsWith('rolled-back-')))));
  assert.equal(journal.failure.stage, 'verify');
  assert.equal(JSON.stringify(journal.failure).includes('TLS failed'), false);
  assert.equal(fs.readFileSync(f.crt, 'utf8'), oldCert.certificatePem); assert.deepEqual(f.row(), oldRow);
  assert.deepEqual(fs.readFileSync(f.indexPath), index); assert.equal(f.engine.recoveryFailed, false);
});

test('preflight rejects unverified web-group permissions without changing certificates', async (t) => {
  const f = fixture(t);
  f.adapter.keyPermissions = async () => ({ mode: 0o644, gid: 712 });
  await assert.rejects(f.engine.prepare(f.input), { code: 'INCOMPATIBLE' });
  f.adapter.keyPermissions = async () => ({ mode: 0o640, gid: 0 });
  await assert.rejects(f.engine.prepare(f.input), { code: 'INCOMPATIBLE' });
  assert.equal(fs.readFileSync(f.crt, 'utf8'), oldCert.certificatePem);
  assert.equal(f.calls.includes('cas'), false);
});
test('fnOS stops rollback on an external edit, retaining a durable journal and disabling writes', async (t) => {
  const f = fixture(t); const originalRestart = f.adapter.restart;
  f.adapter.restart = async () => { fs.writeFileSync(f.indexPath, '[{"external":true}]'); throw new Error('concurrent change'); };
  const preview = await f.engine.prepare(f.input);
  await assert.rejects(f.engine.deploy({ ...f.input, planId: preview.planId }), { code: 'RECOVERY' });
  assert.equal(fs.readFileSync(f.indexPath, 'utf8'), '[{"external":true}]');
  assert.equal(fs.existsSync(path.join(f.options.stateDir, 'active.json')), true);
  f.adapter.restart = originalRestart;
  await assert.rejects(f.engine.prepare(f.input), { code: 'RECOVERY' });
});
test('fnOS recovers an interrupted deployment on helper restart', async (t) => {
  const f = fixture(t); const originalRestart = f.adapter.restart;
  f.adapter.restart = async () => { throw new Error('service unavailable'); };
  const preview = await f.engine.prepare(f.input);
  await assert.rejects(f.engine.deploy({ ...f.input, planId: preview.planId }), { code: 'RECOVERY' });
  f.adapter.restart = originalRestart;
  const restarted = new FnosDeploymentEngine(f.options); await restarted.recover();
  assert.equal(restarted.recoveryFailed, false); assert.equal(fs.existsSync(path.join(f.options.stateDir, 'active.json')), false);
  assert.equal(fs.readFileSync(f.crt, 'utf8'), oldCert.certificatePem); assert.equal(f.row().updated_time, 1234);
});
test('fnOS rejects traversal, out-of-root target files, duplicate index entries, and hard links', async (t) => {
  const f = fixture(t);
  await assert.rejects(f.engine.prepare({ ...f.input, targetId: '../../etc' }), { code: 'INVALID' });
  await assert.rejects(f.engine.prepare({ ...f.input, probeHost: 'localhost;id' }), { code: 'INVALID' });
  const outside = path.join(f.dir, 'outside.crt'); fs.copyFileSync(f.crt, outside); f.changeRow({ certificate: outside });
  await assert.rejects(f.engine.prepare(f.input), { code: 'INCOMPATIBLE' });
  f.changeRow({ certificate: f.crt }); fs.linkSync(f.crt, path.join(f.dir, 'hardlink.crt'));
  await assert.rejects(f.engine.prepare(f.input), { code: 'INCOMPATIBLE' });
  fs.unlinkSync(path.join(f.dir, 'hardlink.crt'));
  const entries = JSON.parse(fs.readFileSync(f.indexPath)); fs.writeFileSync(f.indexPath, JSON.stringify([...entries, ...entries]));
  await assert.rejects(f.engine.prepare(f.input), { code: 'INCOMPATIBLE' });
});
test('certificate deployment rejects CA certificates and trailing content', () => {
  assert.throws(() => inspectDeploymentCertificate(certificate('09', { ca: true }).certificatePem, oldCert.privateKeyPem), { code: 'INVALID' });
  assert.throws(() => inspectDeploymentCertificate(`${newCert.certificatePem}unexpected`, newCert.privateKeyPem), { code: 'INVALID' });
  assert.throws(() => inspectDeploymentCertificate(newCert.certificatePem, 'not a key'), { code: 'INVALID' });
});
test('production trust check rejects self-signed or staging roots before writing', () => {
  assert.throws(() => assertPublicTrust(inspectDeploymentCertificate(newCert.certificatePem, newCert.privateKeyPem)), { code: 'UNTRUSTED' });
});
test('real local TLS probe pins the selected cert and validates trust for new deployments', async (t) => {
  const server = tls.createServer({ cert: oldCert.certificatePem, key: oldCert.privateKeyPem }, (socket) => socket.end());
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const port = server.address().port; const fingerprint = new X509Certificate(oldCert.certificatePem).fingerprint256;
  await probeTls('nas.example.com', port, fingerprint);
  await assert.rejects(probeTls('nas.example.com', port, 'wrong'), { code: 'TLS' });
  await assert.rejects(probeTls('nas.example.com', port, fingerprint, true), { code: 'TLS' });
});
test('fnOS tolerates formatting-only index rewrites, not changed certificate metadata', async (t) => {
  const f = fixture(t);
  f.adapter.restart = async () => { fs.writeFileSync(f.indexPath, JSON.stringify(JSON.parse(fs.readFileSync(f.indexPath)), null, 2)); fs.writeFileSync(f.gatewayPath, JSON.stringify(JSON.parse(fs.readFileSync(f.gatewayPath)), null, 2)); };
  const preview = await f.engine.prepare(f.input);
  assert.equal((await f.engine.deploy({ ...f.input, planId: preview.planId })).ok, true);
});
test('fnOS refuses shared certificate paths or an unrelated neighboring full chain', async (t) => {
  const f = fixture(t);
  f.adapter.rows = async () => [f.row(), { ...f.row(), id: 99 }];
  await assert.rejects(f.engine.prepare(f.input), { code: 'INCOMPATIBLE' });
  f.adapter.rows = async () => [f.row()];
  fs.writeFileSync(path.join(f.options.certRoot, 'fullchain.crt'), newCert.certificatePem);
  await assert.rejects(f.engine.prepare(f.input), { code: 'INCOMPATIBLE' });
  assert.equal(f.calls.includes('cas'), false);
});

function serviceFixture(t) {
  const f = fixture(t); const store = new ConfigStore(path.join(f.dir, 'app-data')); store.load();
  const certPath = path.join(store.certDir, 'local.crt'); const keyPath = path.join(store.certDir, 'local.key');
  fs.writeFileSync(certPath, newCert.certificatePem); fs.writeFileSync(keyPath, newCert.privateKeyPem);
  store.data.certificates.push({ id: 'local-cert', name: 'Local', certPath, keyPath, fingerprint: new X509Certificate(newCert.certificatePem).fingerprint256, automation: { environment: 'production' } }); store.save();
  const service = new FnosDeploymentService({ store, client: { status: () => f.engine.status(), prepare: (input) => f.engine.prepare(input), deploy: (input) => f.engine.deploy(input) } });
  const binding = { certificateId: 'local-cert', targetId: '12', probeHost: 'nas.example.com', probePort: 5667 };
  return { ...f, store, service, binding, certPath };
}
test('deployment service requires saved binding, expiring preflight and explicit confirmation before writes', async (t) => {
  const f = serviceFixture(t); f.service.update(f.binding);
  assert.throws(() => f.service.update({ autoDeploy: true }), /手动部署/);
  const preview = await f.service.prepare();
  assert.throws(() => f.service.kick({ token: preview.token }), { code: 'CONFLICT' });
  assert.equal(f.calls.includes('cas'), false);
  f.service.kick({ token: preview.token, confirmed: true }); await f.service.running;
  assert.equal(f.service.config().lastResult, 'verified'); assert.equal(f.service.config().autoDeploy, false);
  f.service.update({ autoDeploy: true }); assert.equal(f.service.config().autoDeploy, true);
  assert.throws(() => f.service.kick({ token: preview.token, confirmed: true }), { code: 'CONFLICT' });
});
test('automatic deployment follows the certificate ID only after a verified manual deploy', async (t) => {
  const f = serviceFixture(t); f.service.update(f.binding);
  const preview = await f.service.prepare(); f.service.kick({ token: preview.token, confirmed: true }); await f.service.running;
  f.service.update({ autoDeploy: true }); const previousCalls = f.calls.length;
  await f.service.tick(); assert.equal(f.calls.length, previousCalls);
  const renewed = certificate('11', { days: 120 }); fs.writeFileSync(f.certPath, renewed.certificatePem);
  await f.service.tick(); assert.equal(f.service.config().lastFingerprint, new X509Certificate(renewed.certificatePem).fingerprint256);
  assert.equal(f.service.config().autoDeploy, true);
  f.service.update({ probePort: 443 }); assert.equal(f.service.config().autoDeploy, false); assert.equal(f.service.config().lastSuccessAt, null);
});
test('external target changes pause automatic deployment without being overwritten', async (t) => {
  const f = serviceFixture(t); f.service.update(f.binding);
  const preview = await f.service.prepare(); f.service.kick({ token: preview.token, confirmed: true }); await f.service.running;
  f.service.update({ autoDeploy: true });
  fs.writeFileSync(f.certPath, certificate('12').certificatePem);
  fs.writeFileSync(f.crt, certificate('13').certificatePem);
  await f.service.tick(); assert.equal(f.service.config().autoDeploy, false); assert.ok(f.service.config().lastError);
  assert.equal(new X509Certificate(fs.readFileSync(f.crt)).serialNumber, '13');
});
test('deployment settings cannot forge success, enable auto on rebind, or export internal binding', (t) => {
  const f = serviceFixture(t);
  f.service.update({ ...f.binding, autoDeploy: true, lastSuccessAt: 'fake', expectedFingerprint: 'fake' });
  assert.equal(f.service.config().autoDeploy, false); assert.equal(f.service.config().lastSuccessAt, null);
  assert.equal(f.service.config().expectedFingerprint, '');
  assert.equal(JSON.stringify(f.store.exportConfig()).includes('fnosDeployment'), false);
  f.store.data.certificates[0].automation.environment = 'staging';
  assert.throws(() => f.service.source('local-cert'), /测试环境/);
});
test('deployment demo and missing helper never report successful deployment', async (t) => {
  const f = serviceFixture(t);
  const demo = new FnosDeploymentService({ store: f.store, demoMode: true, client: { status: () => assert.fail('no helper call') } });
  assert.equal((await demo.refresh()).helper.available, false); await assert.rejects(demo.prepare(), /演示/);
  const unavailable = new FnosDeploymentService({ store: f.store, client: { status: async () => { throw new Error('/secret/path/key.pem'); } } });
  const result = await unavailable.refresh(); assert.equal(result.helper.available, false); assert.equal(JSON.stringify(result).includes('/secret'), false);
});

test('reads the configured fnOS web identity without accepting commented, duplicate or other users', () => {
  assert.doesNotThrow(() => verifyFnosWebUser('user www-data;\nworker_processes auto;'));
  assert.doesNotThrow(() => verifyFnosWebUser('user www-data www-data;'));
  for (const config of ['# user www-data;', 'user root;', 'user www-data root;', 'user www-data;\nuser root;']) assert.throws(() => verifyFnosWebUser(config), { code: 'INCOMPATIBLE' });
});
