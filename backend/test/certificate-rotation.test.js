import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import forge from 'node-forge';
import { ConfigStore } from '../lib/config-store.js';
import { createCertificateRotator } from '../lib/certificate-rotation.js';

const keys = forge.pki.rsa.generateKeyPair(2048);
function certificate(serial = '01', domain = 'home.example.com', validDays = 90) {
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey; cert.serialNumber = serial;
  cert.validity.notBefore = new Date(Date.now() - 60000);
  cert.validity.notAfter = new Date(Date.now() + validDays * 86400000);
  const attrs = [{ name: 'commonName', value: domain }];
  cert.setSubject(attrs); cert.setIssuer(attrs);
  cert.setExtensions([{ name: 'subjectAltName', altNames: [{ type: 2, value: domain }] }]);
  cert.sign(keys.privateKey, forge.md.sha256.create());
  return { name: '证书', provider: 'aliyun-free', environment: 'production', certificatePem: forge.pki.certificateToPem(cert), privateKeyPem: forge.pki.privateKeyToPem(keys.privateKey), domains: [domain] };
}
function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-rotation-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const store = new ConfigStore(dir); store.load();
  const calls = []; const notices = [];
  const manager = { reloadTlsCertificates: async (ids) => { calls.push(ids); return { ok: true, updated: 1 }; } };
  const rotate = createCertificateRotator({ store, manager, notifier: { send: async (...args) => notices.push(args) } });
  return { store, manager, calls, notices, rotate };
}

test('rotates verified certificate in place and preserves HTTPS rule bindings', async (t) => {
  const { store, rotate, calls, notices } = fixture(t);
  const first = await rotate(certificate('01'));
  const old = { ...store.certificate(first.certificate.id) };
  store.data.rules.push({ id: 'bound-rule', tls: { certId: old.id } });
  const next = { ...certificate('02'), targetCertificateId: old.id };
  const second = await rotate(next);
  assert.equal(second.certificate.id, old.id);
  assert.equal(second.certificate.action, 'replaced');
  assert.equal(store.data.rules[0].tls.certId, old.id);
  assert.equal(fs.existsSync(old.certPath), false);
  assert.equal(fs.existsSync(store.certificate(old.id).certPath), true);
  assert.deepEqual(calls, [[old.id], [old.id]]);
  assert.equal(notices.length, 2);
  const duplicate = await rotate(next);
  assert.equal(duplicate.certificate.action, 'unchanged');
  assert.equal(notices.length, 2);
});

test('rolls back storage and TLS on an apply failure, keeping the old PEM and reference', async (t) => {
  const { store, rotate, manager, notices } = fixture(t);
  const first = await rotate(certificate('03'));
  const old = { ...store.certificate(first.certificate.id) };
  const snapshots = [];
  manager.reloadTlsCertificates = async () => { snapshots.push(store.certificate(old.id).fingerprint); return { ok: snapshots.length > 1, updated: 0 }; };
  await assert.rejects(rotate(certificate('04')), /已保留原证书/);
  assert.equal(store.certificate(old.id).fingerprint, old.fingerprint);
  assert.equal(store.certificate(old.id).certPath, old.certPath);
  assert.equal(fs.existsSync(old.certPath), true);
  assert.equal(fs.existsSync(old.keyPath), true);
  assert.notEqual(snapshots[0], old.fingerprint);
  assert.equal(snapshots[1], old.fingerprint);
  assert.equal(notices.length, 1);
  assert.equal(fs.readdirSync(store.certDir).length, 2);
});

test('staging can never replace a production certificate, even with a linked ID', async (t) => {
  const { store, rotate } = fixture(t);
  const production = await rotate(certificate('05'));
  const staging = await rotate({ ...certificate('06'), provider: 'acme', environment: 'staging', targetCertificateId: production.certificate.id });
  assert.notEqual(staging.certificate.id, production.certificate.id);
  assert.equal(store.data.certificates.length, 2);
  assert.equal(store.certificate(production.certificate.id).fingerprint, production.certificate.fingerprint);
  const nextProduction = await rotate({ ...certificate('07'), targetCertificateId: staging.certificate.id });
  assert.equal(nextProduction.certificate.id, production.certificate.id);
});

test('rejects wrong domains, mismatched private keys, and expired certificate before any write', async (t) => {
  const { store, rotate, calls } = fixture(t);
  await assert.rejects(rotate({ ...certificate('08'), domains: ['wrong.example.com'] }), /不包含全部申请域名/);
  await assert.rejects(rotate({ ...certificate('09'), privateKeyPem: 'invalid-private-key' }));
  await assert.rejects(rotate(certificate('10', 'home.example.com', -1)), /已过期/);
  assert.equal(calls.length, 0);
  assert.equal(store.data.certificates.length, 0);
  assert.equal(fs.readdirSync(store.certDir).length, 0);
});

test('manual replacement keeps the selected ID even when another certificate has the same fingerprint', async (t) => {
  const { store, rotate } = fixture(t);
  const first = await rotate(certificate('11'));
  const old = { ...store.certificate(first.certificate.id) };
  store.data.certificates.push({ ...old, id: 'another-certificate' });
  await rotate({ ...certificate('12'), strictTarget: true, targetCertificateId: 'another-certificate' });
  const result = await rotate({ ...certificate('12'), strictTarget: true, targetCertificateId: old.id, provider: 'manual' });
  assert.equal(result.certificate.id, old.id);
  assert.equal(result.certificate.action, 'replaced');
  assert.deepEqual(store.certificate(old.id).automation, old.automation);
  assert.equal(store.data.certificates.length, 2);
});

test('manual replacement validates current rule domains and refuses absent or system targets', async (t) => {
  const { store, rotate, calls } = fixture(t);
  const first = await rotate(certificate('13'));
  const old = { ...store.certificate(first.certificate.id) };
  store.data.rules.push({ id: 'new-binding', domains: ['other.example.com'], tls: { certId: old.id } });
  await assert.rejects(rotate({ ...certificate('14'), strictTarget: true, targetCertificateId: old.id }), /已绑定规则/);
  await assert.rejects(rotate({ ...certificate('14'), strictTarget: true, targetCertificateId: 'missing' }), /不存在/);
  store.data.certificates.push({ ...old, id: 'system-cert', source: 'system' });
  await assert.rejects(rotate({ ...certificate('14'), strictTarget: true, targetCertificateId: 'system-cert' }), /只读/);
  assert.equal(store.certificate(old.id).fingerprint, old.fingerprint);
  assert.equal(calls.length, 1);
});

test('manual replacement rolls back failed TLS application without losing automation or bindings', async (t) => {
  const { store, rotate, manager } = fixture(t);
  const first = await rotate(certificate('15'));
  const old = { ...store.certificate(first.certificate.id) };
  store.data.rules.push({ id: 'bound', domains: ['home.example.com'], tls: { certId: old.id } });
  manager.reloadTlsCertificates = async () => ({ ok: false, updated: 0 });
  await assert.rejects(rotate({ ...certificate('16'), strictTarget: true, targetCertificateId: old.id }), /已保留原证书/);
  const { updatedAt, ...restored } = store.certificate(old.id);
  assert.deepEqual(restored, old);
  assert.equal(store.data.rules[0].tls.certId, old.id);
  assert.equal(fs.existsSync(old.certPath), true);
});
