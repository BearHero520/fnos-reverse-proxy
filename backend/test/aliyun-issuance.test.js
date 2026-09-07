import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ConfigStore } from '../lib/config-store.js';
import { CertificateIssuance } from '../lib/certificate-issuance.js';
import { AliyunClient, safeCloudError, validationRecord } from '../lib/aliyun-client.js';
import { FREE_PRODUCT_CODE } from '../lib/automation-config.js';

function fixture(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-aliyun-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const store = new ConfigStore(dir); store.load();
  store.updateIssuance({ provider: 'aliyun-free', aliyun: { apiVersion: 'v1', accessKeyId: 'ram-id', accessKeySecret: 'ram-secret', domain: 'home.example.com', dnsZone: 'example.com', autoRenew: true } });
  const calls = [];
  const client = {
    quota: async () => { calls.push('quota'); return { total: 5, used: 1, issued: 1, remaining: 4 }; },
    checkZone: async () => { calls.push('zone'); },
    create: async (config, csr) => { calls.push('create'); assert.equal(config.domain, 'home.example.com'); assert.equal(csr, 'csr'); return '12345'; },
    describe: async () => { calls.push('describe'); return { type: 'domain_verify', validateType: 'DNS', recordType: 'TXT', recordDomain: '_dnsauth.home', recordValue: 'proof' }; },
    ensureRecord: async () => { calls.push('dns'); return { id: 'record-1', owned: true, name: '_dnsauth.home.example.com', type: 'TXT', value: 'proof' }; },
    removeRecord: async (record) => { calls.push(`remove:${record.id}`); },
  };
  const options = { store, aliyunFactory: () => client, acmeLib: { crypto: { createCsr: async () => [Buffer.from('private-key'), Buffer.from('csr')] } }, onCertificate: async (candidate) => { calls.push('rotate'); assert.equal(candidate.privateKeyPem, 'private-key'); return { certificate: { id: 'cert-linked' } }; } };
  return { dir, store, calls, client, options, service: new CertificateIssuance(options) };
}

test('migrates combined settings once and isolates future DDNS / issuance writes', (t) => {
  const { dir, store } = fixture(t);
  store.data.integrations = { domainAutomation: { zoneId: '023e105f4ecef8ad9ca31a8372d0c353', apiToken: 'old-secret', ddns: { enabled: true, recordName: 'home.example.com', lastIp: '1.2.3.4' }, acme: { autoRenew: true, email: 'me@example.com', domains: ['example.com'], certificateId: 'old-cert', accountKeyPem: 'old-key' } } };
  store.save();
  const reloaded = new ConfigStore(dir); reloaded.load();
  assert.equal(reloaded.ddnsStatus().lastIp, '1.2.3.4');
  assert.equal(reloaded.issuanceConfig().acme.certificateId, 'old-cert');
  assert.equal(reloaded.issuanceConfig().provider, 'acme');
  assert.equal(reloaded.data.integrations.domainAutomation, undefined);
  reloaded.updateDdns({ apiToken: 'new-ddns-secret' });
  assert.equal(reloaded.issuanceConfig().acme.apiToken, 'old-secret');
  reloaded.updateIssuance({ acme: { apiToken: 'new-acme-secret' } });
  assert.equal(reloaded.ddnsConfig().apiToken, 'new-ddns-secret');
});

test('ignores forged runtime fields and excludes every private key from status/export', (t) => {
  const { store } = fixture(t);
  store.patchIssuance('aliyun', { order: { domain: 'home.example.com', id: '1', privateKeyPem: 'private-key', csr: 'csr', dnsRecords: [{ value: 'proof' }] } });
  store.updateIssuance({ aliyun: { accessKeySecret: '', certificateId: 'forged', order: null, quota: { remaining: 999 } } });
  assert.equal(store.issuanceConfig().aliyun.accessKeySecret, 'ram-secret');
  assert.equal(store.issuanceConfig().aliyun.order.id, '1');
  assert.equal(store.issuanceConfig().aliyun.certificateId, null);
  assert.equal(store.issuanceConfig().aliyun.quota, null);
  const publicData = JSON.stringify([store.issuanceStatus(), store.exportConfig()]);
  for (const secret of ['private-key', 'ram-secret', 'proof', '"csr"']) assert.equal(publicData.includes(secret), false);
  assert.throws(() => store.updateIssuance({ aliyun: { domain: '*.example.com' } }), /单个普通域名/);
  assert.throws(() => store.updateIssuance({ aliyun: { domain: 'other.example.com' } }), /订单尚未结束/);
});

test('stops at exhausted free quota, without creating an order or changing the old certificate', async (t) => {
  const { client, service, store, calls } = fixture(t);
  store.patchIssuance('aliyun', { certificateId: 'old-cert' });
  client.quota = async () => ({ total: 0, used: 0, issued: 0, remaining: 0 });
  await assert.rejects(service.issue(), /没有可用于自动申请的免费资源包/);
  assert.equal(calls.includes('create'), false);
  assert.equal(store.issuanceConfig().aliyun.certificateId, 'old-cert');
  assert.equal(store.issuanceStatus().aliyun.order, null);
});

test('persists order and private key, resumes across restart, then rotates and cleans owned records', async (t) => {
  const { service, store, calls, client, options, dir } = fixture(t);
  await Promise.all([service.issue(), service.issue()]);
  assert.equal(calls.filter((action) => action === 'create').length, 1);
  assert.equal(store.issuanceStatus().aliyun.phase, 'domain_verify');
  const restoredStore = new ConfigStore(dir); restoredStore.load();
  const restored = new CertificateIssuance({ ...options, store: restoredStore });
  client.describe = async () => ({ type: 'certificate', certificate: 'issued-cert', privateKey: 'never-use-cloud-key' });
  const result = await restored.issue();
  assert.equal(result.certificate.id, 'cert-linked');
  assert.equal(calls.filter((action) => action === 'create').length, 1);
  assert.equal(restoredStore.issuanceStatus().aliyun.certificateId, 'cert-linked');
  assert.equal(restoredStore.issuanceStatus().aliyun.order, null);
  assert.equal(calls.at(-1), 'remove:record-1');
});

test('uncertain submission is never automatically duplicated and can be associated with its cloud order', async (t) => {
  const { service, client, calls, store } = fixture(t);
  client.create = async () => { calls.push('create'); throw new Error('network timeout'); };
  await assert.rejects(service.issue(), /network timeout/);
  assert.equal(store.issuanceStatus().aliyun.order.phase, 'uncertain');
  await assert.rejects(service.issue(), /不会自动重复申请/);
  await service.tick();
  assert.equal(calls.filter((action) => action === 'create').length, 1);
  service.associateOrder('45678');
  await service.issue();
  assert.equal(store.issuanceStatus().aliyun.order.id, '45678');
  assert.equal(store.issuanceStatus().aliyun.phase, 'domain_verify');
});

test('keeps an issued order for rotation retry and avoids consuming new quota on an apply failure', async (t) => {
  const { service, store, client, options, calls } = fixture(t);
  await service.issue();
  store.patchIssuance('aliyun', { certificateId: 'old-cert' });
  client.describe = async () => ({ type: 'certificate', certificate: 'issued-cert' });
  const failed = new CertificateIssuance({ ...options, onCertificate: async () => { throw new Error('TLS failed'); } });
  await assert.rejects(failed.issue(), /TLS failed/);
  assert.equal(store.issuanceConfig().aliyun.order.id, '12345');
  assert.equal(store.issuanceConfig().aliyun.order.privateKeyPem, 'private-key');
  assert.equal(store.issuanceConfig().aliyun.certificateId, 'old-cert');
  await service.issue();
  assert.equal(calls.filter((action) => action === 'create').length, 1);
});

test('resetting uncertain creation requires explicit reconciliation and pauses automatic new applications', async (t) => {
  const { service, client, store } = fixture(t);
  client.create = async () => { throw new Error('request outcome unknown'); };
  await assert.rejects(service.issue());
  assert.throws(() => service.resetUncertain(false), /确认/);
  service.resetUncertain(true);
  assert.equal(store.issuanceStatus().aliyun.order, null);
  assert.equal(store.issuanceStatus().aliyun.autoRenew, false);
});

test('cleanup retries do not repeat certificate application or new orders', async (t) => {
  const { service, client, store, calls } = fixture(t);
  await service.issue();
  client.describe = async () => ({ type: 'certificate', certificate: 'cert' });
  client.removeRecord = async () => { throw new Error('DNS temporarily unavailable'); };
  await assert.rejects(service.issue(), /DNS temporarily/);
  assert.equal(store.issuanceConfig().aliyun.order.phase, 'cleanup');
  assert.equal(store.issuanceConfig().aliyun.order.privateKeyPem, '');
  client.removeRecord = async () => {};
  await service.issue();
  assert.equal(store.issuanceConfig().aliyun.order, null);
  assert.equal(calls.filter((call) => call === 'rotate').length, 1);
  assert.equal(calls.filter((call) => call === 'create').length, 1);
});

test('scheduler renews inside the expiry window only and does not auto-resubmit rejected orders', async (t) => {
  const { service, store, client, calls } = fixture(t);
  store.addCertificate({ id: 'existing', validTo: new Date(Date.now() + 45 * 86400000).toISOString() });
  store.patchIssuance('aliyun', { certificateId: 'existing' });
  await service.tick();
  assert.equal(calls.length, 0);
  store.data.certificates[0].validTo = new Date(Date.now() + 10 * 86400000).toISOString();
  await service.tick();
  assert.equal(calls.filter((action) => action === 'create').length, 1);
  client.describe = async () => ({ type: 'verify_fail' });
  await service.issue();
  store.patchIssuance('aliyun', { lastRunAt: null });
  await service.tick();
  assert.equal(calls.filter((action) => action === 'create').length, 1);
  await service.retryFailed();
  assert.equal(calls.filter((action) => action === 'create').length, 2);
});

test('demo mode never calls cloud APIs or marks real issuance success', async (t) => {
  const { options, calls, store } = fixture(t);
  const demo = new CertificateIssuance({ ...options, demoMode: true });
  await demo.issue(); await demo.tick(); await demo.refreshQuota();
  assert.equal(calls.length, 0);
  assert.equal(store.issuanceStatus().aliyun.lastSuccessAt, null);
  assert.equal(store.issuanceStatus().aliyun.quota, null);
});

test('failed historical submissions do not exhaust unissued free quota', async () => {
  const client = new AliyunClient({}, { dnsClient: {}, casClient: {
    describePackageStateWithOptions: async () => ({ body: { totalCount: 20, usedCount: 25, issuedCount: 1 } }),
  } });
  const quota = await client.quota();
  assert.equal(quota.remaining, 19);
  assert.equal(quota.estimated, true);
  assert.equal(quota.scope, 'legacy-package');
});

test('credential changes invalidate quota and cannot reuse another accounts secret', (t) => {
  const { store } = fixture(t);
  store.patchIssuance('aliyun', { quota: { remaining: 5 }, lastError: 'old error' });
  assert.throws(() => store.updateIssuance({ aliyun: { accessKeyId: 'other' } }), /新 Secret/);
  store.updateIssuance({ aliyun: { accessKeyId: 'other', accessKeySecret: 'new-secret' } });
  assert.equal(store.issuanceStatus().aliyun.quota, null);
  assert.equal(store.issuanceStatus().aliyun.lastError, null);
});

test('official SDK requests hardcode the free product and disable retries', async () => {
  const requests = [];
  const casClient = {
    describePackageStateWithOptions: async (req, opts) => { requests.push({ req, opts }); return { body: { productCode: FREE_PRODUCT_CODE, totalCount: 20, usedCount: 2, issuedCount: 1 } }; },
    createCertificateForPackageRequestWithOptions: async (req, opts) => { requests.push({ req, opts }); return { body: { orderId: 12345 } }; },
  };
  const client = new AliyunClient({}, { casClient, dnsClient: {} });
  assert.equal((await client.quota()).remaining, 19);
  assert.equal(await client.create({ domain: 'home.example.com' }, 'csr'), '12345');
  for (const { req, opts } of requests) { assert.equal(req.productCode, 'digicert-free-1-free'); assert.equal(opts.autoretry, false); assert.equal(opts.maxAttempts, 1); }
  assert.equal(requests[1].req.csr, 'csr'); assert.equal(requests[1].req.validateType, 'DNS');
  assert.equal(safeCloudError({ code: 'Forbidden', message: 'ram-secret', data: { RequestId: 'req-1', privateKey: 'private-key' } }).includes('ram-secret'), false);
});

test('AliDNS handles relative/full record names, refuses collisions, and only deletes unchanged owned records', async () => {
  assert.deepEqual(validationRecord('_dnsauth.home', 'example.com'), { name: '_dnsauth.home.example.com', rr: '_dnsauth.home' });
  assert.deepEqual(validationRecord('_dnsauth.home.example.com.', 'example.com'), { name: '_dnsauth.home.example.com', rr: '_dnsauth.home' });
  assert.throws(() => validationRecord('@', 'example.com'), /无效/);
  const actions = [];
  let records = [];
  const dnsClient = {
    describeSubDomainRecordsWithOptions: async () => ({ body: { totalCount: records.length, domainRecords: { record: records } } }),
    addDomainRecordWithOptions: async (req) => { actions.push(req); return { body: { recordId: 'our-id' } }; },
    deleteDomainRecordWithOptions: async (req) => { actions.push(req); return { body: {} }; },
  };
  const client = new AliyunClient({}, { casClient: {}, dnsClient });
  const state = { validateType: 'DNS', recordDomain: '_dnsauth.home', recordType: 'TXT', recordValue: 'proof' };
  const added = await client.ensureRecord('example.com', state);
  assert.equal(added.owned, true); assert.equal(actions[0].RR, '_dnsauth.home'); assert.equal(actions[0].TTL, 600);
  records = [{ recordId: 'external', type: 'TXT', value: 'proof' }];
  const reused = await client.ensureRecord('example.com', state);
  assert.equal(reused.owned, false); await client.removeRecord(reused); assert.equal(actions.length, 1);
  records = [{ recordId: 'conflict', type: 'CNAME', value: 'target.example.com' }];
  await assert.rejects(client.ensureRecord('example.com', state), /不会覆盖/);
  records = [{ recordId: 'our-id', type: 'TXT', value: 'user-edited' }];
  await client.removeRecord(added); assert.equal(actions.length, 1);
  records[0].value = 'proof'; await client.removeRecord(added); assert.equal(actions.length, 2);
});
