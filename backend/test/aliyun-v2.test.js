import assert from 'node:assert/strict';
import test from 'node:test';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { ConfigStore } from '../lib/config-store.js';
import { CertificateIssuance } from '../lib/certificate-issuance.js';
import { AliyunV2Client, isFreeInstance } from '../lib/aliyun-v2.js';
import { validationRecord } from '../lib/aliyun-client.js';

function unused(id = 'cas_dv-cn-free1') {
  return { instanceId: id, instanceType: 'TEST', certificateType: 'DV', spec: 'ss.dv.t', fullDomainCount: 1,
    wildcardDomainCount: 0, status: 'inactive', orderStartTime: Date.now(), orderEndTime: Date.now() + 90 * 86400000 };
}
function setup(t) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'aliyun-v2-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const store = new ConfigStore(dir); store.load();
  store.updateIssuance({ aliyun: { apiVersion: 'v2', accessKeyId: 'id', accessKeySecret: 'secret', domain: 'home.example.com', dnsZone: 'example.com', autoRenew: true } });
  const remote = { detail: unused(), task: 'success', dns: [] }; const calls = [];
  const casClient = {};
  const handlers = {
    ListInstances: async () => ({ totalCount: 1, instanceList: [remote.detail] }),
    GetInstanceDetail: async () => ({ ...remote.detail }),
    ListContact: async () => ({ totalCount: 1, contactList: [{ contactId: 123, email: 'private@example.com' }] }),
    UpdateInstance: async (req) => { Object.assign(remote.detail, req); return {}; },
    ApplyCertificate: async () => { remote.detail.status = 'pending'; remote.detail.domainValidationList = [{ domain: 'home.example.com', rootDomain: 'example.com', validationType: 'TXT', validationKey: '_dnsauth.home', validationValue: 'proof' }]; return { requestId: 'request-not-task-id' }; },
    GetTaskAttribute: async (req) => { assert.equal(req.taskId, remote.detail.instanceId); return { taskStatus: remote.task, taskMessage: 'must-not-leak' }; },
    GetUserCertificateDetail: async () => ({ id: 456, instanceId: remote.detail.instanceId, cert: 'issued-chain', key: 'cloud-key-do-not-use' }),
  };
  for (const action of Object.keys(handlers)) casClient[`${action[0].toLowerCase()}${action.slice(1)}WithOptions`] = async (req, opts) => {
    calls.push(action); assert.equal(opts.autoretry, false); return { body: await handlers[action](req) };
  };
  const dnsClient = {
    describeDomainInfoWithOptions: async () => ({ body: {} }),
    describeSubDomainRecordsWithOptions: async () => ({ body: { totalCount: remote.dns.length, domainRecords: { record: remote.dns } } }),
    addDomainRecordWithOptions: async (r) => { remote.dns.push({ recordId: 'dns1', type: r.type, value: r.value }); calls.push('AddDNS'); return { body: { recordId: 'dns1' } }; },
    deleteDomainRecordWithOptions: async () => { calls.push('DeleteDNS'); remote.dns = []; return { body: {} }; },
  };
  const options = { store, aliyunFactory: (c) => new AliyunV2Client(c, { casClient, dnsClient }),
    acmeLib: { crypto: { createCsr: async () => [Buffer.from('local-key'), Buffer.from('local-csr')] } },
    onCertificate: async (c) => { calls.push('Rotate'); assert.equal(c.privateKeyPem, 'local-key'); assert.equal(c.certificatePem, 'issued-chain'); return { certificate: { id: c.targetCertificateId || 'stable-cert' } }; } };
  return { store, remote, calls, handlers, options, service: new CertificateIssuance(options), dir };
}

test('V2 filters PRO, formal, unknown and incomplete instance specifications', () => {
  assert.equal(isFreeInstance(unused()), true);
  for (const patch of [{ instanceType: 'BUY' }, { spec: 'pro' }, { orderEndTime: undefined }, { fullDomainCount: 2 },
    { orderEndTime: Date.now() + 365 * 86400000 }, { upgradeStatus: 'payed' }]) assert.equal(isFreeInstance({ ...unused(), ...patch }), false);
});

test('V2 completes DNS issuance across restart and preserves certificate identity', async (t) => {
  const f = setup(t);
  f.store.patchIssuance('aliyun', { certificateId: 'existing-cert' });
  const result = await f.service.issue(); assert.equal(result.phase, 'domain_verify');
  assert.equal(f.remote.detail.autoReissue, 'disable');
  assert.equal(f.remote.detail.generateCsrMethod, 'upload');
  assert.deepEqual(f.remote.detail.contactIdList, [123]);
  const restored = new ConfigStore(f.dir); restored.load();
  const service = new CertificateIssuance({ ...f.options, store: restored });
  f.remote.detail.certificateId = 456; f.remote.detail.certificateStatus = 'issued';
  await service.issue();
  assert.equal(restored.issuanceConfig().aliyun.certificateId, 'existing-cert');
  assert.equal(restored.issuanceConfig().aliyun.order, null);
  assert.equal(f.calls.filter((v) => v === 'ApplyCertificate').length, 1);
  assert.equal(f.calls.at(-1), 'DeleteDNS');
  assert.equal(JSON.stringify(restored.issuanceStatus()).includes('local-key'), false);
});

test('V2 interrupted submission queries the same instance and never reapplies', async (t) => {
  const f = setup(t); const apply = f.handlers.ApplyCertificate;
  f.handlers.ApplyCertificate = async () => { await apply(); throw new Error('timeout with secret dump'); };
  await assert.rejects(f.service.issue(), /阿里云请求失败/);
  assert.equal(f.store.issuanceConfig().aliyun.order.stage, 'submitted');
  await f.service.issue();
  assert.equal(f.calls.filter((v) => v === 'ApplyCertificate').length, 1);
  assert.equal(f.store.issuanceStatus().aliyun.phase, 'domain_verify');
});

test('V2 rejects ambiguous contacts before modifying an instance', async (t) => {
  const f = setup(t); f.handlers.ListContact = async () => ({ totalCount: 2, contactList: [{ contactId: 1 }, { contactId: 2 }] });
  await assert.rejects(f.service.issue(), /多个联系人/);
  assert.equal(f.calls.includes('UpdateInstance'), false);
  assert.equal(f.store.issuanceConfig().aliyun.order, null);
});

test('V2 has no purchase fallback when no unused free instances exist', async (t) => {
  const f = setup(t); f.remote.detail.spec = 'paid-pro';
  await assert.rejects(f.service.issue(), /没有可用的新版免费实例/);
  assert.deepEqual(f.calls, ['ListInstances']);
  assert.equal(f.store.issuanceConfig().aliyun.order, null);
});

test('V2 guards external domain/CSR changes and invalid downloaded certificates', async (t) => {
  const f = setup(t); await f.service.issue();
  f.remote.detail.domain = 'other.example.com';
  await assert.rejects(f.service.issue(), /域名、CSR/);
  assert.equal(f.calls.includes('Rotate'), false);
  f.remote.detail.domain = 'home.example.com'; f.remote.detail.certificateId = 456; f.remote.detail.certificateStatus = 'issued';
  f.handlers.GetUserCertificateDetail = async () => ({ id: 456, instanceId: 'cas_dv-cn-other', cert: 'bad' });
  await assert.rejects(f.service.issue(), /下载证书与实例不一致/);
  assert.equal(f.calls.includes('Rotate'), false);
});

test('V2 failed task needs explicit retry and does not expose raw task messages', async (t) => {
  const f = setup(t); f.remote.task = 'failed';
  await assert.rejects(f.service.issue(), /未通过/);
  assert.equal(f.store.issuanceStatus().aliyun.lastError.includes('must-not-leak'), false);
  await f.service.tick(); assert.equal(f.calls.filter((x) => x === 'ApplyCertificate').length, 1);
  f.remote.detail.status = 'inactive';
  f.store.updateIssuance({ aliyun: { contactId: '789' } });
  f.handlers.ApplyCertificate = async () => { f.remote.task = 'success'; f.remote.detail.status = 'pending'; return {}; };
  await f.service.retryFailed();
  assert.equal(f.calls.filter((x) => x === 'ApplyCertificate').length, 2);
  assert.deepEqual(f.remote.detail.contactIdList, [789]);
});

test('V2 rejects cross-domain DNS challenges before adding records and handles apex TXT explicitly', async (t) => {
  const f = setup(t); await f.service.issue();
  f.remote.detail.domainValidationList[0].domain = 'victim.example.com';
  const before = f.calls.filter((s) => s === 'AddDNS').length;
  await assert.rejects(f.service.issue(), /其他域名/);
  assert.equal(f.calls.filter((s) => s === 'AddDNS').length, before);
  assert.deepEqual(validationRecord('example.com', 'example.com', true), { name: 'example.com', rr: '@' });
  assert.throws(() => validationRecord('outside.test', 'example.com', true), /不属于/);
});

test('V2 cannot switch versions while pending and legacy settings retain their API version', (t) => {
  const f = setup(t);
  f.store.patchIssuance('aliyun', { order: { id: 'cas_dv-cn-id', apiVersion: 'v2' } });
  assert.throws(() => f.store.updateIssuance({ aliyun: { apiVersion: 'v1' } }), /尚未结束/);
  delete f.store.data.integrations.certificateIssuance.aliyun.apiVersion;
  assert.equal(f.store.issuanceConfig().aliyun.apiVersion, 'v1');
});

test('V2 rotates with the next unused instance and retains the stable local ID', async (t) => {
  const f = setup(t); await f.service.issue();
  f.remote.detail.certificateId = 456; f.remote.detail.certificateStatus = 'issued';
  await f.service.issue();
  const originalId = f.store.issuanceConfig().aliyun.certificateId;
  f.remote.detail = unused('cas_dv-cn-free2');
  await f.service.issue();
  assert.equal(f.store.issuanceConfig().aliyun.order.id, 'cas_dv-cn-free2');
  f.remote.detail.certificateId = 456; f.remote.detail.certificateStatus = 'issued';
  await f.service.issue();
  assert.equal(f.store.issuanceConfig().aliyun.certificateId, originalId);
  assert.equal(f.calls.filter((s) => s === 'ApplyCertificate').length, 2);
});

test('V2 rotation failure retains the order/key and cleanup recovery does not reissue', async (t) => {
  const f = setup(t); await f.service.issue();
  f.remote.detail.certificateId = 456; f.remote.detail.certificateStatus = 'issued';
  const good = f.service.onCertificate;
  f.service.onCertificate = async () => { throw new Error('certificate validation rejected'); };
  await assert.rejects(f.service.issue(), /validation rejected/);
  assert.equal(f.store.issuanceConfig().aliyun.order.privateKeyPem, 'local-key');
  assert.equal(f.store.issuanceConfig().aliyun.lastSuccessAt, null);
  f.service.onCertificate = good;
  const cleanup = f.service.cleanup;
  f.service.cleanup = async () => { throw new Error('cleanup unavailable'); };
  await assert.rejects(f.service.issue(), /cleanup unavailable/);
  assert.equal(f.store.issuanceConfig().aliyun.order.stage, 'cleanup');
  assert.equal(f.store.issuanceConfig().aliyun.certificateId, 'stable-cert');
  f.service.cleanup = cleanup;
  await f.service.issue();
  assert.equal(f.store.issuanceConfig().aliyun.order, null);
  assert.equal(f.calls.filter((s) => s === 'ApplyCertificate').length, 1);
});

test('V2 rejects incomplete pages and foreign-domain instances before writes', async (t) => {
  const f = setup(t);
  f.handlers.ListInstances = async () => ({ totalCount: 2, instanceList: [f.remote.detail] });
  await assert.rejects(f.service.issue(), /重复或不完整/);
  f.handlers.ListInstances = async () => ({ totalCount: 1, instanceList: [{ ...f.remote.detail, domain: 'other.example.com' }] });
  await assert.rejects(f.service.issue(), /没有可用/);
  assert.equal(f.calls.includes('UpdateInstance'), false);
});


test('issuance progress exposes real in-flight steps, bounds history and omits SDK data', async () => {
  let complete;
  const pending = new Promise((resolve) => { complete = resolve; });
  const service = new CertificateIssuance({ store: {}, aliyunFactory: () => ({ quota: () => pending }) });
  const task = service.client({ accessKeySecret: 'private-key' }).quota();
  assert.equal(service.activeSteps.get('aliyun').message, '查询免费额度 / 可用实例');
  assert.equal(service.events.length, 1);
  complete({ remaining: 1, privateKey: 'never-log-response' }); await task;
  assert.equal(service.activeSteps.size, 0);
  assert.equal(service.events.at(-1).level, 'success');
  assert.doesNotMatch(JSON.stringify(service.events), /private-key|never-log-response/);
  for (let i = 0; i < 250; i++) service.event('aliyun', 'poll');
  assert.equal(service.events.length, 200);
  const failing = new CertificateIssuance({ store: {}, aliyunFactory: () => ({ quota: async () => { throw new Error('secret-raw-sdk-response'); } }) });
  await assert.rejects(failing.client({}).quota());
  assert.equal(failing.events.at(-1).level, 'error');
  assert.equal(failing.activeSteps.size, 0);
  assert.doesNotMatch(JSON.stringify(failing.events), /secret-raw-sdk-response/);
});
