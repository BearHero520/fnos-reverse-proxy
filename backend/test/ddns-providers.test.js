import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ConfigStore } from '../lib/config-store.js';
import { DdnsService } from '../lib/ddns-service.js';
import { AliyunDdnsClient, DnspodDdnsClient, createDdnsClient, relativeRecord } from '../lib/ddns-providers.js';
import { CloudflareDnsClient } from '../lib/cloudflare-dns.js';

const credentials = {
  aliyun: { accessKeyId: 'test-ak-id', accessKeySecret: 'test-ak-secret', dnsZone: 'example.com', line: 'default' },
  dnspod: { secretId: 'test-tc-id', secretKey: 'test-tc-secret', dnsZone: 'example.com', line: '默认' },
};
const zoneId = '023e105f4ecef8ad9ca31a8372d0c353';
function setup(t, provider = 'aliyun', patch = {}) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-ddns-providers-'));
  t.after(() => fs.rmSync(dir, { recursive: true, force: true }));
  const store = new ConfigStore(dir); store.load();
  store.updateDdns({ provider, recordName: 'home.example.com', zoneId, apiToken: 'test-cf-secret', ...credentials, ...patch });
  return store;
}
function sdkHarness(provider, initial = []) {
  const calls = [];
  let records = initial;
  let response;
  let error;
  const wrap = (body) => provider === 'aliyun' ? { body } : body;
  const read = async (input, runtime) => {
    calls.push({ action: 'read', input, runtime });
    if (error) throw error;
    return wrap(response || (provider === 'aliyun' ? { totalCount: records.length, domainRecords: { record: records } } : { RecordCountInfo: { TotalCount: records.length, ListCount: records.length }, RecordList: records }));
  };
  const write = (action) => async (input, runtime) => {
    calls.push({ action, input, runtime });
    records = provider === 'aliyun'
      ? [{ ...aliRecord(), ...input, recordId: input.recordId || 'record-1' }]
      : [{ ...tcRecord(), ...input, Name: input.SubDomain, Type: input.RecordType, Line: input.RecordLine, RecordId: input.RecordId || 101 }];
    return wrap(provider === 'aliyun' ? { recordId: records[0].recordId } : { RecordId: records[0].RecordId });
  };
  const dnsClient = provider === 'aliyun'
    ? { describeDomainRecordsWithOptions: read, addDomainRecordWithOptions: write('create'), updateDomainRecordWithOptions: write('update') }
    : { DescribeRecordList: read, CreateRecord: write('create'), ModifyRecord: write('update') };
  const client = provider === 'aliyun' ? new AliyunDdnsClient(credentials.aliyun, { dnsClient }) : new DnspodDdnsClient(credentials.dnspod, { dnsClient });
  return { client, calls, setRecords: (value) => { records = value; }, setResponse: (value) => { response = value; }, setError: (value) => { error = value; } };
}
const aliRecord = (patch = {}) => ({ recordId: 'record-1', RR: 'home', type: 'A', line: 'default', value: '198.51.100.1', TTL: 600, status: 'ENABLE', ...patch });
const tcRecord = (patch = {}) => ({ RecordId: 101, Name: 'home', Type: 'A', Line: '默认', Value: '198.51.100.1', TTL: 600, Status: 'ENABLE', ...patch });
const target = { name: 'home.example.com', type: 'A', content: '203.0.113.8', ttl: 600 };

test('DDNS preserves legacy Cloudflare config and isolates every provider from certificate issuance', (t) => {
  const store = setup(t, 'cloudflare', { enabled: true });
  store.recordDdnsResult({ ok: true, ip: target.content, changed: true });
  store.data.integrations.ddns = { provider: 'cloudflare', zoneId, apiToken: 'test-cf-secret', enabled: true, recordName: 'home.example.com', lastIp: target.content };
  store.save();
  const loaded = new ConfigStore(store.dataDir); loaded.load();
  assert.equal(loaded.ddnsConfig().provider, 'cloudflare');
  assert.equal(loaded.ddnsConfig().enabled, true);
  assert.equal(loaded.ddnsConfig().lastIp, target.content);
  assert.equal(loaded.ddnsConfig().dnspod.line, '默认');
  loaded.updateIssuance({ aliyun: { accessKeyId: 'certificate-ak', accessKeySecret: 'certificate-secret' } });
  loaded.updateDdns({ provider: 'aliyun', ...credentials });
  assert.equal(loaded.ddnsConfig().ttl, 600);
  assert.equal(loaded.ddnsConfig().enabled, false);
  assert.equal(loaded.ddnsConfig().lastIp, null);
  assert.equal(loaded.issuanceConfig().aliyun.accessKeySecret, 'certificate-secret');
  loaded.updateDdns({ provider: 'dnspod', dnspod: { secretKey: '', line: '电信' }, lastIp: 'forged', lastError: 'forged' });
  assert.equal(loaded.ddnsConfig().dnspod.secretKey, credentials.dnspod.secretKey);
  assert.equal(loaded.ddnsConfig().aliyun.accessKeySecret, credentials.aliyun.accessKeySecret);
  assert.equal(loaded.ddnsConfig().apiToken, 'test-cf-secret');
  assert.equal(loaded.ddnsConfig().lastError, null);
  const publicData = JSON.stringify([loaded.ddnsStatus(), loaded.exportConfig()]);
  for (const secret of ['test-cf-secret', 'test-ak-secret', 'test-tc-secret', 'certificate-secret']) assert.equal(publicData.includes(secret), false);
  const reloaded = new ConfigStore(store.dataDir); reloaded.load();
  assert.equal(reloaded.ddnsConfig().dnspod.line, '电信');
  reloaded.updateDdns({ dnspod: { clearSecretKey: true } });
  assert.equal(reloaded.ddnsConfig().dnspod.secretKey, '');
  assert.equal(reloaded.ddnsStatus().dnspod.hasSecretKey, false);
});

test('DDNS validates provider, DNS zone boundaries, TTL, record type, and account-key changes', (t) => {
  const store = setup(t);
  for (const patch of [{ provider: 'unknown' }, { provider: 'toString' }, { recordType: 'CNAME' }, { recordName: 'example.com.evil.test' }, { recordName: 'notexample.com' }, { ttl: 1 }, { aliyun: { accessKeyId: 'different-id' } }, { aliyun: { line: 'default\nforged' } }]) assert.throws(() => store.updateDdns(patch));
  store.updateDdns({ recordName: 'example.com', aliyun: { accessKeyId: 'new-id', accessKeySecret: 'new-secret' }, enabled: true });
  assert.equal(store.ddnsConfig().recordName, 'example.com');
  assert.throws(() => store.updateDdns({ aliyun: { clearAccessKeySecret: true } }), /凭据/);
  store.updateDdns({ enabled: false, aliyun: { clearAccessKeySecret: true } });
  assert.equal(store.ddnsStatus().aliyun.hasAccessKeySecret, false);
  assert.equal(relativeRecord('EXAMPLE.COM.', 'example.com'), '@');
  assert.equal(relativeRecord('home.office.example.com', 'example.com'), 'home.office');
  assert.throws(() => relativeRecord('otherexample.com', 'example.com'));
});

for (const provider of ['aliyun', 'dnspod']) {
  const item = provider === 'aliyun' ? aliRecord : tcRecord;
  test(`${provider}: creates only the requested host/type/line and skips unchanged updates`, async () => {
    const harness = sdkHarness(provider);
    assert.equal((await harness.client.upsert(target)).changed, true);
    assert.equal((await harness.client.upsert(target)).changed, false);
    assert.deepEqual(harness.calls.map((call) => call.action), ['read', 'create', 'read']);
    const input = harness.calls[1].input;
    if (provider === 'aliyun') {
      assert.equal(input.domainName, 'example.com'); assert.equal(input.RR, 'home'); assert.equal(input.type, 'A'); assert.equal(input.line, 'default'); assert.equal(input.TTL, 600);
      assert.equal(harness.calls[0].input.searchMode, 'COMBINATION');
      assert.equal(harness.calls[0].runtime.autoretry, false);
    } else {
      assert.equal(input.Domain, 'example.com'); assert.equal(input.SubDomain, 'home'); assert.equal(input.RecordType, 'A'); assert.equal(input.RecordLine, '默认'); assert.equal(input.TTL, 600);
      assert.equal(harness.calls[0].input.ErrorOnEmpty, 'no'); assert.equal(harness.calls[0].input.SubDomain, 'home');
      assert.equal(Object.hasOwn(input, 'DomainId'), false);
    }
  });
  test(`${provider}: updates an exact record ID without altering other hosts or lines`, async () => {
    const otherHost = provider === 'aliyun' ? { RR: 'other', recordId: 'other' } : { Name: 'other', RecordId: 102 };
    const otherLine = provider === 'aliyun' ? { line: 'telecom', recordId: 'other-line' } : { Line: '电信', RecordId: 103 };
    const harness = sdkHarness(provider, [item(otherHost), item(otherLine), item()]);
    assert.equal((await harness.client.upsert(target)).changed, true);
    assert.deepEqual(harness.calls.map((call) => call.action), ['read', 'update']);
    assert.equal(provider === 'aliyun' ? harness.calls[1].input.recordId : harness.calls[1].input.RecordId, provider === 'aliyun' ? 'record-1' : 101);
  });
  test(`${provider}: supports root records and equivalent compressed IPv6 without repeated writes`, async () => {
    const harness = sdkHarness(provider);
    const root = { ...target, name: 'example.com', type: 'AAAA', content: '2001:db8::1' };
    await harness.client.upsert(root);
    assert.equal(provider === 'aliyun' ? harness.calls[1].input.RR : harness.calls[1].input.SubDomain, '@');
    assert.equal((await harness.client.upsert({ ...root, content: '2001:db8:0:0:0:0:0:1' })).changed, false);
  });
  test(`${provider}: refuses duplicate records, CNAME, disabled records, and weighted routing`, async () => {
    const cases = [[item(), item()], [item(provider === 'aliyun' ? { type: 'CNAME' } : { Type: 'CNAME' })], [item(provider === 'aliyun' ? { status: 'DISABLE' } : { Status: 'DISABLE' })], [item(provider === 'aliyun' ? { lbaStatus: true } : { Weight: 10 })]];
    for (const records of cases) {
      const harness = sdkHarness(provider, records);
      await assert.rejects(harness.client.upsert(target), /多条|冲突|暂停|负载均衡/);
      assert.deepEqual(harness.calls.map((call) => call.action), ['read']);
    }
  });
  test(`${provider}: a truncated/malformed response is not treated as an absent record`, async () => {
    for (const response of provider === 'aliyun' ? [{}, { totalCount: 2, domainRecords: { record: [item()] } }, { totalCount: 1, domainRecords: { record: [{}] } }] : [{}, { RecordCountInfo: { TotalCount: 2 }, RecordList: [item()] }, { RecordCountInfo: { TotalCount: 1 }, RecordList: [{}] }]) {
      const harness = sdkHarness(provider); harness.setResponse(response);
      await assert.rejects(harness.client.upsert(target), /响应不完整/);
      assert.deepEqual(harness.calls.map((call) => call.action), ['read']);
    }
  });
  test(`${provider}: sanitized authentication errors never cause a create call or leak credentials`, async (t) => {
    const store = setup(t, provider);
    const logs = [];
    const harness = sdkHarness(provider);
    harness.setError(Object.assign(new Error(`request dump test-ak-secret test-tc-secret test-cf-secret`), { code: 'AuthFailure.SignatureFailure', requestId: 'request-test' }));
    const service = new DdnsService({ store, logger: { warn: (...args) => logs.push(args) }, clientFactory: () => harness.client });
    await assert.rejects(service.sync({ publicIp: target.content }), /AuthFailure.SignatureFailure/);
    assert.deepEqual(harness.calls.map((call) => call.action), ['read']);
    const result = JSON.stringify([store.ddnsStatus(), logs]);
    for (const secret of ['test-ak-secret', 'test-tc-secret', 'test-cf-secret']) assert.equal(result.includes(secret), false);
    assert.equal(store.ddnsStatus().lastSuccessAt, null);
  });
  test(`${provider}: read-only connection checks never detect public IP or write sync history`, async (t) => {
    const store = setup(t, provider);
    const harness = sdkHarness(provider, [item()]);
    const before = store.ddnsStatus();
    const service = new DdnsService({ store, clientFactory: () => harness.client, fetchFn: () => assert.fail('IP lookup must not run') });
    assert.equal((await service.test()).recordExists, true);
    assert.deepEqual(store.ddnsStatus(), before);
    assert.deepEqual(harness.calls.map((call) => call.action), ['read']);
  });
  test(`${provider}: automatic sync detects the correct IP family and demo never reaches the cloud`, async (t) => {
    const store = setup(t, provider, { enabled: true, recordType: 'AAAA' });
    const harness = sdkHarness(provider);
    const requests = [];
    const fetchFn = async (url) => { requests.push(url); return { ok: true, json: async () => ({ ip: '2001:db8::1' }) }; };
    const service = new DdnsService({ store, clientFactory: () => harness.client, fetchFn });
    await service.tick(); await service.tick();
    assert.equal(store.ddnsStatus().lastIp, '2001:db8::1');
    assert.equal(requests.length, 1); assert.match(requests[0], /api6\.ipify/);
    assert.deepEqual(harness.calls.map((call) => call.action), ['read', 'create']);
    await assert.rejects(service.sync({ publicIp: '203.0.113.1' }), /类型/);
    assert.equal(harness.calls.length, 2);
    const before = store.ddnsStatus();
    const demo = new DdnsService({ store, demoMode: true, fetchFn: () => assert.fail('no network in demo'), clientFactory: () => assert.fail('no SDK in demo') });
    assert.equal((await demo.sync()).demoMode, true); assert.equal((await demo.test()).demoMode, true);
    await demo.tick(); assert.deepEqual(store.ddnsStatus(), before);
  });
}

test('the factory constructs official cloud DNS SDKs with fixed HTTPS endpoints', (t) => {
  const store = setup(t);
  const aliyun = createDdnsClient(store.ddnsConfig());
  assert.ok(aliyun instanceof AliyunDdnsClient);
  assert.equal(aliyun.runtime.autoretry, false);
  store.updateDdns({ provider: 'dnspod' });
  const dnspod = createDdnsClient(store.ddnsConfig());
  assert.ok(dnspod instanceof DnspodDdnsClient);
  assert.equal(dnspod.client.profile.httpProfile.endpoint, 'dnspod.tencentcloudapi.com');
  assert.equal(dnspod.client.profile.signMethod, 'TC3-HMAC-SHA256');
  assert.equal(dnspod.client.profile.httpProfile.reqTimeout, 15);
  store.updateDdns({ provider: 'cloudflare' });
  assert.ok(createDdnsClient(store.ddnsConfig()) instanceof CloudflareDnsClient);
});

test('Cloudflare refuses ambiguous same-type records and CNAME conflicts before writing', async () => {
  for (const types of [['A', 'A'], ['CNAME']]) {
    const methods = [];
    const client = new CloudflareDnsClient({ zoneId, apiToken: 'test-only', fetchFn: async (url, options) => {
      methods.push(options.method);
      return { ok: true, status: 200, json: async () => ({ success: true, result: types.map((type, i) => ({ id: `id-${i}`, name: target.name, type, content: '203.0.113.1' })) }) };
    } });
    await assert.rejects(client.upsert(target), /多条|冲突/);
    assert.deepEqual(methods, ['GET']);
  }
});
