import assert from 'node:assert/strict';
import test from 'node:test';
import { AliyunZoneDiscovery, zoneCandidates } from '../lib/aliyun-zone-discovery.js';

const credentials = {
  ddns: { accessKeyId: 'ddns-id', accessKeySecret: 'ddns-private-secret', dnsZone: 'old.example.com' },
  issuance: { accessKeyId: 'issuance-id', accessKeySecret: 'issuance-private-secret', dnsZone: 'example.com', order: { id: '101' } },
};
const body = (zones = []) => ({ body: { totalCount: zones.length, domains: { domain: zones.map((domainName) => ({ domainName, domainId: `id-${domainName}` })) } } });
function fixture(handler = (request) => body(request.keyWord === 'example.com' ? ['example.com'] : []), options = {}) {
  const saved = structuredClone(credentials);
  const before = JSON.stringify(saved);
  const calls = [];
  const accounts = [];
  const service = new AliyunZoneDiscovery({
    store: { ddnsConfig: () => ({ aliyun: saved.ddns }), issuanceConfig: () => ({ aliyun: saved.issuance }) },
    dnsFactory: (config) => { accounts.push(config); return { describeDomainsWithOptions: (request, runtime) => { calls.push({ request, runtime }); return handler(request, runtime); } }; },
    ...options,
  });
  return { service, calls, accounts, assertReadOnly: () => assert.equal(JSON.stringify(saved), before) };
}

test('zone candidates preserve multi-part suffixes and reject wildcards, IPs and excessive work', () => {
  assert.deepEqual(zoneCandidates(' HOME.Example.COM.CN. '), ['home.example.com.cn', 'example.com.cn', 'com.cn']);
  assert.deepEqual(zoneCandidates('example.com'), ['example.com']);
  assert.deepEqual(zoneCandidates('home.xn--fiqs8s.com'), ['home.xn--fiqs8s.com', 'xn--fiqs8s.com']);
  for (const value of ['', null, {}, 'localhost', '127.0.0.1', '::1', 'https://example.com', '*.example.com', 'home..com', 'home.example.com/path', `${'a.'.repeat(18)}com`]) assert.throws(() => zoneCandidates(value));
});

test('query is exact, bounded and read-only; a longer unstarred child wins over its parent', async () => {
  const f = fixture((request) => body(['example.com.cn', 'nas.example.com.cn'].includes(request.keyWord) && !request.starmark ? [request.keyWord] : []));
  const result = await f.service.resolve('certificate-issuance', { domain: 'www.nas.example.com.cn' });
  assert.equal(result.dnsZone, 'nas.example.com.cn');
  assert.equal(result.domain, 'www.nas.example.com.cn');
  assert.ok(Date.parse(result.checkedAt));
  assert.deepEqual(f.calls.map(({ request }) => [request.keyWord, request.starmark]), [['www.nas.example.com.cn', false], ['www.nas.example.com.cn', true], ['nas.example.com.cn', false]]);
  for (const { request, runtime } of f.calls) {
    assert.equal(request.searchMode, 'EXACT'); assert.equal(request.pageNumber, 1); assert.equal(request.pageSize, 100);
    assert.equal(runtime.autoretry, false); assert.equal(runtime.maxAttempts, 1);
    assert.ok(runtime.readTimeout <= 8000); assert.ok(runtime.connectTimeout <= 5000);
  }
  assert.equal(JSON.stringify(result).includes('secret'), false);
  f.assertReadOnly();
});

test('starred domains and apex records resolve without relying on list default filtering', async () => {
  const f = fixture((request) => body(request.starmark ? ['example.co.uk'] : []));
  assert.equal((await f.service.resolve('ddns', { domain: 'example.co.uk' })).dnsZone, 'example.co.uk');
  assert.equal(f.calls.length, 2);
  f.assertReadOnly();
});

test('credentials stay scoped and unsaved drafts are not persisted or returned', async () => {
  const f = fixture();
  await f.service.resolve('ddns', { domain: 'home.example.com' });
  await f.service.resolve('certificate-issuance', { domain: 'home.example.com', accessKeySecret: '' });
  const result = await f.service.resolve('ddns', { domain: 'home.example.com', accessKeyId: 'new-draft-id', accessKeySecret: 'unsaved-secret', scope: 'certificate-issuance', endpoint: 'https://attacker.invalid' });
  assert.deepEqual(f.accounts, [
    { accessKeyId: 'ddns-id', accessKeySecret: 'ddns-private-secret' },
    { accessKeyId: 'issuance-id', accessKeySecret: 'issuance-private-secret' },
    { accessKeyId: 'new-draft-id', accessKeySecret: 'unsaved-secret' },
  ]);
  assert.deepEqual(Object.keys(result).sort(), ['checkedAt', 'dnsZone', 'domain']);
  f.assertReadOnly();
});

test('missing, cleared and mismatched credentials fail before any cloud call', async () => {
  const f = fixture();
  for (const input of [{ accessKeyId: '' }, { accessKeyId: 'different-account' }, { clearAccessKeySecret: true }, { accessKeyId: 'x'.repeat(257), accessKeySecret: 'new-secret' }]) {
    await assert.rejects(f.service.resolve('ddns', { domain: 'home.example.com', ...input }), { status: 400 });
  }
  await assert.rejects(f.service.resolve('unknown', { domain: 'home.example.com' }), { status: 400 });
  await assert.rejects(f.service.resolve('ddns', null), { status: 400 });
  assert.equal(f.calls.length, 0);
});

test('no match is explicit and is never filled using a guessed parent domain', async () => {
  const f = fixture(() => body());
  await assert.rejects(f.service.resolve('ddns', { domain: 'home.example.com.cn' }), { status: 404 });
  assert.equal(f.calls.length, 6);
  f.assertReadOnly();
});

test('malformed, partial, duplicate and unrelated exact-match responses fail closed', async () => {
  for (const response of [undefined, {}, { body: {} }, { body: { domains: { domain: [] } } }, { body: { totalCount: 5, domains: { domain: [] } } }, body(['example.com', 'example.com']), body(['notexample.com']), { body: { totalCount: 1, domains: { domain: [{ domainName: 'example.com' }] } } }]) {
    const f = fixture(() => response);
    await assert.rejects(f.service.resolve('ddns', { domain: 'example.com' }), { status: 502 });
    assert.equal(f.calls.length, 1);
    f.assertReadOnly();
  }
});

test('cloud errors preserve recovery guidance but never expose SDK dumps or secrets', async () => {
  for (const [code, status, message] of [['Forbidden.RAM', 403, /alidns:DescribeDomains/], ['InvalidAccessKeyId.NotFound', 502, /AccessKey/], ['unknown-unsaved-secret', 502, /网络/]]) {
    const f = fixture(() => { throw Object.assign(new Error('unsaved-secret signed url: https://secret.invalid'), { code, data: { RequestId: 'unsaved-secret' } }); });
    await assert.rejects(f.service.resolve('ddns', { domain: 'example.com' }), (error) => {
      assert.equal(error.status, status); assert.match(error.message, message); assert.doesNotMatch(error.message, /unsaved-secret|secret.invalid|signed url/); return true;
    });
    assert.equal(f.calls.length, 1); f.assertReadOnly();
  }
});

test('demo mode has no network calls and never pretends to resolve a zone', async () => {
  const f = fixture(() => { throw new Error('must not call cloud'); }, { demoMode: true });
  const result = await f.service.resolve('ddns', { domain: 'home.example.com' });
  assert.equal(result.demoMode, true); assert.equal(result.dnsZone, null); assert.match(result.message, /演示模式/);
  assert.equal(f.accounts.length, 0); f.assertReadOnly();
});

test('a lookup has an overall deadline and releases concurrency on timeout', async () => {
  const f = fixture(() => new Promise(() => {}), { timeoutMs: 15 });
  await assert.rejects(f.service.resolve('ddns', { domain: 'home.example.com' }), { status: 504 });
  assert.equal(f.service.active, 0); assert.equal(f.calls.length, 1);
});

test('concurrent lookups are bounded and failed calls release their slots', async () => {
  let release;
  const pending = new Promise((resolve) => { release = resolve; });
  const f = fixture(() => pending);
  const first = f.service.resolve('ddns', { domain: 'example.com' });
  const second = f.service.resolve('certificate-issuance', { domain: 'example.com' });
  await assert.rejects(f.service.resolve('ddns', { domain: 'example.com' }), { status: 429 });
  release(body(['example.com']));
  await Promise.all([first, second]);
  assert.equal(f.service.active, 0);
});
