import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ConfigStore } from '../lib/config-store.js';
import { CloudflareDnsClient } from '../lib/cloudflare-dns.js';
import { DdnsService } from '../lib/ddns-service.js';
import { CertificateIssuance } from '../lib/certificate-issuance.js';

const response = (result, { status = 200, success = true } = {}) => ({
  ok: status >= 200 && status < 300,
  status,
  json: async () => ({ success, result }),
});

test('updates an existing Cloudflare DNS record and avoids unchanged writes', async () => {
  const requests = [];
  const fetchFn = async (url, options = {}) => {
    requests.push({ url, options });
    if ((options.method || 'GET') === 'GET') return response([{ id: 'record-1', type: 'A', name: 'home.example.com', content: requests.length === 1 ? '198.51.100.1' : '203.0.113.7', ttl: 1, proxied: false }]);
    return response({ id: 'record-1', ...JSON.parse(options.body) });
  };
  const client = new CloudflareDnsClient({ zoneId: 'zone-id', apiToken: 'secret', fetchFn });
  const changed = await client.upsert({ type: 'A', name: 'home.example.com', content: '203.0.113.7', ttl: 1, proxied: false });
  const unchanged = await client.upsert({ type: 'A', name: 'home.example.com', content: '203.0.113.7', ttl: 1, proxied: false });
  assert.equal(changed.changed, true);
  assert.equal(unchanged.changed, false);
  assert.equal(requests.filter((item) => item.options.method === 'PATCH').length, 1);
  assert.equal(requests[0].options.headers.Authorization, 'Bearer secret');
});

test('syncs DDNS and records the latest address without exposing the token', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-ddns-'));
  const store = new ConfigStore(directory);
  try {
    store.load();
    store.updateDdns({ zoneId: '023e105f4ecef8ad9ca31a8372d0c353', apiToken: 'secret', recordName: 'home.example.com', recordType: 'A' });
    const fetchFn = async (url, options = {}) => (options.method || 'GET') === 'GET' ? response([]) : response({ id: 'new-record', ...JSON.parse(options.body) });
    const automation = new DdnsService({ store, fetchFn });
    const result = await automation.sync({ publicIp: '203.0.113.9' });
    assert.equal(result.changed, true);
    assert.equal(store.ddnsStatus().lastIp, '203.0.113.9');
    assert.equal(Object.hasOwn(store.ddnsStatus(), 'apiToken'), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('a malformed Cloudflare response or a timeout reading its body cannot cause a DNS write', async () => {
  const calls = [];
  const malformed = new CloudflareDnsClient({ zoneId: 'zone', apiToken: 'secret', fetchFn: async (url, options) => { calls.push(options.method); return { ok: true, status: 200, json: async () => ({}) }; } });
  await assert.rejects(malformed.upsert({ type: 'A', name: 'home.example.com', content: '1.2.3.4' }), /响应无效/);
  assert.deepEqual(calls, ['GET']);
  const timeout = new CloudflareDnsClient({ zoneId: 'zone', apiToken: 'secret', fetchFn: async () => ({ json: async () => { throw Object.assign(new Error('aborted'), { name: 'AbortError' }); } }) });
  await assert.rejects(timeout.findRecords('A', 'home.example.com'), /请求超时/);
});

test('completes ACME DNS-01, cleans the challenge, and links the saved certificate', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-acme-'));
  const store = new ConfigStore(directory);
  const requests = [];
  try {
    store.load();
    store.updateIssuance({ provider: 'acme', acme: {
      zoneId: '023e105f4ecef8ad9ca31a8372d0c353',
      apiToken: 'secret',
      email: 'admin@example.com', domains: ['example.com', '*.example.com'], environment: 'staging',
    } });
    const fetchFn = async (url, options = {}) => {
      requests.push({ url, options });
      if (options.method === 'DELETE') return response({ id: 'txt-1' });
      return response({ id: 'txt-1' });
    };
    const fakeAcme = {
      directory: { letsencrypt: { staging: 'https://acme.test/staging', production: 'https://acme.test/production' } },
      crypto: {
        createPrivateEcdsaKey: async () => Buffer.from('account-key'),
        createCsr: async () => [Buffer.from('certificate-key'), Buffer.from('csr')],
      },
      Client: class {
        async auto(options) {
          const authz = { identifier: { value: 'example.com' } };
          const challenge = { url: 'challenge-1', token: 'token-1' };
          await options.challengeCreateFn(authz, challenge, 'dns-proof');
          await options.challengeRemoveFn(authz, challenge, 'dns-proof');
          return 'certificate-chain';
        }
      },
    };
    const automation = new CertificateIssuance({
      store,
      fetchFn,
      resolver: { resolveTxt: async () => [['dns-proof']] },
      acmeLib: fakeAcme,
      onCertificate: async (candidate) => {
        assert.equal(candidate.privateKeyPem, 'certificate-key');
        return { certificate: { id: 'certificate-1', name: candidate.name }, tlsReload: { ok: true, updated: 1 } };
      },
    });
    const result = await automation.issue();
    assert.equal(result.certificate.id, 'certificate-1');
    assert.equal(store.issuanceStatus().acme.certificateId, 'certificate-1');
    assert.equal(store.issuanceStatus().acme.hasAccount, true);
    assert.equal(requests.filter((item) => item.options.method === 'POST').length, 1);
    assert.equal(requests.filter((item) => item.options.method === 'DELETE').length, 1);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
