import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import { ConfigStore, isRuleScheduleOpen, normalizeRule, parseHeaders, parsePortSpec, targetPortFor, validateRule, validateTargetSafety } from '../lib/config-store.js';

test('normalizes list fields and header text', () => {
  const rule = normalizeRule({ name: 'Web', domains: 'a.test, b.test\na.test', customHeaders: 'X-App: proxy\nX-Mode: safe' });
  assert.deepEqual(rule.domains, ['a.test', 'b.test']);
  assert.deepEqual(parseHeaders(rule.customHeaders), { 'X-App': 'proxy', 'X-Mode': 'safe' });
});

test('detects conflicting TCP-family listeners', () => {
  const existing = normalizeRule({ name: 'HTTP', protocol: 'http', listenPort: 8080 });
  const next = normalizeRule({ name: 'TCP', protocol: 'tcp', listenPort: 8080 });
  assert.throws(() => validateRule(next, [existing]), /监听地址/);
});

test('allows TCP and UDP on the same numeric port', () => {
  const tcp = normalizeRule({ name: 'TCP', protocol: 'tcp', listenPort: 19191 });
  const udp = normalizeRule({ name: 'UDP', protocol: 'udp', listenPort: 19191 });
  assert.doesNotThrow(() => validateRule(udp, [tcp]));
});

test('normalizes and validates one transparent TCP+UDP rule on the same numeric port', () => {
  const rule = normalizeRule({
    name: 'Universal transport',
    protocols: ['tcp', 'udp'],
    listenHost: '127.0.0.1',
    listenPorts: [19191],
    targetProtocols: ['tcp', 'udp'],
    targetHost: '127.0.0.1',
    targetPorts: [19191],
  });
  assert.equal(rule.protocol, 'tcp+udp');
  assert.deepEqual(rule.protocols, ['tcp', 'udp']);
  assert.deepEqual(rule.targetProtocols, ['tcp', 'udp']);
  assert.deepEqual(rule.listenPorts, [19191]);
  assert.deepEqual(rule.targetPorts, [19191]);
  assert.doesNotThrow(() => validateRule(rule));
});

test('normalizes multi-protocol rules and legacy TCP+UDP rules', () => {
  const multi = normalizeRule({ protocols: ['http', 'ws', 'udp'], targetProtocols: ['http', 'udp'], listenPortStart: 8000, listenPortEnd: 8002, targetPortStart: 9000, targetPortEnd: 9002 });
  assert.deepEqual(multi.protocols, ['http', 'ws', 'udp']);
  assert.deepEqual(multi.targetProtocols, ['http', 'udp']);
  assert.equal(multi.listenPort, 8000);
  assert.equal(multi.listenPortEnd, 8002);
  assert.doesNotThrow(() => validateRule(multi));

  const legacy = normalizeRule({ protocol: 'tcp+udp', targetProtocol: 'tcp' });
  assert.deepEqual(legacy.protocols, ['tcp', 'udp']);
  assert.deepEqual(legacy.targetProtocols, ['tcp', 'udp']);
});

test('parses discrete ports, newlines, Chinese separators, and ranges', () => {
  assert.deepEqual(parsePortSpec('80,22，445\n8000-8002 9000'), [80, 22, 445, 8000, 8001, 8002, 9000]);
  assert.deepEqual(parsePortSpec('80\n22\n80'), [80, 22]);
  assert.throws(() => parsePortSpec('9000-8000'), /结束端口/);
  assert.throws(() => parsePortSpec('80,not-a-port'), /格式/);
});

test('maps discrete source ports to shared or ordered target ports', () => {
  const mapped = normalizeRule({ protocol: 'tcp', targetProtocol: 'tcp', listenPorts: [80, 22, 445], targetPorts: [8080, 2222, 4445] });
  assert.deepEqual(mapped.listenPorts, [80, 22, 445]);
  assert.deepEqual(mapped.targetPorts, [8080, 2222, 4445]);
  assert.equal(targetPortFor(mapped, 22), 2222);
  assert.doesNotThrow(() => validateRule(mapped));

  const shared = normalizeRule({ protocol: 'tcp', targetProtocol: 'tcp', listenPorts: '80,22,445', targetPorts: '9000' });
  assert.equal(targetPortFor(shared, 445), 9000);
});

test('detects overlapping port ranges and invalid range mappings', () => {
  const existing = normalizeRule({ name: 'Range A', protocol: 'tcp', listenPortStart: 8100, listenPortEnd: 8110, targetProtocol: 'tcp' });
  const overlap = normalizeRule({ name: 'Range B', protocol: 'tcp', listenPortStart: 8108, listenPortEnd: 8120, targetProtocol: 'tcp' });
  assert.throws(() => validateRule(overlap, [existing]), /冲突/);

  const mismatched = normalizeRule({ name: 'Bad mapping', protocol: 'tcp', listenPortStart: 8200, listenPortEnd: 8202, targetProtocol: 'tcp', targetPortStart: 9200, targetPortEnd: 9201 });
  assert.throws(() => validateRule(mismatched), /数量一致/);
});

test('detects conflicts only on ports that are actually selected', () => {
  const existing = normalizeRule({ name: 'Discrete A', protocol: 'tcp', targetProtocol: 'tcp', listenPorts: [80, 445] });
  const clear = normalizeRule({ name: 'Discrete B', protocol: 'tcp', targetProtocol: 'tcp', listenPorts: [81, 444] });
  const overlap = normalizeRule({ name: 'Discrete C', protocol: 'tcp', targetProtocol: 'tcp', listenPorts: [22, 445] });
  assert.doesNotThrow(() => validateRule(clear, [existing]));
  assert.throws(() => validateRule(overlap, [existing]), /冲突/);
});

test('rejects multiple incompatible TCP listener modes on one range', () => {
  const rule = normalizeRule({ name: 'Mixed', protocols: ['http', 'tcp'], targetProtocols: ['http', 'tcp'] });
  assert.throws(() => validateRule(rule), /一组 TCP 类入口/);
});

test('rejects unsupported or explicitly empty protocol selections', () => {
  assert.throws(() => normalizeRule({ protocols: ['smtp'], targetProtocols: ['smtp'] }), /来源协议不受支持/);
  assert.throws(() => normalizeRule({ protocols: [], targetProtocols: [] }), /至少选择一种来源协议/);
  assert.throws(() => normalizeRule({ protocols: ['http'], targetProtocols: ['smtp'] }), /目标协议不受支持/);
});

test('rejects invalid custom and real-IP header names or values', () => {
  const badName = normalizeRule({ customHeaders: { 'Bad Header': 'value' } });
  const badValue = normalizeRule({ customHeaders: { 'X-Test': 'one\ntwo' } });
  const badRealIp = normalizeRule({ realIp: { enabled: true, header: 'Bad Header' } });
  assert.throws(() => validateRule(badName), /自定义请求头/);
  assert.throws(() => validateRule(badValue), /自定义请求头/);
  assert.throws(() => validateRule(badRealIp), /真实 IP 请求头/);
});

test('rejects invalid allow-list and block-list entries', () => {
  assert.throws(() => validateRule(normalizeRule({ allowIps: ['not-an-ip'] })), /白名单/);
  assert.throws(() => validateRule(normalizeRule({ blockIps: ['192.168.1.0/64'] })), /黑名单/);
  assert.doesNotThrow(() => validateRule(normalizeRule({ allowIps: ['192.168.1.0/24', '::1/128'] })));
});

test('detects wildcard and loopback listener conflicts', () => {
  const wildcard = normalizeRule({ name: 'Wildcard', protocol: 'tcp', listenHost: '0.0.0.0', listenPort: 18080, targetProtocol: 'tcp' });
  const loopback = normalizeRule({ name: 'Loopback', protocol: 'tcp', listenHost: '127.0.0.1', listenPort: 18080, targetProtocol: 'tcp' });
  assert.throws(() => validateRule(loopback, [wildcard]), /冲突/);
});

test('blocks direct local forwarding loops and reserved management targets', () => {
  const loop = normalizeRule({ name: 'Loop', protocol: 'tcp', listenHost: '0.0.0.0', listenPort: 18080, targetProtocol: 'tcp', targetHost: '127.0.0.1', targetPort: 18080 });
  assert.throws(() => validateTargetSafety(loop), /转发回环/);
  const management = normalizeRule({ name: 'Management', protocol: 'tcp', listenPort: 18081, targetProtocol: 'tcp', targetHost: 'nas.local', targetPort: 5099 });
  assert.throws(() => validateTargetSafety(management, { localHosts: ['nas.local'], reservedPorts: [5099] }), /管理端口/);
  assert.doesNotThrow(() => validateTargetSafety({ ...loop, enabled: false }));
});

test('evaluates normal and overnight rule schedules', () => {
  const daytime = normalizeRule({ schedule: { enabled: true, days: [1], start: '08:00', end: '18:00' } });
  assert.equal(isRuleScheduleOpen(daytime, new Date(2026, 8, 7, 12, 0)), true);
  assert.equal(isRuleScheduleOpen(daytime, new Date(2026, 8, 7, 20, 0)), false);
  const overnight = normalizeRule({ schedule: { enabled: true, days: [1], start: '22:00', end: '06:00' } });
  assert.equal(isRuleScheduleOpen(overnight, new Date(2026, 8, 7, 23, 0)), true);
  assert.equal(isRuleScheduleOpen(overnight, new Date(2026, 8, 8, 5, 30)), true);
  assert.equal(isRuleScheduleOpen(overnight, new Date(2026, 8, 8, 7, 0)), false);
});

test('validates fallback settings and applies batch rule changes atomically', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-batch-'));
  const store = new ConfigStore(directory, { reservedPorts: [5099] });
  try {
    store.load();
    assert.throws(() => store.updateSettings({ unmatchedHost: { action: 'proxy', targetUrl: 'file:///secret' } }), /HTTP/);
    assert.throws(() => store.updateSettings({ unmatchedHost: { action: 'proxy', targetUrl: 'http://127.0.0.1:5099' } }), /管理端口/);
    assert.equal(store.updateSettings({ unmatchedHost: { action: 'redirect', redirectUrl: 'https://example.test/' } }).unmatchedHost.action, 'redirect');
    const first = store.createRule({ name: 'One', protocol: 'tcp', listenPort: 18301, targetProtocol: 'tcp', targetPort: 22, enabled: false });
    const second = store.createRule({ name: 'Two', protocol: 'tcp', listenPort: 18302, targetProtocol: 'tcp', targetPort: 22, enabled: false });
    const result = store.batchRules([first.id, second.id], 'enable');
    assert.equal(result.affected.length, 2);
    assert.equal(store.rules().filter((rule) => rule.enabled).length, 2);
    store.batchRules([first.id], 'delete');
    assert.equal(store.rule(first.id), null);
    store.createRule({ name: 'Web loop', protocol: 'http', listenPort: 18303, targetProtocol: 'http', targetHost: '192.0.2.10', targetPort: 80 });
    assert.throws(() => store.updateSettings({ unmatchedHost: { action: 'proxy', targetUrl: 'http://localhost:18303' } }), /兜底转发回环/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('stores certificate push credentials as a hash and reveals the token once', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-certificate-push-'));
  const store = new ConfigStore(directory);
  try {
    store.load();
    const integration = store.rotateCertificatePush();
    assert.equal(store.verifyCertificatePush(integration.bindingId, integration.token), true);
    assert.equal(store.verifyCertificatePush(integration.bindingId, `${integration.token}x`), false);
    assert.equal(store.certificatePushStatus().enabled, true);
    const persisted = fs.readFileSync(path.join(directory, 'config.json'), 'utf8');
    assert.equal(persisted.includes(integration.token), false);
    assert.equal(JSON.stringify(store.exportConfig()).includes('certificatePush'), false);
    store.markCertificatePushUsed();
    assert.ok(store.certificatePushStatus().lastUsedAt);
    store.disableCertificatePush();
    assert.equal(store.verifyCertificatePush(integration.bindingId, integration.token), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('keeps Cloudflare and ACME secrets write-only while preserving saved credentials', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-domain-automation-'));
  const store = new ConfigStore(directory);
  try {
    store.load();
    const saved = store.updateDdns({
      zoneId: '023e105f4ecef8ad9ca31a8372d0c353',
      apiToken: 'cloudflare-secret-token',
      enabled: true, recordName: 'home.example.com', recordType: 'A', intervalMinutes: 15,
    });
    assert.equal(saved.hasApiToken, true);
    assert.equal(Object.hasOwn(saved, 'apiToken'), false);
    assert.equal(JSON.stringify(store.exportConfig()).includes('cloudflare-secret-token'), false);
    const retained = store.updateDdns({ intervalMinutes: 30 });
    assert.equal(store.ddnsConfig().apiToken, 'cloudflare-secret-token');
    assert.equal(retained.intervalMinutes, 30);
    store.patchIssuance('acme', { accountKeyPem: 'private-account-key' });
    assert.equal(store.issuanceStatus().acme.hasAccount, true);
    assert.equal(JSON.stringify(store.issuanceStatus()).includes('private-account-key'), false);
    assert.throws(() => store.updateDdns({ zoneId: 'bad', enabled: true }), /Zone ID/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('requires referenced certificates for newly saved HTTPS rules', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-cert-ref-'));
  const store = new ConfigStore(directory);
  try {
    store.load();
    assert.throws(() => store.createRule({ name: 'TLS', protocol: 'https', listenPort: 18443, targetProtocol: 'http', tls: { certId: 'missing' } }), /证书不存在/);
    store.addCertificate({ id: 'available-cert', name: 'Available' });
    assert.doesNotThrow(() => store.createRule({ name: 'TLS', protocol: 'https', listenPort: 18443, targetProtocol: 'http', tls: { certId: 'available-cert' } }));
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('rekeys imported rules when merging a backup with existing IDs', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-import-ids-'));
  const store = new ConfigStore(directory);
  try {
    store.load();
    store.createRule({ name: 'Original', protocol: 'tcp', listenPort: 18222, targetProtocol: 'tcp', targetPort: 22 });
    const result = store.importConfig(store.exportConfig(), { replace: false });
    assert.equal(result.rules.length, 2);
    assert.equal(new Set(result.rules.map((rule) => rule.id)).size, 2);
    assert.equal(result.rules.filter((rule) => rule.enabled).length, 1);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('persists CRUD operations atomically', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'reverse-proxy-store-'));
  const store = new ConfigStore(directory);
  store.load();
  const created = store.createRule({ name: 'SSH', protocol: 'tcp', listenPort: 8222, targetProtocol: 'tcp', targetPort: 22 });
  store.updateRule(created.id, { enabled: false });
  const reloaded = new ConfigStore(directory);
  reloaded.load();
  assert.equal(reloaded.rule(created.id).enabled, false);
  reloaded.deleteRule(created.id);
  assert.equal(reloaded.rules().length, 0);
  fs.rmSync(directory, { recursive: true, force: true });
});
