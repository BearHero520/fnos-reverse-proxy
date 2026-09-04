import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import os from 'node:os';
import path from 'node:path';
import test from 'node:test';
import forge from 'node-forge';
import { ConfigStore } from '../lib/config-store.js';
import { ProxyManager } from '../lib/proxy-manager.js';
import { SystemCertificateStore } from '../lib/system-certificate-store.js';

const logger = { debug() {}, info() {}, warn() {}, error() {} };

function certificateFixture(domain = 'system.example.test', {
  validFrom = new Date(Date.now() - 60_000),
  validTo = new Date(Date.now() + 365 * 86_400_000),
} = {}) {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = String(Math.floor(Math.random() * 1_000_000) + 1);
  certificate.validity.notBefore = validFrom;
  certificate.validity.notAfter = validTo;
  const attributes = [{ name: 'commonName', value: domain }];
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes);
  certificate.setExtensions([{ name: 'subjectAltName', altNames: [
    { type: 2, value: domain },
    { type: 2, value: `alt.${domain}` },
  ] }]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  return {
    certPem: forge.pki.certificateToPem(certificate),
    keyPem: forge.pki.privateKeyToPem(keys.privateKey),
  };
}

function writeInventory(directory, entries) {
  const file = path.join(directory, 'network_cert_all.conf');
  fs.writeFileSync(file, `${JSON.stringify(entries, null, 2)}\n`);
  return file;
}

function writeMaterial(directory, name, fixture) {
  const certificate = path.join(directory, `${name}.fullchain.pem`);
  const privateKey = path.join(directory, `${name}.key`);
  fs.writeFileSync(certificate, fixture.certPem);
  fs.writeFileSync(privateKey, fixture.keyPem);
  return { certificate, privateKey };
}

function listen(server, port = 0) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(port, '127.0.0.1', () => {
      server.off('error', reject);
      resolve(server.address().port);
    });
  });
}

function close(server) {
  return new Promise((resolve) => {
    if (!server?.listening) return resolve();
    server.close(resolve);
  });
}

function httpsRequest(port) {
  return new Promise((resolve, reject) => {
    const request = https.get({
      host: '127.0.0.1',
      port,
      path: '/from-system',
      servername: 'system.example.test',
      headers: { Host: 'system.example.test' },
      rejectUnauthorized: false,
    }, (response) => {
      const chunks = [];
      response.on('data', (chunk) => chunks.push(chunk));
      response.on('end', () => resolve({ status: response.statusCode, body: Buffer.concat(chunks).toString() }));
    });
    request.once('error', reject);
  });
}

function peerFingerprint(port) {
  return new Promise((resolve, reject) => {
    const agent = new https.Agent({ maxCachedSessions: 0 });
    const request = https.get({ host: '127.0.0.1', port, servername: 'system.example.test', rejectUnauthorized: false, agent }, (response) => {
      const fingerprint = response.socket.getPeerCertificate().fingerprint256;
      response.resume();
      response.on('end', () => { agent.destroy(); resolve(fingerprint); });
    });
    request.once('error', (error) => { agent.destroy(); reject(error); });
  });
}

test('loads fnOS certificate metadata from X509 while keeping paths and key material private', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-load-'));
  try {
    const fixture = certificateFixture();
    const material = writeMaterial(directory, 'system', fixture);
    const configPath = writeInventory(directory, [{
      domain: 'configured.example.invalid',
      san: ['configured-san.example.invalid'],
      certificate: path.join(directory, 'unused.crt'),
      fullchain: material.certificate,
      privateKey: material.privateKey,
      used: '1',
      appFlag: ['trim-connect', 'reverse-proxy'],
      validFrom: '2000-01-01T00:00:00Z',
      validTo: '2001-01-01T00:00:00Z',
    }]);
    const source = new SystemCertificateStore({ configPath, logger });
    const result = await source.reload();
    assert.equal(result.status.state, 'ready');
    assert.equal(result.status.certificateCount, 1);
    const certificate = result.certificates[0];
    assert.equal(certificate.source, 'system');
    assert.equal(certificate.managed, true);
    assert.equal(certificate.deletable, false);
    assert.equal(certificate.name, 'system.example.test');
    assert.deepEqual(certificate.subjectAltNames, ['system.example.test', 'alt.system.example.test']);
    assert.equal(certificate.configuredDomain, 'configured.example.invalid');
    assert.deepEqual(certificate.configuredSan, ['configured-san.example.invalid']);
    assert.equal(certificate.used, true);
    assert.deepEqual(certificate.appFlag, ['trim-connect', 'reverse-proxy']);
    assert.notEqual(certificate.validFrom, certificate.configuredValidFrom);
    assert.notEqual(certificate.validTo, certificate.configuredValidTo);
    const serialized = JSON.stringify(result);
    assert.equal(serialized.includes(material.certificate), false);
    assert.equal(serialized.includes(material.privateKey), false);
    assert.equal(serialized.includes('PRIVATE KEY'), false);
    const internal = source.certificate(certificate.id);
    assert.match(internal.certificatePem, /BEGIN CERTIFICATE/);
    assert.match(internal.privateKeyPem, /BEGIN PRIVATE KEY/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('keeps the last-known-good certificate when key loading or config parsing fails', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-lkg-'));
  try {
    const fixture = certificateFixture();
    const other = certificateFixture('other.example.test');
    const material = writeMaterial(directory, 'system', fixture);
    const configPath = writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const source = new SystemCertificateStore({ configPath, logger });
    await source.reload();
    const original = source.certificates()[0];

    fs.writeFileSync(material.privateKey, other.keyPem);
    const mismatched = await source.reload();
    assert.equal(mismatched.status.state, 'degraded');
    assert.equal(mismatched.status.usingLastKnownGood, true);
    assert.equal(mismatched.status.staleCount, 1);
    assert.equal(mismatched.certificates[0].fingerprint, original.fingerprint);
    assert.equal(mismatched.certificates[0].stale, true);
    assert.match(mismatched.certificates[0].lastError, /不匹配/);

    fs.writeFileSync(configPath, '{broken json');
    const malformed = await source.reload();
    assert.equal(malformed.status.state, 'degraded');
    assert.equal(malformed.status.usingLastKnownGood, true);
    assert.equal(malformed.certificates[0].fingerprint, original.fingerprint);
    assert.equal(malformed.certificates[0].stale, true);
    assert.match(malformed.certificates[0].lastError, /无法解析/);
    assert.match(malformed.status.message, /继续使用上一份可用证书/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('retries an unchanged degraded snapshot and clears its stale marker after recovery', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-degraded-retry-'));
  try {
    const fixture = certificateFixture();
    const material = writeMaterial(directory, 'system', fixture);
    const configPath = writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const source = new SystemCertificateStore({ configPath, logger });
    await source.reload();
    const originalRead = source.readBoundedFile.bind(source);
    let failOnce = true;
    source.readBoundedFile = async (file, ...args) => {
      if (file === source.configPath && failOnce) {
        failOnce = false;
        const error = new Error('系统证书配置不可读取（EACCES）');
        error.code = 'EACCES';
        throw error;
      }
      return originalRead(file, ...args);
    };

    const failed = await source.reload();
    assert.equal(failed.status.state, 'degraded');
    assert.equal(failed.status.usingLastKnownGood, true);
    assert.equal(failed.certificates[0].stale, true);
    assert.match(failed.certificates[0].lastError, /EACCES/);

    // No file or mtime changed. Degraded state itself must cause the retry.
    const recovered = await source.refreshIfChanged();
    assert.equal(recovered.status.state, 'ready');
    assert.equal(recovered.status.usingLastKnownGood, false);
    assert.equal(recovered.certificates[0].stale, false);
    assert.equal(recovered.certificates[0].lastError, null);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('retries an unchanged unavailable source and automatically recovers', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-unavailable-retry-'));
  try {
    const fixture = certificateFixture();
    const material = writeMaterial(directory, 'system', fixture);
    const configPath = writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const source = new SystemCertificateStore({ configPath, logger });
    const originalRead = source.readBoundedFile.bind(source);
    let failOnce = true;
    source.readBoundedFile = async (file, ...args) => {
      if (file === source.configPath && failOnce) {
        failOnce = false;
        const error = new Error('系统证书配置不可读取（EACCES）');
        error.code = 'EACCES';
        throw error;
      }
      return originalRead(file, ...args);
    };

    const failed = await source.reload();
    assert.equal(failed.status.state, 'unavailable');
    assert.equal(failed.certificates.length, 0);
    const recovered = await source.refreshIfChanged();
    assert.equal(recovered.status.state, 'ready');
    assert.equal(recovered.status.certificateCount, 1);
    assert.equal(recovered.certificates[0].stale, false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('reports an explicit unavailable state when the fnOS inventory cannot be read', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-missing-'));
  try {
    const source = new SystemCertificateStore({ configPath: path.join(directory, 'missing.conf'), logger });
    const result = await source.reload();
    assert.equal(result.status.state, 'unavailable');
    assert.equal(result.status.available, false);
    assert.equal(result.status.errorCount, 1);
    assert.match(result.status.message, /不可读取/);
    assert.equal(result.certificates.length, 0);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('detects certificate source mtime changes and emits one atomic change event', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-mtime-'));
  try {
    const fixture = certificateFixture();
    const material = writeMaterial(directory, 'system', fixture);
    const configPath = writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey, used: false }]);
    const source = new SystemCertificateStore({ configPath, logger });
    await source.reload();
    const stableId = source.certificates()[0].id;
    let events = 0;
    source.on('changed', () => { events += 1; });
    const unchanged = await source.refreshIfChanged();
    assert.equal(unchanged.changed, false);

    writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey, used: true }]);
    const future = new Date(Date.now() + 5000);
    fs.utimesSync(configPath, future, future);
    const changed = await source.refreshIfChanged();
    assert.equal(changed.changed, true);
    assert.equal(changed.certificates[0].id, stableId);
    assert.equal(changed.certificates[0].used, true);
    assert.equal(events, 1);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('keeps certificate IDs bound to source identity when inventory order changes', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-stable-id-'));
  try {
    const first = writeMaterial(directory, 'first', certificateFixture('first.example.test'));
    const second = writeMaterial(directory, 'second', certificateFixture('second.example.test'));
    const configPath = writeInventory(directory, [
      { fullchain: first.certificate, privateKey: first.privateKey },
      { fullchain: second.certificate, privateKey: second.privateKey },
    ]);
    const source = new SystemCertificateStore({ configPath, logger });
    await source.reload();
    const initial = Object.fromEntries(source.certificates().map((certificate) => [certificate.name, certificate.id]));

    writeInventory(directory, [
      { fullchain: second.certificate, privateKey: second.privateKey },
      { fullchain: first.certificate, privateKey: first.privateKey },
    ]);
    await source.reload();
    const reordered = Object.fromEntries(source.certificates().map((certificate) => [certificate.name, certificate.id]));
    assert.deepEqual(reordered, initial);
    const serialized = JSON.stringify(source.certificates());
    assert.equal(serialized.includes(first.certificate), false);
    assert.equal(serialized.includes(first.privateKey), false);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('marks expired certificates unavailable dynamically and rejects them for new TLS rules', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-expired-'));
  try {
    const fixture = certificateFixture('expired.example.test', {
      validFrom: new Date(Date.now() - 86_400_000),
      validTo: new Date(Date.now() - 1_000),
    });
    const material = writeMaterial(directory, 'expired', fixture);
    const configPath = writeInventory(directory, [{ domain: 'expired.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const systemCertificates = new SystemCertificateStore({ configPath, logger });
    await systemCertificates.reload();
    const certificate = systemCertificates.certificates()[0];
    assert.equal(certificate.status, 'expired');
    assert.equal(certificate.available, false);

    const store = new ConfigStore(path.join(directory, 'data'), { systemCertificates });
    store.load();
    assert.throws(() => store.createRule({
      name: 'Expired TLS',
      protocol: 'https',
      listenPort: 18443,
      targetProtocol: 'http',
      tls: { certId: certificate.id },
    }), /当前不可用/);

    const internal = systemCertificates.certificate(certificate.id);
    internal.validFrom = new Date(Date.now() - 1_000).toISOString();
    internal.validTo = new Date(Date.now() + 60_000).toISOString();
    assert.equal(systemCertificates.certificates()[0].available, true);
    let validityEvent = null;
    systemCertificates.once('changed', (event) => { validityEvent = event; });
    const becameValid = await systemCertificates.refreshIfChanged();
    assert.equal(becameValid.changed, true);
    assert.equal(validityEvent.reason, 'validity');
    internal.validTo = new Date(Date.now() - 1).toISOString();
    assert.equal(systemCertificates.certificates()[0].available, false);
    const becameExpired = await systemCertificates.refreshIfChanged();
    assert.equal(becameExpired.changed, true);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('allows an existing TLS rule to be disabled after its system certificate disappears', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-disable-missing-'));
  try {
    const material = writeMaterial(directory, 'system', certificateFixture());
    const configPath = writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const systemCertificates = new SystemCertificateStore({ configPath, logger });
    await systemCertificates.reload();
    const store = new ConfigStore(path.join(directory, 'data'), { systemCertificates });
    store.load();
    const rule = store.createRule({
      name: 'System TLS',
      protocol: 'https',
      listenPort: 18443,
      targetProtocol: 'http',
      tls: { certId: systemCertificates.certificates()[0].id },
    });
    writeInventory(directory, []);
    await systemCertificates.reload();
    assert.doesNotThrow(() => store.updateRule(rule.id, { enabled: false }));
    assert.equal(store.rule(rule.id).enabled, false);
    assert.throws(() => store.updateRule(rule.id, { enabled: true }), /不存在或当前不可用/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('retries when the inventory changes after it was read instead of accepting a stale signature', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-read-race-'));
  try {
    const first = writeMaterial(directory, 'first', certificateFixture('first.example.test'));
    const second = writeMaterial(directory, 'second', certificateFixture('second.example.test'));
    const configPath = writeInventory(directory, [{ fullchain: first.certificate, privateKey: first.privateKey }]);
    const source = new SystemCertificateStore({ configPath, logger });
    const originalRead = source.readBoundedFile.bind(source);
    let configReads = 0;
    source.readBoundedFile = async (file, ...args) => {
      const buffer = await originalRead(file, ...args);
      if (file === source.configPath && configReads++ === 0) {
        writeInventory(directory, [{ fullchain: second.certificate, privateKey: second.privateKey }]);
        const future = new Date(Date.now() + 5_000);
        fs.utimesSync(configPath, future, future);
      }
      return buffer;
    };
    const result = await source.reload();
    assert.ok(configReads >= 2);
    assert.equal(result.status.state, 'ready');
    assert.equal(result.certificates[0].name, 'second.example.test');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('rejects unrelated certificates in a configured full chain', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-chain-'));
  try {
    const leaf = certificateFixture('leaf.example.test');
    const unrelated = certificateFixture('unrelated.example.test');
    const material = writeMaterial(directory, 'leaf', leaf);
    fs.appendFileSync(material.certificate, unrelated.certPem);
    const configPath = writeInventory(directory, [{ domain: 'leaf.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const source = new SystemCertificateStore({ configPath, logger });
    const result = await source.reload();
    assert.equal(result.status.state, 'degraded');
    assert.equal(result.certificates.length, 0);
    assert.equal(result.status.errors[0].code, 'INVALID_CHAIN');
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('does not repeat unchanged partial-load warnings during automatic recovery', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-log-dedupe-'));
  const warnings = [];
  const sourceLogger = {
    debug() {},
    info() {},
    error() {},
    warn(message, meta) { warnings.push({ message, meta }); },
  };
  try {
    const fixture = certificateFixture('healthy.example.test');
    const material = writeMaterial(directory, 'healthy', fixture);
    const configPath = writeInventory(directory, [
      { domain: 'healthy.example.test', fullchain: material.certificate, privateKey: material.privateKey },
      { domain: 'broken.example.test' },
    ]);
    const source = new SystemCertificateStore({ configPath, logger: sourceLogger });
    const first = await source.reload({ reason: 'startup' });
    const repeated = await source.reload({ reason: 'recovery' });

    assert.equal(first.status.state, 'degraded');
    assert.equal(first.status.certificateCount, 1);
    assert.equal(repeated.changed, false);
    assert.equal(warnings.length, 1);
    assert.equal(warnings[0].message, 'fnOS 系统证书部分加载失败');
    assert.equal(warnings[0].meta.errors[0].certificate, 'broken.example.test');
    assert.equal(warnings[0].meta.errors[0].code, 'MISSING_PATH');

    await source.reload({ reason: 'manual' });
    assert.equal(warnings.length, 2);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('allows HTTPS rules to reference a system certificate and serves TLS with it', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-proxy-'));
  const target = http.createServer((request, response) => response.end(`target:${request.url}`));
  let manager;
  try {
    const fixture = certificateFixture();
    const material = writeMaterial(directory, 'system', fixture);
    const configPath = writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const systemCertificates = new SystemCertificateStore({ configPath, logger });
    await systemCertificates.reload();
    const systemCertificate = systemCertificates.certificates()[0];
    const store = new ConfigStore(path.join(directory, 'data'), { systemCertificates });
    store.load();
    const targetPort = await listen(target);
    const reservation = http.createServer();
    const proxyPort = await listen(reservation);
    await close(reservation);
    const rule = store.createRule({
      name: 'System TLS',
      protocol: 'https',
      listenHost: '127.0.0.1',
      listenPort: proxyPort,
      domains: ['system.example.test'],
      targetProtocol: 'http',
      targetHost: '127.0.0.1',
      targetPort,
      tls: { certId: systemCertificate.id },
    });
    manager = new ProxyManager({ store, logger });
    await manager.startAll();
    assert.equal(manager.snapshot().rules[rule.id].state, 'healthy');
    assert.deepEqual(await httpsRequest(proxyPort), { status: 200, body: 'target:/from-system' });
  } finally {
    await manager?.stopAll();
    await close(target);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('hot-updates active TLS servers and retains the previous context when refresh fails', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-hot-reload-'));
  const target = http.createServer((request, response) => response.end('ok'));
  let manager;
  try {
    const firstFixture = certificateFixture();
    const material = writeMaterial(directory, 'system', firstFixture);
    const configPath = writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const systemCertificates = new SystemCertificateStore({ configPath, logger });
    await systemCertificates.reload();
    const certificateId = systemCertificates.certificates()[0].id;
    const store = new ConfigStore(path.join(directory, 'data'), { systemCertificates });
    store.load();
    const targetPort = await listen(target);
    const reservation = http.createServer();
    const proxyPort = await listen(reservation);
    await close(reservation);
    const rule = store.createRule({
      name: 'Hot TLS',
      protocol: 'https',
      listenHost: '127.0.0.1',
      listenPort: proxyPort,
      targetProtocol: 'http',
      targetHost: '127.0.0.1',
      targetPort,
      tls: { certId: certificateId },
    });
    manager = new ProxyManager({ store, logger });
    await manager.startAll();
    const originalServer = manager.runtimes.get(rule.id).tlsBindings[0].server;
    const originalFingerprint = await peerFingerprint(proxyPort);

    const renewed = certificateFixture();
    fs.writeFileSync(material.certificate, renewed.certPem);
    fs.writeFileSync(material.privateKey, renewed.keyPem);
    const changed = await systemCertificates.reload();
    const applied = await manager.reloadTlsCertificates(changed.certificateIds);
    assert.equal(applied.ok, true);
    assert.equal(applied.results[0].action, 'updated');
    assert.equal(manager.runtimes.get(rule.id).tlsBindings[0].server, originalServer);
    const renewedFingerprint = await peerFingerprint(proxyPort);
    assert.notEqual(renewedFingerprint, originalFingerprint);

    const mismatch = certificateFixture('other.example.test');
    fs.writeFileSync(material.privateKey, mismatch.keyPem);
    const degraded = await systemCertificates.reload();
    const retained = await manager.reloadTlsCertificates(degraded.certificateIds || [certificateId]);
    assert.equal(retained.ok, false);
    assert.equal(retained.failures[0].retainedContext, true);
    assert.equal(manager.runtimes.get(rule.id).tlsBindings[0].server, originalServer);
    assert.equal(await peerFingerprint(proxyPort), renewedFingerprint);
    assert.equal(manager.snapshot().rules[rule.id].state, 'warning');
  } finally {
    await manager?.stopAll();
    await close(target);
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('keeps manual certificates first and excludes system metadata from exports', async () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'fnos-system-cert-priority-'));
  try {
    const fixture = certificateFixture();
    const material = writeMaterial(directory, 'system', fixture);
    const configPath = writeInventory(directory, [{ domain: 'system.example.test', fullchain: material.certificate, privateKey: material.privateKey }]);
    const systemCertificates = new SystemCertificateStore({ configPath, logger });
    await systemCertificates.reload();
    const systemCertificate = systemCertificates.certificates()[0];
    const systemId = systemCertificate.id;
    const store = new ConfigStore(path.join(directory, 'data'), { systemCertificates });
    store.load();
    assert.equal(store.manualCertificateFingerprints().has(systemCertificate.fingerprint), false);
    store.addCertificate({ id: 'manual-id', name: 'Manual certificate', fingerprint: systemCertificate.fingerprint });
    assert.equal(store.manualCertificateFingerprints().has(systemCertificate.fingerprint), true);
    assert.deepEqual(store.certificates().map((certificate) => certificate.source), ['manual', 'system']);
    assert.equal(store.certificates().filter((certificate) => certificate.fingerprint === systemCertificate.fingerprint).length, 2);
    assert.equal(store.certificate('manual-id').name, 'Manual certificate');
    assert.match(store.certificate(systemId).privateKeyPem, /BEGIN PRIVATE KEY/);
    assert.deepEqual(store.exportConfig().certificates.map((certificate) => certificate.id), ['manual-id']);
    assert.throws(() => store.removeCertificate(systemId), /系统管理/);
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});
