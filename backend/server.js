import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import express from 'express';
import { inspectCertificateFiles, publicCertificateCandidate } from './lib/certificate-parser.js';
import { ConfigStore, listenPortsFor } from './lib/config-store.js';
import { DdnsService } from './lib/ddns-service.js';
import { AliyunZoneDiscovery } from './lib/aliyun-zone-discovery.js';
import { CertificateIssuance } from './lib/certificate-issuance.js';
import { createCertificateRotator } from './lib/certificate-rotation.js';
import { FnosDeploymentService } from './lib/fnos-deployment.js';
import { ProxyManager } from './lib/proxy-manager.js';
import { discoverServices, localHostAliases } from './lib/service-discovery.js';
import { sanitizeCertificate, SystemCertificateStore } from './lib/system-certificate-store.js';
import { WebhookNotifier } from './lib/webhook-notifier.js';

const PORT = Number(process.env.PORT || 5099);
const SOCKET_PATH = process.env.SOCKET_PATH || '';
const GATEWAY_PREFIX = (process.env.GATEWAY_PREFIX || '/app/reverse-proxy').replace(/\/$/, '');
const DATA_DIR = process.env.DATA_DIR || path.join(import.meta.dirname, '.data');
const FRONTEND_DIST = process.env.FRONTEND_DIST || path.join(import.meta.dirname, '..', 'build', 'web');
const DEMO_MODE = /^(1|true|yes)$/i.test(process.env.DEMO_MODE || '');
const APP_VERSION = '1.0.16';
const startedAt = Date.now();
const LOG_LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const MAX_LOG_BYTES = 5 * 1024 * 1024;

fs.mkdirSync(DATA_DIR, { recursive: true });

class AppLogger {
  constructor(file) {
    this.file = file;
    this.entries = [];
    try {
      this.entries = fs.readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).slice(-1500).reverse().map((line) => JSON.parse(line));
    } catch {}
  }
  setLevel(level) { this.level = Object.hasOwn(LOG_LEVELS, level) ? level : 'info'; }
  rotateIfNeeded() {
    try {
      if (fs.statSync(this.file).size < MAX_LOG_BYTES) return;
      const archive = `${this.file}.1`;
      fs.rmSync(archive, { force: true });
      fs.renameSync(this.file, archive);
    } catch {}
  }
  write(level, message, meta = {}) {
    if ((LOG_LEVELS[level] || LOG_LEVELS.info) < (LOG_LEVELS[this.level] || LOG_LEVELS.info)) return null;
    const entry = { id: randomUUID(), at: new Date().toISOString(), level, message, meta };
    this.entries.unshift(entry);
    this.entries = this.entries.slice(0, 1500);
    this.rotateIfNeeded();
    try { fs.appendFileSync(this.file, `${JSON.stringify(entry)}\n`, { mode: 0o600 }); } catch {}
    return entry;
  }
  debug(message, meta) { return this.write('debug', message, meta); }
  info(message, meta) { return this.write('info', message, meta); }
  warn(message, meta) { return this.write('warn', message, meta); }
  error(message, meta) { return this.write('error', message, meta); }
  list({ level = 'all', search = '', limit = 300 } = {}) {
    const needle = String(search).toLowerCase();
    return this.entries.filter((entry) => (level === 'all' || entry.level === level) && (!needle || `${entry.message} ${JSON.stringify(entry.meta)}`.toLowerCase().includes(needle))).slice(0, Math.min(1000, Math.max(1, Number(limit) || 300)));
  }
  clear() { this.entries = []; try { fs.writeFileSync(this.file, '', { mode: 0o600 }); } catch {} }
}

const logger = new AppLogger(path.join(DATA_DIR, 'app.log'));
const systemCertificates = new SystemCertificateStore({ logger });
await systemCertificates.start();
const reservedPorts = SOCKET_PATH ? [] : [PORT];
const store = new ConfigStore(DATA_DIR, { demoMode: DEMO_MODE, systemCertificates, localHosts: localHostAliases(), reservedPorts });
store.load();
logger.setLevel(store.settings().logLevel);
const webhookNotifier = new WebhookNotifier({ store, logger });
const manager = new ProxyManager({ store, logger, demoMode: DEMO_MODE, notifier: webhookNotifier });
const startupResult = await manager.startAll();
if (!startupResult.ok) logger.warn('部分代理规则启动失败', { failures: startupResult.failures });
systemCertificates.on('changed', ({ reason, certificateIds }) => {
  if (reason === 'manual') return;
  void manager.reloadTlsCertificates(certificateIds).then(
    (result) => {
      if (result.ok) logger.info('系统证书变化已热更新到 HTTPS / WSS 规则', { updated: result.updated, reason });
      else logger.warn('部分 HTTPS / WSS 规则未能应用系统证书更新', { failures: result.failures, reason });
      void webhookNotifier.send('certificate.updated', { source: 'fnos', reason, certificateIds, tlsUpdated: result.updated, ok: result.ok });
    },
    (error) => logger.error('系统证书变化应用失败', { error: error.message }),
  );
});

const app = express();
app.disable('x-powered-by');

const asyncRoute = (handler) => async (req, res, next) => { try { await handler(req, res, next); } catch (error) { next(error); } };
const router = express.Router();
router.use(express.json({ limit: '16mb' }));
router.use(express.urlencoded({ extended: true, limit: '16mb' }));

const disableApiCaching = (req, res, next) => {
  res.set('Cache-Control', 'no-store');
  return next();
};

// Only trust fnOS identity headers on the Unix socket registered with the
// unified gateway. The local TCP development server deliberately does not use
// these headers, so a browser cannot expand its privileges by forging them.
const requireGatewayAdmin = (req, res, next) => {
  const userId = req.get('X-Trim-Userid');
  if (typeof userId !== 'string' || !userId.trim()) {
    return res.status(401).json({ error: '需要通过 fnOS 登录后访问' });
  }
  const isAdmin = req.get('X-Trim-Isadmin');
  if (typeof isAdmin !== 'string' || isAdmin.toLowerCase() !== 'true') {
    return res.status(403).json({ error: '仅 fnOS 管理员可访问' });
  }
  res.locals.gatewayIdentity = Object.freeze({ userId: userId.trim(), isAdmin: true });
  return next();
};

const discardUntrustedGatewayIdentity = (req, res, next) => {
  delete req.headers['x-trim-userid'];
  delete req.headers['x-trim-isadmin'];
  return next();
};

router.get('/status', (req, res) => {
  const snapshot = manager.snapshot();
  const rules = store.rules();
  const runtimeValues = Object.values(snapshot.rules);
  res.json({
    ok: true,
    demoMode: DEMO_MODE,
    version: APP_VERSION,
    uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000),
    rules: {
      total: rules.length,
      enabled: rules.filter((rule) => rule.enabled).length,
      healthy: runtimeValues.filter((runtime) => runtime.state === 'healthy').length,
      warning: runtimeValues.filter((runtime) => ['warning', 'error'].includes(runtime.state)).length,
    },
    ports: [...new Set(rules.filter((rule) => rule.enabled).flatMap((rule) => listenPortsFor(rule)))].sort((a, b) => a - b),
    runtime: snapshot,
  });
});

router.get('/rules', (req, res) => res.json({ rules: store.rules(), runtime: manager.snapshot().rules }));
router.get('/discovery/services', asyncRoute(async (req, res) => {
  const result = await discoverServices({ rules: store.rules(), demoMode: DEMO_MODE, reservedPorts });
  res.json(result);
}));
router.post('/rules', asyncRoute(async (req, res) => {
  const rule = store.createRule(req.body);
  await manager.reload();
  const runtime = manager.snapshot().rules[rule.id];
  const ok = runtime?.state !== 'error';
  logger[ok ? 'info' : 'warn'](ok ? '已创建代理规则' : '代理规则已保存但启动失败', { ruleId: rule.id, rule: rule.name, error: ok ? undefined : runtime?.message });
  res.status(201).json({ ok, rule, runtime, warning: ok ? null : `规则已保存，但启动失败：${runtime?.message || '未知错误'}` });
}));
router.put('/rules/:id', asyncRoute(async (req, res) => {
  const rule = store.updateRule(req.params.id, req.body);
  await manager.reload();
  const runtime = manager.snapshot().rules[rule.id];
  const ok = runtime?.state !== 'error';
  logger[ok ? 'info' : 'warn'](ok ? '已更新代理规则' : '代理规则已更新但启动失败', { ruleId: rule.id, rule: rule.name, error: ok ? undefined : runtime?.message });
  res.json({ ok, rule, runtime, warning: ok ? null : `规则已保存，但启动失败：${runtime?.message || '未知错误'}` });
}));
router.post('/rules/:id/toggle', asyncRoute(async (req, res) => {
  const current = store.rule(req.params.id);
  if (!current) { const error = new Error('规则不存在'); error.status = 404; throw error; }
  const rule = store.updateRule(req.params.id, { enabled: req.body.enabled ?? !current.enabled });
  await manager.reload();
  const runtime = manager.snapshot().rules[rule.id];
  const ok = runtime?.state !== 'error';
  logger[ok ? 'info' : 'warn'](ok ? (rule.enabled ? '已启用代理规则' : '已停用代理规则') : '代理规则状态已保存但启动失败', { ruleId: rule.id, rule: rule.name, error: ok ? undefined : runtime?.message });
  res.json({ ok, rule, runtime, warning: ok ? null : `规则状态已保存，但启动失败：${runtime?.message || '未知错误'}` });
}));
router.post('/rules/:id/duplicate', asyncRoute(async (req, res) => {
  const rule = store.duplicateRule(req.params.id);
  await manager.reload();
  const runtime = manager.snapshot().rules[rule.id];
  logger.info('已复制代理规则', { ruleId: rule.id, rule: rule.name });
  res.status(201).json({ ok: true, rule, runtime });
}));
router.delete('/rules/:id', asyncRoute(async (req, res) => { const rule = store.deleteRule(req.params.id); const reload = await manager.reload(); logger.warn('已删除代理规则', { ruleId: rule.id, rule: rule.name }); res.json({ ok: reload.ok, rule, warning: reload.ok ? null : '规则已删除，但其他规则中仍有启动失败项' }); }));
router.post('/rules/batch', asyncRoute(async (req, res) => {
  const result = store.batchRules(req.body.ids, req.body.action);
  const reload = await manager.reload();
  logger.info('已完成批量规则操作', { action: result.action, affected: result.affected.map((rule) => rule.id) });
  res.json({ ok: reload.ok, ...result, runtime: reload.runtime, warning: reload.ok ? null : '批量操作已保存，但部分规则启动失败' });
}));
router.post('/rules/:id/test', asyncRoute(async (req, res) => { const rule = store.rule(req.params.id); if (!rule) { const error = new Error('规则不存在'); error.status = 404; throw error; } const runtime = await manager.checkRule(rule); res.json({ runtime: manager.publicRuntime(runtime) }); }));
router.post('/reload', asyncRoute(async (req, res) => { const result = await manager.reload(); logger[result.ok ? 'info' : 'warn'](result.ok ? '全部代理规则已重新加载' : '代理规则重新加载完成，但部分规则启动失败', { failures: result.failures }); res.json({ ok: result.ok, failures: result.failures, runtime: result.runtime }); }));

router.get('/certificates', (req, res) => res.json({
  certificates: store.certificates(),
  sources: { system: systemCertificates.status() },
}));
const saveCertificateCandidate = (candidate) => {
  const id = candidate.id || randomUUID();
  const certPath = path.join(store.certDir, `${id}.crt`);
  const keyPath = path.join(store.certDir, `${id}.key`);
  fs.writeFileSync(certPath, candidate.certificatePem, { mode: 0o600 });
  fs.writeFileSync(keyPath, candidate.privateKeyPem, { mode: 0o600 });
  const certificate = store.addCertificate({ ...publicCertificateCandidate({ ...candidate, id }), certPath, keyPath, createdAt: new Date().toISOString() });
  return sanitizeCertificate(certificate);
};

const savePushedCertificateCandidate = (candidate) => {
  const duplicate = store.data.certificates.find((certificate) => certificate.fingerprint && certificate.fingerprint === candidate.fingerprint);
  if (duplicate) return { action: 'unchanged', certificate: sanitizeCertificate(duplicate), previousFiles: [] };
  const replacing = store.matchingManualCertificate(candidate);
  const id = replacing?.id || candidate.id || randomUUID();
  const suffix = replacing ? `-${Date.now()}` : '';
  const certPath = path.join(store.certDir, `${id}${suffix}.crt`);
  const keyPath = path.join(store.certDir, `${id}${suffix}.key`);
  fs.writeFileSync(certPath, candidate.certificatePem, { mode: 0o600 });
  fs.writeFileSync(keyPath, candidate.privateKeyPem, { mode: 0o600 });
  const stored = { ...publicCertificateCandidate({ ...candidate, id }), certPath, keyPath, createdAt: replacing?.createdAt || new Date().toISOString() };
  const certificate = replacing ? store.replaceManualCertificate(id, stored) : store.addCertificate(stored);
  return { action: replacing ? 'replaced' : 'created', certificate: sanitizeCertificate(certificate), previousFiles: replacing ? [replacing.certPath, replacing.keyPath].filter(Boolean) : [] };
};

const applyAutomatedCertificate = createCertificateRotator({ store, manager, notifier: webhookNotifier });
const ddnsService = new DdnsService({ store, logger, demoMode: DEMO_MODE });
const aliyunZoneDiscovery = new AliyunZoneDiscovery({ store, demoMode: DEMO_MODE });
const fnosDeployment = new FnosDeploymentService({ store, logger, demoMode: DEMO_MODE, onDeployed: () => systemCertificates.reload({ reason: 'deployment' }) });
const certificateIssuance = new CertificateIssuance({ store, logger, demoMode: DEMO_MODE, onCertificate: applyAutomatedCertificate });

router.get('/integrations/certificate-push', (req, res) => res.json({ integration: store.certificatePushStatus() }));
router.post('/integrations/certificate-push/rotate', (req, res) => {
  const integration = store.rotateCertificatePush();
  logger.warn('已重新生成证书推送凭据', { bindingId: integration.bindingId });
  res.status(201).json({ integration });
});
router.delete('/integrations/certificate-push', (req, res) => {
  const integration = store.disableCertificatePush();
  logger.warn('已停用外部证书推送');
  res.json({ integration });
});
router.get('/integrations/webhook', (req, res) => res.json({ integration: store.webhookStatus() }));
router.put('/integrations/webhook', (req, res) => {
  const integration = store.updateWebhook(req.body);
  logger.info('Webhook 通知设置已更新', { enabled: integration.enabled, events: integration.events, headerNames: integration.headerNames });
  res.json({ integration });
});
router.post('/integrations/webhook/test', asyncRoute(async (req, res) => {
  const result = await webhookNotifier.test();
  if (!result.ok) return res.status(502).json({ error: `Webhook 测试失败：${result.error}` });
  res.json({ ok: true, status: result.status });
}));
router.get('/integrations/ddns', (req, res) => res.json({ integration: { ...store.ddnsStatus(), detection: ddnsService.detectionStatus(), running: Boolean(ddnsService.running), demoMode: DEMO_MODE } }));
for (const scope of ['ddns', 'certificate-issuance']) {
  // Read-only draft lookup: never save credentials, consume quota, or change DNS.
  router.post(`/integrations/${scope}/aliyun/resolve-zone`, asyncRoute(async (req, res) => {
    res.json({ result: await aliyunZoneDiscovery.resolve(scope, req.body) });
  }));
}
router.post('/integrations/ddns/detect', asyncRoute(async (req, res) => {
  const result = await ddnsService.detect(req.body?.recordType);
  res.json({ result, detection: ddnsService.detectionStatus() });
}));
router.put('/integrations/ddns', (req, res) => {
  if (ddnsService.running) return res.status(409).json({ error: 'DDNS 正在同步，请稍后保存' });
  res.json({ integration: store.updateDdns(req.body) });
});
router.post('/integrations/ddns/sync', asyncRoute(async (req, res) => {
  if (ddnsService.running) return res.status(409).json({ error: 'DDNS 正在处理，请稍后重试' });
  const result = await ddnsService.sync();
  res.json({ result, integration: store.ddnsStatus() });
}));
router.post('/integrations/ddns/test', asyncRoute(async (req, res) => {
  if (ddnsService.running) return res.status(409).json({ error: 'DDNS 正在处理，请稍后重试' });
  const result = await ddnsService.test();
  res.json({ result, integration: store.ddnsStatus() });
}));
router.get('/integrations/certificate-issuance', (req, res) => res.json({ integration: certificateIssuance.status() }));
router.get('/integrations/fnos-deployment', (req, res) => res.json({ integration: fnosDeployment.status() }));
router.put('/integrations/fnos-deployment', (req, res) => res.json({ integration: fnosDeployment.update(req.body) }));
router.post('/integrations/fnos-deployment/refresh', asyncRoute(async (req, res) => res.json({ integration: await fnosDeployment.refresh() })));
router.post('/integrations/fnos-deployment/prepare', asyncRoute(async (req, res) => res.json({ preview: await fnosDeployment.prepare() })));
router.post('/integrations/fnos-deployment/deploy', (req, res) => res.status(202).json({ result: fnosDeployment.kick(req.body), integration: fnosDeployment.status() }));
router.put('/integrations/certificate-issuance', (req, res) => {
  if (certificateIssuance.running.size) return res.status(409).json({ error: '证书任务正在处理，请稍后保存' });
  store.updateIssuance(req.body);
  res.json({ integration: certificateIssuance.status() });
});
router.post('/integrations/certificate-issuance/issue', (req, res) => {
  const result = certificateIssuance.kick();
  res.status(202).json({ result, integration: certificateIssuance.status() });
});
router.post('/integrations/certificate-issuance/aliyun/quota', asyncRoute(async (req, res) => {
  const result = await certificateIssuance.refreshQuota();
  res.json({ result, integration: certificateIssuance.status() });
}));
router.post('/integrations/certificate-issuance/aliyun/associate', (req, res) => {
  certificateIssuance.associateOrder(req.body.orderId);
  res.json({ integration: certificateIssuance.status() });
});
router.post('/integrations/certificate-issuance/aliyun/reset', (req, res) => {
  certificateIssuance.resetUncertain(req.body.confirmedNoOrder);
  res.json({ integration: certificateIssuance.status() });
});
router.post('/integrations/certificate-issuance/aliyun/retry', asyncRoute(async (req, res) => {
  // Only an explicit manual retry may replace a rejected order.
  await certificateIssuance.retryFailed();
  res.json({ integration: certificateIssuance.status() });
}));

const externalCertificatePush = asyncRoute(async (req, res) => {
  const authorization = String(req.get('Authorization') || '');
  const token = authorization.match(/^Bearer\s+(.+)$/i)?.[1]?.trim();
  if (!store.verifyCertificatePush(req.params.bindingId, token)) return res.status(401).json({ error: '证书推送凭据无效' });
  let files = Array.isArray(req.body.files) ? req.body.files : [];
  if (!files.length && req.body.certificate && req.body.privateKey) {
    files = [
      { name: `${String(req.body.name || 'certificate')}.pem`, data: Buffer.from(String(req.body.certificate)).toString('base64') },
      { name: `${String(req.body.name || 'certificate')}.key`, data: Buffer.from(String(req.body.privateKey)).toString('base64') },
    ];
  }
  if (!files.length) { const error = new Error('请提供 files，或 certificate 与 privateKey'); error.status = 400; throw error; }
  const parsed = inspectCertificateFiles(files, { passphrase: String(req.body.passphrase || ''), name: String(req.body.name || '') });
  const results = parsed.candidates.map((candidate) => savePushedCertificateCandidate({ ...candidate, automation: { provider: 'push' } }));
  const changedIds = results.filter((result) => result.action !== 'unchanged').map((result) => result.certificate.id);
  const tlsReload = changedIds.length ? await manager.reloadTlsCertificates(changedIds) : { ok: true, updated: 0, failures: [] };
  for (const result of results) {
    if (result.action === 'replaced') for (const previousFile of result.previousFiles) { try { fs.unlinkSync(previousFile); } catch {} }
  }
  store.markCertificatePushUsed();
  logger.info('已接收外部证书推送', { bindingId: req.params.bindingId, certificates: results.map((result) => ({ id: result.certificate.id, name: result.certificate.name, action: result.action })), tlsUpdated: tlsReload.updated });
  for (const result of results.filter((item) => item.action !== 'unchanged')) void webhookNotifier.send('certificate.updated', { source: 'push', certificateId: result.certificate.id, name: result.certificate.name, action: result.action, tlsUpdated: tlsReload.updated, ok: tlsReload.ok });
  res.status(results.some((result) => result.action === 'created') ? 201 : 200).json({ ok: tlsReload.ok, certificates: results.map((result) => ({ ...result.certificate, action: result.action })), warnings: parsed.warnings, tlsReload });
});

router.get('/certificates/system/status', (req, res) => res.json({ status: systemCertificates.status() }));
router.post('/certificates/system/reload', asyncRoute(async (req, res) => {
  const result = await systemCertificates.reload({ reason: 'manual' });
  const certificateIds = result.certificateIds || systemCertificates.certificates().map((certificate) => certificate.id);
  const tlsReload = await manager.reloadTlsCertificates(certificateIds);
  const ok = result.status.state === 'ready' && tlsReload.ok;
  logger[ok ? 'info' : 'warn'](ok ? '已手动刷新 fnOS 系统证书' : 'fnOS 系统证书刷新完成，但存在未应用项', {
    loaded: result.status.certificateCount,
    state: result.status.state,
    usingLastKnownGood: result.status.usingLastKnownGood,
    failures: tlsReload.failures,
  });
  res.json({ ok, status: result.status, certificates: result.certificates, tlsReload, runtime: tlsReload.runtime });
}));

router.post('/certificates/inspect', asyncRoute(async (req, res) => {
  const result = inspectCertificateFiles(req.body.files, { passphrase: String(req.body.passphrase || ''), name: String(req.body.name || '') });
  res.json({ candidates: result.candidates.map(publicCertificateCandidate), warnings: result.warnings });
}));

router.post('/certificates/import', asyncRoute(async (req, res) => {
  const result = inspectCertificateFiles(req.body.files, { passphrase: String(req.body.passphrase || ''), name: String(req.body.name || '') });
  // A system-managed copy must not block creating an app-owned fallback.
  // Only app-owned certificates participate in import de-duplication.
  const existing = store.manualCertificateFingerprints();
  const imported = [];
  const skipped = [];
  for (const candidate of result.candidates) {
    if (existing.has(candidate.fingerprint)) { skipped.push(`${candidate.name} 已存在`); continue; }
    imported.push(saveCertificateCandidate(candidate));
    existing.add(candidate.fingerprint);
  }
  logger.info('已批量导入 HTTPS 证书', { imported: imported.length, skipped: skipped.length, formats: [...new Set(imported.map((certificate) => certificate.format))] });
  for (const certificate of imported) void webhookNotifier.send('certificate.updated', { source: 'manual', certificateId: certificate.id, name: certificate.name, action: 'created' });
  res.status(imported.length ? 201 : 200).json({ certificates: imported, warnings: [...result.warnings, ...skipped] });
}));

router.post('/certificates', asyncRoute(async (req, res) => {
  const name = String(req.body.name || '').trim();
  const certificatePem = String(req.body.certificate || '').trim();
  const privateKeyPem = String(req.body.privateKey || '').trim();
  if (!name || !certificatePem || !privateKeyPem) { const error = new Error('请填写证书名称、证书内容和私钥'); error.status = 400; throw error; }
  let result;
  try {
    result = inspectCertificateFiles([
      { name: `${name}.pem`, data: Buffer.from(certificatePem).toString('base64') },
      { name: `${name}.key`, data: Buffer.from(privateKeyPem).toString('base64') },
    ], { name });
  } catch (cause) { const error = new Error(`证书或私钥无效：${cause.message}`); error.status = 400; throw error; }
  const certificate = saveCertificateCandidate(result.candidates[0]);
  logger.info('已添加 HTTPS 证书', { certificateId: certificate.id, name: certificate.name });
  void webhookNotifier.send('certificate.updated', { source: 'manual', certificateId: certificate.id, name: certificate.name, action: 'created' });
  res.status(201).json({ certificate });
}));
router.put('/certificates/:id', asyncRoute(async (req, res) => {
  const previous = store.data.certificates.find((cert) => cert.id === req.params.id && cert.source !== 'system');
  if (!previous) throw Object.assign(new Error('只能替换应用管理的证书，系统证书保持只读'), { status: 404 });
  const files = req.body.kind === 'files' ? req.body.files : [
    { name: 'replacement.pem', data: Buffer.from(String(req.body.certificate || '')).toString('base64') },
    { name: 'replacement.key', data: Buffer.from(String(req.body.privateKey || '')).toString('base64') },
  ];
  const parsed = inspectCertificateFiles(files, { passphrase: String(req.body.passphrase || ''), name: previous.name });
  if (parsed.candidates.length !== 1) throw Object.assign(new Error('每次替换请选择一套证书和对应私钥'), { status: 400 });
  const candidate = parsed.candidates[0];
  const domains = [...new Set([...(previous.subjectAltNames || []), ...store.rules().filter((rule) => rule.tls?.certId === previous.id).flatMap((rule) => rule.domains || [])])];
  if (!domains.length) throw Object.assign(new Error('原证书缺少可核验域名，无法安全替换'), { status: 400 });
  const result = await applyAutomatedCertificate({ name: previous.name, certificatePem: candidate.certificatePem, privateKeyPem: candidate.privateKeyPem,
    domains, targetCertificateId: previous.id, strictTarget: true, environment: previous.automation?.environment || 'production', provider: 'manual' });
  logger.info('证书已替换并应用到关联规则', { certificateId: previous.id, updated: result.tlsReload.updated });
  res.json(result);
}));

router.delete('/certificates/:id', asyncRoute(async (req, res) => {
  const inUse = store.rules().some((rule) => rule.tls.certId === req.params.id);
  if (inUse) { const error = new Error('证书正在被代理规则使用，请先更换规则证书'); error.status = 409; throw error; }
  const certificate = store.removeCertificate(req.params.id);
  for (const file of [certificate.certPath, certificate.keyPath]) { try { fs.unlinkSync(file); } catch {} }
  logger.warn('已删除 HTTPS 证书', { certificateId: certificate.id, name: certificate.name });
  res.json({ ok: true });
}));

router.get('/logs', (req, res) => res.json({ entries: logger.list({ level: req.query.level, search: req.query.search, limit: req.query.limit }) }));
router.delete('/logs', (req, res) => { if (req.query.confirm !== 'clear') return res.status(400).json({ error: '需要明确确认清空日志' }); logger.clear(); logger.info('诊断日志已清空'); res.json({ ok: true }); });

router.get('/settings', (req, res) => res.json({ settings: store.settings() }));
router.put('/settings', asyncRoute(async (req, res) => { const settings = store.updateSettings(req.body); logger.setLevel(settings.logLevel); await manager.reload(); logger.info('应用设置已更新', settings); res.json({ settings }); }));

router.get('/export', (req, res) => { res.setHeader('Content-Disposition', `attachment; filename="reverse-proxy-${new Date().toISOString().slice(0, 10)}.json"`); res.json(store.exportConfig()); });
router.post('/import', asyncRoute(async (req, res) => { const result = store.importConfig(req.body.config || req.body, { replace: Boolean(req.body.replace) }); await manager.reload(); logger.info('代理配置已导入', { imported: result.imported, replace: Boolean(req.body.replace) }); res.json(result); }));

router.get('/network', (req, res) => {
  const interfaces = [];
  for (const [name, addresses] of Object.entries(os.networkInterfaces())) {
    for (const address of addresses || []) if (!address.internal) interfaces.push({ name, address: address.address, family: address.family, cidr: address.cidr });
  }
  res.json({ hostname: os.hostname(), interfaces });
});

router.get('/diagnostics', (req, res) => res.json({ generatedAt: new Date().toISOString(), platform: process.platform, architecture: process.arch, node: process.version, hostname: os.hostname(), uptimeSeconds: Math.floor((Date.now() - startedAt) / 1000), gatewayPrefix: GATEWAY_PREFIX, demoMode: DEMO_MODE, settings: store.settings(), certificateSources: { system: systemCertificates.status() }, rules: store.rules(), runtime: manager.snapshot(), recentLogs: logger.list({ limit: 80 }) }));

const pushJson = express.json({ limit: '16mb' });
app.put(`${GATEWAY_PREFIX}/api/integrations/certificates/:bindingId`, disableApiCaching, pushJson, externalCertificatePush);
if (!SOCKET_PATH) app.put('/api/integrations/certificates/:bindingId', disableApiCaching, pushJson, externalCertificatePush);

if (SOCKET_PATH) {
  app.use(`${GATEWAY_PREFIX}/api`, disableApiCaching, requireGatewayAdmin, router);
} else {
  app.use('/api', disableApiCaching, discardUntrustedGatewayIdentity, router);
  app.use(`${GATEWAY_PREFIX}/api`, disableApiCaching, discardUntrustedGatewayIdentity, router);
}

if (fs.existsSync(path.join(FRONTEND_DIST, 'index.html'))) {
  app.use(GATEWAY_PREFIX, express.static(FRONTEND_DIST));
  app.get(`${GATEWAY_PREFIX}/*`, (req, res) => res.sendFile(path.join(FRONTEND_DIST, 'index.html')));
  app.use(express.static(FRONTEND_DIST));
  app.get('/', (req, res) => res.redirect(`${GATEWAY_PREFIX}/`));
}

app.use((error, req, res, next) => {
  logger.error('API 请求失败', { method: req.method, path: req.path, error: error.message });
  res.status(error.status || 500).json({ error: error.message || '内部服务错误', details: error.details });
});

const expiryNotifications = new Set();
const checkCertificateExpiry = () => {
  const current = Date.now();
  for (const certificate of store.certificates()) {
    const expiresAt = new Date(certificate.validTo).getTime();
    const days = Number.isFinite(expiresAt) ? Math.ceil((expiresAt - current) / 86400000) : null;
    const key = `${certificate.id}:${certificate.validTo}`;
    if (days !== null && days > 0 && days <= 30 && !expiryNotifications.has(key)) {
      expiryNotifications.add(key);
      void webhookNotifier.send('certificate.expiring', { certificateId: certificate.id, name: certificate.name, validTo: certificate.validTo, daysRemaining: days, source: certificate.source || 'manual' });
    }
  }
};
const certificateExpiryTimer = setInterval(checkCertificateExpiry, 6 * 60 * 60 * 1000);
certificateExpiryTimer.unref?.();
checkCertificateExpiry();
ddnsService.start();
fnosDeployment.start();
certificateIssuance.start();

const server = http.createServer(app);
if (SOCKET_PATH) {
  try { fs.unlinkSync(SOCKET_PATH); } catch {}
  server.listen(SOCKET_PATH, () => logger.info('管理服务已通过统一网关启动', { socket: SOCKET_PATH, gatewayPrefix: GATEWAY_PREFIX }));
} else {
  server.listen(PORT, '127.0.0.1', () => logger.info('本地管理服务已启动', { url: `http://127.0.0.1:${PORT}${GATEWAY_PREFIX}/`, demoMode: DEMO_MODE }));
}

async function shutdown(signal) {
  if (shutdown.started) return;
  shutdown.started = true;
  logger.info('正在停止反向代理服务', { signal });
  systemCertificates.stop();
  ddnsService.stop();
  fnosDeployment.stop();
  certificateIssuance.stop();
  clearInterval(certificateExpiryTimer);
  const forceExit = setTimeout(() => process.exit(1), 5000);
  forceExit.unref();
  const closeManagement = new Promise((resolve) => {
    try {
      server.close(resolve);
      server.closeAllConnections?.();
    } catch { resolve(); }
  });
  await Promise.allSettled([manager.stopAll(), closeManagement]);
  clearTimeout(forceExit);
  process.exit(0);
}
shutdown.started = false;
process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));
