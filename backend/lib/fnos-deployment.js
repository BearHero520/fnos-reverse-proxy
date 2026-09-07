import fs from 'node:fs';
import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { DEPLOY_ERRORS, DEPLOY_STAGES, deployError, inspectDeploymentCertificate } from './fnos-deployment-engine.js';

const defaults = () => ({ certificateId: '', targetId: '', probeHost: '', probePort: 5667, autoDeploy: false, expectedFingerprint: '', lastFingerprint: '', lastSuccessAt: null, lastAttemptAt: null, lastError: null, lastResult: null });
export class FnosDeploymentClient {
  constructor(socketPath = '/run/reverse-proxy-cert-deployer/control.sock') { this.socketPath = socketPath; }
  request(action, body = {}) {
    return new Promise((resolve, reject) => {
      const request = http.request({ socketPath: this.socketPath, method: 'POST', path: `/${action}`, headers: { 'Content-Type': 'application/json' } }, (response) => {
        let raw = '';
        response.setEncoding('utf8'); response.on('data', (chunk) => { raw += chunk; if (raw.length > 1024 * 1024) request.destroy(); });
        response.on('error', () => reject(deployError('UNAVAILABLE')));
        response.on('end', () => { try { const result = JSON.parse(raw); if (response.statusCode !== 200) reject(Object.assign(deployError(DEPLOY_ERRORS[result.code] ? result.code : 'INCOMPATIBLE'), { stage: DEPLOY_STAGES[result.stage] ? result.stage : undefined })); else resolve(result); } catch { reject(deployError('INCOMPATIBLE')); } });
      });
      request.setTimeout(action === 'deploy' ? 240000 : 60000, () => request.destroy());
      request.on('error', () => reject(deployError('UNAVAILABLE')));
      request.end(JSON.stringify(body));
    });
  }
  status() { return this.request('status'); }
  prepare(input) { return this.request('prepare', input); }
  deploy(input) { return this.request('deploy', input); }
}

export class FnosDeploymentService {
  constructor({ store, logger, client = new FnosDeploymentClient(), demoMode = false, onDeployed }) {
    Object.assign(this, { store, logger, client, demoMode, onDeployed });
    this.running = null; this.refreshing = null; this.prepared = null;
    this.helper = { available: false, targets: [], message: '尚未检查内置部署服务' };
  }
  config() { return { ...defaults(), ...this.store.data.integrations?.fnosDeployment }; }
  patch(patch) {
    const previous = this.store.data.integrations.fnosDeployment;
    this.store.data.integrations.fnosDeployment = { ...this.config(), ...patch };
    try { this.store.save(); } catch (e) { this.store.data.integrations.fnosDeployment = previous; throw e; }
  }
  status() { return { ...this.config(), helper: this.helper, running: Boolean(this.running), demoMode: this.demoMode, experimental: true }; }
  source(id) {
    const certificate = this.store.data.certificates.find((c) => c.id === id);
    if (!certificate || certificate.source === 'system' || certificate.automation?.environment === 'staging') throw Object.assign(new Error('请选择证书库中的正式证书，不支持系统来源或测试环境证书'), { status: 400 });
    let certificatePem, privateKeyPem;
    try { certificatePem = fs.readFileSync(certificate.certPath, 'utf8'); privateKeyPem = fs.readFileSync(certificate.keyPath, 'utf8'); } catch { throw deployError('INVALID'); }
    const parsed = inspectDeploymentCertificate(certificatePem, privateKeyPem);
    return { certificatePem, privateKeyPem, fingerprint: parsed.fingerprint };
  }
  update(input = {}) {
    if (this.running) throw deployError('BUSY');
    const current = this.config(); const next = {};
    for (const field of ['certificateId', 'targetId', 'probeHost']) if (Object.hasOwn(input, field)) {
      if (typeof input[field] !== 'string' || input[field].length > 255) throw deployError('INVALID');
      next[field] = input[field].trim();
    }
    if (Object.hasOwn(input, 'probePort')) { next.probePort = Number(input.probePort); if (!Number.isInteger(next.probePort) || next.probePort < 1 || next.probePort > 65535) throw deployError('INVALID'); }
    if (Object.hasOwn(input, 'autoDeploy') && typeof input.autoDeploy !== 'boolean') throw deployError('INVALID');
    const changed = Object.keys(next).some((key) => next[key] !== current[key]);
    if (changed) Object.assign(next, { autoDeploy: false, expectedFingerprint: '', lastFingerprint: '', lastSuccessAt: null, lastError: null, lastResult: null });
    else if (Object.hasOwn(input, 'autoDeploy')) {
      if (input.autoDeploy && (!current.lastSuccessAt || !current.expectedFingerprint || current.lastError)) throw Object.assign(new Error('请先完成一次手动部署并通过 HTTPS 验证，再开启自动部署'), { status: 400 });
      next.autoDeploy = input.autoDeploy;
    }
    this.patch(next); this.prepared = null; return this.status();
  }
  async refresh() {
    if (this.running) return this.status();
    if (!this.refreshing) this.refreshing = (async () => {
      if (this.demoMode) this.helper = { available: false, targets: [], message: '本地演示不连接 fnOS，也不执行系统写入' };
      else { try { this.helper = await this.client.status(); } catch (e) { this.helper = { available: false, targets: [], message: DEPLOY_ERRORS[e.code] || DEPLOY_ERRORS.UNAVAILABLE }; } }
      return this.status();
    })().finally(() => { this.refreshing = null; });
    return this.refreshing;
  }
  async prepare() {
    if (this.running) throw deployError('BUSY');
    if (this.demoMode) throw Object.assign(new Error('演示模式不执行 fnOS 预检；请安装到 NAS 后操作'), { status: 400 });
    this.prepared = null;
    const config = this.config(); const source = this.source(config.certificateId);
    // Manual preflight deliberately accepts a new target fingerprint, but never
    // changes the saved automatic binding until a successful, confirmed deploy.
    const input = { ...config, ...source, expectedFingerprint: '' };
    const preview = await this.client.prepare(input);
    const token = randomUUID(); this.prepared = { input, preview, token, config: JSON.stringify(config), expires: Date.now() + 5 * 60000 };
    return { ...preview, token, expiresAt: new Date(this.prepared.expires).toISOString() };
  }
  kick({ token, confirmed = false } = {}) {
    if (this.running) throw deployError('BUSY');
    const prepared = this.prepared;
    if (!confirmed || !prepared || prepared.token !== token || prepared.expires <= Date.now() || prepared.config !== JSON.stringify(this.config())) throw deployError('CONFLICT');
    if (this.source(prepared.input.certificateId).fingerprint !== prepared.input.fingerprint) throw deployError('CONFLICT');
    this.prepared = null;
    this.running = this.perform(prepared.input, prepared.preview).finally(() => { this.running = null; });
    void this.running.catch(() => {});
    return { started: true };
  }
  async perform(input, preview) {
    this.patch({ lastAttemptAt: new Date().toISOString(), lastError: null, lastResult: 'running' });
    try {
      const result = await this.client.deploy({ ...input, planId: preview.planId });
      if (!result.ok || result.fingerprint !== input.fingerprint || !result.verifiedAt) throw deployError('INCOMPATIBLE');
      this.patch({ expectedFingerprint: result.fingerprint, lastFingerprint: result.fingerprint, lastSuccessAt: result.verifiedAt, lastError: null, lastResult: 'verified' });
      this.logger?.info('fnOS 证书已部署并验证 HTTPS', { certificateId: input.certificateId });
      try { await this.onDeployed?.(); } catch {}
      return result;
    } catch (e) {
      const message = (DEPLOY_STAGES[e.stage] ? `失败步骤：${DEPLOY_STAGES[e.stage]}；` : '') + (DEPLOY_ERRORS[e.code] || '部署结果无法确认，自动部署已暂停；请先检查 fnOS HTTPS，再重新预检');
      this.patch({ autoDeploy: false, lastError: message, lastResult: e.code === 'ROLLED_BACK' ? 'rolled-back' : 'failed' });
      this.logger?.warn('fnOS 证书部署停止', { error: message });
      throw Object.assign(new Error(message), { status: 502 });
    }
  }
  start() {
    this.stop();
    if (this.config().lastResult === 'running') this.patch({ autoDeploy: false, lastResult: 'interrupted', lastError: '上次部署被中断，请检查助手恢复状态并重新预检' });
    void this.refresh(); this.timer = setInterval(() => void this.tick(), 60000); this.timer.unref?.();
  }
  stop() { clearInterval(this.timer); }
  async tick() {
    const config = this.config();
    if (this.demoMode || this.running || !config.autoDeploy) return;
    this.running = (async () => {
      try {
        const source = this.source(config.certificateId);
        if (source.fingerprint === config.lastFingerprint) return;
        const input = { ...config, ...source };
        const preview = await this.client.prepare(input);
        await this.perform(input, preview);
      } catch (e) {
        this.patch({ autoDeploy: false, lastError: DEPLOY_ERRORS[e.code] || '自动部署预检失败，请检查证书和系统状态后手动部署', lastResult: 'failed' });
      }
    })().finally(() => { this.running = null; });
    await this.running;
  }
}
