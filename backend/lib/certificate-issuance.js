import { promises as dns } from 'node:dns';
import acme from 'acme-client';
import { CloudflareDnsClient } from './cloudflare-dns.js';
import { AliyunClient, automationError } from './aliyun-client.js';
import { AliyunV2Client, advanceAliyunV2 } from './aliyun-v2.js';

const now = () => new Date().toISOString();
const DAY = 86400_000;
const due = (at, interval) => !Number.isFinite(Date.parse(at)) || Date.now() - Date.parse(at) >= interval;
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

export class CertificateIssuance {
  constructor({ store, logger, demoMode = false, onCertificate, fetchFn = globalThis.fetch, resolver = dns, acmeLib = acme, aliyunFactory = (config) => config.apiVersion === 'v2' ? new AliyunV2Client(config) : new AliyunClient(config) }) {
    Object.assign(this, { store, logger, demoMode, onCertificate, fetchFn, resolver, acme: acmeLib, aliyunFactory });
    this.running = new Map();
    this.events = []; this.eventId = 0; this.activeSteps = new Map();
  }
  start() { this.stop(); this.scheduleBase = Date.now(); this.nextTickAt = this.scheduleBase + 10_000; this.timer = setInterval(() => void this.tick(), 60_000); this.timer.unref?.(); this.initial = setTimeout(() => void this.tick(), 10_000); this.initial.unref?.(); }
  stop() { clearInterval(this.timer); clearTimeout(this.initial); }
  event(provider, message, level = 'info') {
    this.events.push({ id: ++this.eventId, at: now(), provider, level, message });
    this.events = this.events.slice(-200);
  }
  client(config) {
    const client = this.aliyunFactory(config);
    const labels = { quota: '查询免费额度 / 可用实例', checkZone: '检查 DNS 区域', select: '选择可用免费实例', contacts: '核对证书联系人', configure: '配置域名与 CSR', prepareApply: '核验申请配置', apply: '提交证书申请', detail: '查询实例状态', task: '查询 CA 任务状态', download: '下载已签发证书', describe: '查询证书订单', create: '提交免费证书申请', ensureRecord: '检查并配置 DNS 验证记录', removeRecord: '清理本次验证记录' };
    return new Proxy(client, { get: (target, key) => {
      const value = Reflect.get(target, key);
      if (typeof value !== 'function') return value;
      if (!labels[key]) return value.bind(target);
      return async (...args) => {
        const step = { message: labels[key], since: now() };
        this.activeSteps.set('aliyun', step); this.event('aliyun', `${labels[key]}…`);
        try { const result = await value.apply(target, args); this.event('aliyun', `${labels[key]}完成`, 'success'); return result; }
        catch (error) { this.event('aliyun', `${labels[key]}失败，请查看上方错误信息`, 'error'); throw error; }
        finally { if (this.activeSteps.get('aliyun') === step) this.activeSteps.delete('aliyun'); }
      };
    } });
  }
  status() {
    const status = this.store.issuanceStatus();
    const a = this.store.issuanceConfig().aliyun;
    const pending = a.order && !['verify_fail', 'uncertain', 'creating'].includes(a.order.phase);
    const eligible = (Date.parse(a.lastRunAt || '') || Date.now()) + (a.lastError ? 900000 : 60000);
    const scheduled = this.scheduleBase ? this.scheduleBase + Math.ceil((eligible - this.scheduleBase) / 60000) * 60000 : eligible;
    const nextPollAt = pending && !this.running.has('aliyun') && this.timer
      ? new Date(Math.max(this.nextTickAt || Date.now(), scheduled)).toISOString() : null;
    return { ...status, running: [...this.running.keys()], demoMode: this.demoMode,
      progress: { events: this.events, active: this.activeSteps.get('aliyun') || null, nextPollAt } };
  }
  assertConfig(provider) {
    const config = this.store.issuanceConfig();
    if (provider === 'acme') {
      const a = config.acme;
      if (!a.zoneId || !a.apiToken || !a.email || !a.domains.length) throw automationError('请先保存 ACME 的 DNS 凭据、邮箱和域名');
    } else {
      const a = config.aliyun;
      if (!a.accessKeyId || !a.accessKeySecret || !a.domain || !a.dnsZone) throw automationError('请先保存阿里云 AccessKey、证书域名和 DNS 主域名');
    }
  }
  issue(provider = this.store.issuanceConfig().provider) {
    const key = provider === 'acme' ? 'acme' : 'aliyun';
    if (this.running.has(key)) return this.running.get(key);
    this.assertConfig(provider);
    if (this.demoMode) return Promise.resolve({ demoMode: true });
    // Reserve the lock before any await, including key generation and quota checks.
    this.event(key, this.store.issuanceConfig()[key].order ? '继续查询已保存的申请' : '开始签发任务');
    const task = Promise.resolve().then(() => key === 'acme' ? this.issueAcme() : this.advanceAliyun()).catch((error) => {
      const config = this.store.issuanceConfig()[key];
      let message = error.message || '证书签发失败';
      for (const secret of [config.apiToken, config.accessKeySecret, config.accountKeyPem, config.order?.privateKeyPem].filter(Boolean)) message = message.split(secret).join('[已隐藏]');
      const patch = { lastError: message, lastRunAt: now() };
      if (key === 'acme' || !config.order) patch.phase = 'error';
      else if (!config.order.id) { patch.phase = 'uncertain'; patch.order = { ...config.order, phase: 'uncertain' }; }
      this.store.patchIssuance(key, patch);
      if (message !== config.lastError) this.logger?.warn('证书签发暂未完成', { provider: key, error: message });
      throw automationError(message, error.status || 502);
    }).finally(() => { this.running.delete(key); const state = this.store.issuanceConfig()[key]; this.event(key, state.lastError ? '本轮未完成，请查看错误信息' : state.order ? '本轮检查完成，等待下一次轮询' : state.phase === 'issued' ? '证书已验证并保存到证书库' : '本轮检查结束', state.lastError ? 'error' : 'info'); });
    this.running.set(key, task);
    return task;
  }
  kick() {
    const provider = this.store.issuanceConfig().provider;
    this.assertConfig(provider);
    void this.issue(provider).catch(() => {});
    return { accepted: !this.demoMode, demoMode: this.demoMode };
  }
  async refreshQuota() {
    const config = this.store.issuanceConfig().aliyun;
    if (!config.accessKeyId || !config.accessKeySecret) throw automationError('请先保存阿里云 AccessKey');
    if (this.demoMode) return { demoMode: true };
    const quota = await this.client(config).quota();
    const current = this.store.issuanceConfig().aliyun;
    if (['apiVersion', 'accessKeyId', 'accessKeySecret', 'domain'].some((key) => current[key] !== config[key]))
      throw automationError('配置已变化，请重新查询当前账号的额度', 409);
    this.store.patchIssuance('aliyun', { quota });
    return quota;
  }
  associateOrder(id) {
    if (this.running.has('aliyun')) throw automationError('订单正在处理，请稍后重试', 409);
    const config = this.store.issuanceConfig().aliyun;
    if (!config.order || config.order.id) throw automationError('只有提交结果不确定的申请可以关联订单');
    if (!/^\d+$/.test(String(id)) || !Number.isSafeInteger(Number(id)) || Number(id) <= 0) throw automationError('订单 ID 无效');
    if (this.demoMode) return;
    this.store.patchIssuance('aliyun', { order: { ...config.order, id: String(id), phase: 'pending' }, phase: 'pending', lastError: null, lastRunAt: null });
  }
  resetUncertain(confirmedNoOrder) {
    if (this.running.has('aliyun')) throw automationError('订单正在处理，请稍后重试', 409);
    const config = this.store.issuanceConfig().aliyun;
    if (confirmedNoOrder !== true || !config.order || config.order.id) throw automationError('请先在阿里云控制台确认没有本次申请的订单');
    if (this.demoMode) return;
    // Explicit human reconciliation is required: the create API has no idempotency token.
    this.store.patchIssuance('aliyun', { order: null, phase: 'idle', autoRenew: false, lastRunAt: now(), lastError: null });
    this.logger?.info('用户已确认云端无订单，重置本地申请并暂停自动轮换');
  }
  async retryFailed() {
    if (this.running.has('aliyun')) throw automationError('订单正在处理，请稍后重试', 409);
    const config = this.store.issuanceConfig().aliyun;
    if (config.order?.phase !== 'verify_fail') throw automationError('只有审核失败的订单可以重新申请');
    if (this.demoMode) return;
    // Keep this operation under the same lock as the scheduler.
    const task = (async () => {
      const client = this.client(config);
      if (config.order.apiVersion === 'v2') {
        const detail = await client.detail(config.order.id);
        client.assertBinding(detail, config.order);
        const task = await client.task(config.order.id);
        if (task.taskStatus !== 'failed' || detail.status !== 'inactive' || detail.certificateId) throw automationError('云端状态已改变，请继续查询原实例，不会重新提交');
        const contactIds = await client.contacts(detail);
        this.store.patchIssuance('aliyun', { order: { ...config.order, contactIds, stage: 'configure', phase: 'pending' }, phase: 'pending', lastError: null });
        return;
      }
      const state = await client.describe(config.order.id);
      if (state.type !== 'verify_fail') throw automationError('订单状态已改变，请继续查询原订单');
      await this.cleanup(client, config.order);
      this.store.patchIssuance('aliyun', { order: null, phase: 'idle', lastRunAt: now(), lastError: null });
    })().finally(() => this.running.delete('aliyun'));
    this.running.set('aliyun', task);
    await task;
    return this.issue('aliyun-free');
  }
  async cleanup(client, order) {
    for (const record of order.dnsRecords || []) await client.removeRecord(record);
  }
  async advanceAliyun() {
    let config = this.store.issuanceConfig().aliyun;
    if (config.apiVersion === 'v2') return advanceAliyunV2(this);
    const client = this.client(config);
    this.store.patchIssuance('aliyun', { lastRunAt: now(), lastError: null });
    let order = config.order;
    if (!order) {
      this.store.patchIssuance('aliyun', { phase: 'checking' });
      const quota = await client.quota();
      this.store.patchIssuance('aliyun', { quota });
      if (quota.remaining < 1) throw automationError(quota.total === 0
        ? '当前 AccessKey 账号没有可用于自动申请的免费资源包。请核对账号及 V1.0 历史额度；V2.0 订阅实例不能用于此接口。旧证书保持不变。'
        : '免费证书额度不足：该免费资源包已签发完毕。请核对阿里云历史额度；旧证书保持不变。');
      await client.checkZone(config.dnsZone);
      const [privateKey, csr] = await this.acme.crypto.createCsr({ commonName: config.domain, altNames: [config.domain] });
      order = { id: null, phase: 'creating', domain: config.domain, createdAt: now(), privateKeyPem: privateKey.toString(), csr: csr.toString(), dnsRecords: [] };
      // Persist intent and key BEFORE submitting. A crash/timeout must not spend another quota.
      this.store.patchIssuance('aliyun', { order, phase: 'creating' });
      order = { ...order, id: await client.create(config, order.csr), phase: 'pending' };
      this.store.patchIssuance('aliyun', { order, phase: 'pending', quota: { ...quota, used: quota.used + 1, remaining: Math.max(0, quota.remaining - 1) } });
    }
    if (!order.id) throw automationError('上次提交结果不确定，请在阿里云控制台查找该域名订单并关联订单 ID；不会自动重复申请');
    if (order.phase === 'cleanup') {
      await this.cleanup(client, order);
      this.store.patchIssuance('aliyun', { order: null, phase: 'issued', lastError: null });
      return { ok: true, certificateId: config.certificateId };
    }
    const state = await client.describe(order.id);
    if (state.type === 'certificate') {
      if (!state.certificate || !order.privateKeyPem) throw automationError('云端未返回完整证书或本地申请私钥缺失，保留旧证书并等待处理', 502);
      const saved = await this.onCertificate({ name: `阿里云 · ${order.domain}`, provider: 'aliyun-free', environment: 'production', domains: [order.domain], targetCertificateId: config.certificateId, certificatePem: state.certificate, privateKeyPem: order.privateKeyPem, orderId: order.id });
      const certificateId = saved.certificate.id;
      order = { ...order, phase: 'cleanup', privateKeyPem: '', csr: '' };
      this.store.patchIssuance('aliyun', { certificateId, order, phase: 'issued', lastSuccessAt: now(), lastError: null });
      this.logger?.info('阿里云免费证书已签发并完成轮换', { certificateId, domain: order.domain, orderId: order.id });
      await this.cleanup(client, order);
      this.store.patchIssuance('aliyun', { order: null });
      return { ok: true, ...saved };
    }
    if (state.type === 'domain_verify') {
      if (state.domain && state.domain.toLowerCase() !== order.domain) throw automationError('关联订单的域名与本地申请不符，请核对订单 ID');
      const record = await client.ensureRecord(config.dnsZone, state);
      const records = [...order.dnsRecords];
      if (!records.some((item) => item.id === record.id)) records.push(record);
      order = { ...order, phase: 'domain_verify', dnsRecords: records, dnsName: record.name };
    } else order = { ...order, phase: ['process', 'verify_fail', 'payed'].includes(state.type) ? state.type : 'unknown' };
    this.store.patchIssuance('aliyun', { order, phase: order.phase, lastError: order.phase === 'verify_fail' ? 'CA 审核失败，请检查阿里云订单；修正后可手动重新申请，旧证书不变' : null });
    return { pending: true, phase: order.phase, orderId: order.id };
  }
  async waitForTxt(name, value) {
    for (let attempt = 0; attempt < 24; attempt += 1) {
      try { if ((await this.resolver.resolveTxt(name)).some((parts) => parts.join('') === value)) return; } catch {}
      await wait(5000);
    }
    throw automationError('DNS 验证记录未在两分钟内生效，请检查 DNS 配置后重试', 504);
  }
  async issueAcme() {
    const config = this.store.issuanceConfig().acme;
    this.store.patchIssuance('acme', { phase: 'issuing', lastRunAt: now(), lastError: null });
    let accountKey = config.accountKeyPem;
    if (!accountKey) { accountKey = (await this.acme.crypto.createPrivateEcdsaKey()).toString(); this.store.patchIssuance('acme', { accountKeyPem: accountKey }); }
    const [privateKey, csr] = await this.acme.crypto.createCsr({ altNames: config.domains });
    const client = new this.acme.Client({ directoryUrl: this.acme.directory.letsencrypt[config.environment], accountKey });
    const dnsClient = new CloudflareDnsClient({ ...config, fetchFn: this.fetchFn });
    const records = new Map();
    try {
      const certificatePem = await client.auto({
        csr, email: config.email, termsOfServiceAgreed: true, challengePriority: ['dns-01'], skipChallengeVerification: true,
        challengeCreateFn: async (authz, challenge, value) => {
          const name = `_acme-challenge.${authz.identifier.value.replace(/^\*\./, '')}`;
          const record = await dnsClient.createTxt(name, value);
          records.set(challenge.url || challenge.token, record.id);
          await this.waitForTxt(name, value);
        },
        challengeRemoveFn: async (authz, challenge) => {
          const key = challenge.url || challenge.token;
          await dnsClient.deleteRecord(records.get(key)); records.delete(key);
        },
      });
      const saved = await this.onCertificate({ name: `ACME · ${config.domains[0]}`, provider: 'acme', environment: config.environment, domains: config.domains, targetCertificateId: config.certificateId, certificatePem: String(certificatePem), privateKeyPem: privateKey.toString() });
      this.store.patchIssuance('acme', { phase: 'issued', certificateId: saved.certificate.id, lastSuccessAt: now(), lastError: null });
      this.logger?.info('ACME 证书已签发', { certificateId: saved.certificate.id, environment: config.environment });
      return saved;
    } finally {
      for (const id of records.values()) { try { await dnsClient.deleteRecord(id); } catch { this.logger?.warn('ACME 验证记录清理失败，请检查 Cloudflare DNS'); } }
    }
  }
  needsRenewal(config) {
    const certificate = config.certificateId ? this.store.certificate(config.certificateId) : null;
    return !certificate || !Number.isFinite(Date.parse(certificate.validTo)) || Date.parse(certificate.validTo) - Date.now() <= config.renewDays * DAY;
  }
  async tick() {
    this.nextTickAt = this.scheduleBase ? this.scheduleBase + (Math.floor((Date.now() - this.scheduleBase) / 60000) + 1) * 60000 : Date.now() + 60_000;
    if (this.demoMode) return;
    const config = this.store.issuanceConfig();
    const pending = config.aliyun.order;
    if (pending && !['verify_fail', 'uncertain', 'creating'].includes(pending.phase) && due(config.aliyun.lastRunAt, config.aliyun.lastError ? 15 * 60_000 : 60_000)) {
      try { await this.issue('aliyun-free'); } catch {}
    }
    const key = config.provider === 'acme' ? 'acme' : 'aliyun';
    const current = this.store.issuanceConfig()[key];
    if (current.autoRenew && !current.order && this.needsRenewal(current) && due(current.lastRunAt, 6 * 3600_000)) { try { await this.issue(config.provider); } catch {} }
  }
}
