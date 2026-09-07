import net from 'node:net';
import { publicIpEndpoint } from './cloudflare-dns.js';
import { automationError } from './aliyun-client.js';
import { assertDdnsReady, DDNS_PROVIDERS } from './automation-config.js';
import { createDdnsClient } from './ddns-providers.js';

export class DdnsService {
  constructor({ store, logger, demoMode = false, fetchFn = globalThis.fetch, clientFactory = createDdnsClient }) {
    Object.assign(this, { store, logger, demoMode, fetchFn, clientFactory });
    this.running = null;
    this.detecting = new Map();
    this.detections = {};
  }
  start() { this.stop(); this.timer = setInterval(() => void this.tick(), 60_000); this.timer.unref?.(); this.initial = setTimeout(() => void this.tick(), 10_000); this.initial.unref?.(); }
  stop() { clearInterval(this.timer); clearTimeout(this.initial); }
  sync(options = {}) {
    if (!this.running) this.running = this.perform(options).finally(() => { this.running = null; });
    return this.running;
  }
  test() { return this.sync({ checkOnly: true }); }
  detectionStatus() { return { results: { ...this.detections }, running: [...this.detecting.keys()] }; }
  detect(recordType = this.store.ddnsConfig().recordType) {
    if (!['A', 'AAAA'].includes(recordType)) return Promise.reject(automationError('请选择 A（IPv4）或 AAAA（IPv6）', 400));
    if (!this.detecting.has(recordType)) {
      const task = this.detectAddress(recordType).finally(() => this.detecting.delete(recordType));
      this.detecting.set(recordType, task);
    }
    return this.detecting.get(recordType);
  }
  async detectAddress(recordType) {
    const source = new URL(publicIpEndpoint(recordType)).hostname;
    if (this.demoMode) return { demoMode: true, recordType, source, message: '演示模式不检测真实公网 IP；安装到 NAS 后由 NAS 自动获取出口地址' };
    try {
      const response = await this.fetchFn(publicIpEndpoint(recordType), { headers: { Accept: 'application/json' }, redirect: 'error', signal: AbortSignal.timeout(10_000) });
      if (!response.ok) throw new Error('response');
      const ip = String((await response.json()).ip || '').trim();
      if (net.isIP(ip) !== (recordType === 'AAAA' ? 6 : 4)) throw new Error('family');
      if (recordType === 'A') {
        const [a, b] = ip.split('.').map(Number);
        if (a === 0 || a === 10 || a === 127 || a >= 224 || a === 100 && b >= 64 && b <= 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 198 && [18, 19].includes(b)) throw new Error('private');
      } else if (!/^[23]/i.test(ip)) throw new Error('private');
      const result = { ip, recordType, source, detectedAt: new Date().toISOString(), error: null };
      this.detections[recordType] = result;
      return result;
    } catch {
      const error = `公网 IPv${recordType === 'AAAA' ? '6' : '4'} 检测失败，请检查 NAS 网络及 ${source} 可达性${recordType === 'AAAA' ? '，并确认网络支持 IPv6' : ''}`;
      this.detections[recordType] = { ...this.detections[recordType], recordType, source, error, attemptedAt: new Date().toISOString() };
      throw automationError(error, 502);
    }
  }
  async perform({ publicIp, checkOnly = false } = {}) {
    const config = this.store.ddnsConfig();
    try {
      assertDdnsReady(config);
      let ip = publicIp;
      if (this.demoMode) return { demoMode: true, message: '演示模式不修改 DNS，也不记录真实同步成功' };
      const client = this.clientFactory(config, { fetchFn: this.fetchFn });
      if (checkOnly) {
        const record = await client.inspect({ type: config.recordType, name: config.recordName });
        return { ok: true, recordExists: Boolean(record), message: `${DDNS_PROVIDERS[config.provider]} 查询正常${record ? '，已找到目标记录' : '，同步时将创建记录'}；写权限需在实际同步时验证` };
      }
      if (!ip) {
        ip = (await this.detect(config.recordType)).ip;
      }
      if (net.isIP(ip) !== (config.recordType === 'AAAA' ? 6 : 4)) throw automationError('公网检测返回的 IP 类型与 DNS 记录类型不符', 502);
      const result = await client.upsert({ type: config.recordType, name: config.recordName, content: ip, ttl: config.ttl, proxied: config.provider === 'cloudflare' && config.proxied });
      this.store.recordDdnsResult({ ok: true, ip, changed: result.changed });
      if (result.changed) this.logger?.info('DDNS 记录已更新', { provider: config.provider, recordName: config.recordName, ip });
      return { ok: true, provider: config.provider, changed: result.changed, ip };
    } catch (error) {
      let message = error.status ? String(error.message) : 'DDNS 请求失败或超时，请检查网络后重试';
      for (const secret of [config.apiToken, config.aliyun.accessKeySecret, config.dnspod.secretKey].filter(Boolean)) message = message.split(secret).join('[已隐藏]');
      if (!checkOnly) this.store.recordDdnsResult({ ok: false, error: message });
      this.logger?.warn(checkOnly ? 'DDNS 连接测试失败' : 'DDNS 同步失败', { provider: config.provider, error: message });
      throw automationError(message, error.status || 502);
    }
  }
  async tick() {
    if (this.demoMode) return;
    const config = this.store.ddnsConfig();
    if (config.enabled && (!config.lastRunAt || Date.now() - Date.parse(config.lastRunAt) >= config.intervalMinutes * 60_000)) { try { await this.sync(); } catch {} }
  }
}
