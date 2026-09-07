import AliDns from '@alicloud/alidns20150109';
import OpenApi from '@alicloud/openapi-client';
import Tea from '@alicloud/tea-util';
import { validDomain } from './automation-config.js';
import { automationError } from './aliyun-client.js';

const clean = (value) => typeof value === 'string' ? value.trim() : '';
const normalize = (value) => clean(value).toLowerCase().replace(/\.$/, '');
const incomplete = () => automationError('阿里云解析区域响应不完整，请重试或手动填写 DNS 主域名', 502);
const timeout = () => automationError('解析区域查询超时，请重试或手动填写 DNS 主域名', 504);

// Exact account-scoped queries, longest suffix first. Never guess the last two
// labels: public suffixes and separately hosted subdomains need different zones.
export function zoneCandidates(value) {
  const domain = normalize(value);
  if (!validDomain(domain)) throw automationError('请先填写完整的普通域名，例如 home.example.com');
  const labels = domain.split('.');
  if (labels.length > 17) throw automationError('域名层级过多，请手动填写 DNS 主域名');
  return labels.slice(0, -1).map((_, index) => labels.slice(index).join('.'));
}

function lookupError(error) {
  // SDK errors may contain credentials, signed URLs and the entire request.
  const code = String(error?.code || '');
  if (/Forbidden|Unauthorized|AccessDenied|NoPermission/i.test(code)) return automationError('自动识别需要 alidns:DescribeDomains 查询权限；请检查 RAM 授权，或手动填写 DNS 主域名', 403);
  if (/AccessKey|Signature|AuthFailure/i.test(code)) return automationError('阿里云 AccessKey 校验失败，请检查 ID 与 Secret 是否属于同一账号', 502);
  return automationError('无法查询阿里云解析区域，请检查网络与凭据后重试，或手动填写 DNS 主域名', 502);
}

export class AliyunZoneDiscovery {
  constructor({ store, demoMode = false, timeoutMs = 30_000, dnsFactory = (credentials) => new AliDns.default(new OpenApi.Config({ ...credentials, regionId: 'cn-hangzhou', endpoint: 'alidns.aliyuncs.com' })) }) {
    Object.assign(this, { store, demoMode, timeoutMs, dnsFactory });
    this.active = 0;
  }

  async resolve(scope, input = {}) {
    if (!['certificate-issuance', 'ddns'].includes(scope)) throw automationError('不支持的解析区域查询来源');
    if (!input || typeof input !== 'object' || Array.isArray(input)) throw automationError('解析区域查询参数无效');
    const candidates = zoneCandidates(input.domain);
    const saved = (scope === 'ddns' ? this.store.ddnsConfig() : this.store.issuanceConfig()).aliyun;
    const accessKeyId = clean(input.accessKeyId ?? saved.accessKeyId);
    const suppliedSecret = clean(input.accessKeySecret);
    if (accessKeyId !== saved.accessKeyId && !suppliedSecret && !input.clearAccessKeySecret) throw automationError('更换 AccessKey ID 后，请同时填写对应的新 Secret');
    const accessKeySecret = suppliedSecret || (input.clearAccessKeySecret ? '' : saved.accessKeySecret);
    if (!accessKeyId || !accessKeySecret) throw automationError('请先填写当前功能的 AccessKey ID 和 Secret；已保存的 Secret 可留空');
    if (accessKeyId.length > 256 || accessKeySecret.length > 1024) throw automationError('AccessKey 格式无效');
    if (this.demoMode) return { demoMode: true, dnsZone: null, message: '演示模式不查询阿里云；请在 NAS 上自动识别，或手动填写。' };
    if (this.active >= 2) throw automationError('解析区域正在查询，请稍后重试', 429);
    this.active += 1;
    const deadline = Date.now() + this.timeoutMs;
    try {
      const client = this.dnsFactory({ accessKeyId, accessKeySecret });
      for (const candidate of candidates) {
        // Query both star states explicitly so the provider's default starred
        // filter cannot hide a more specific, unstarred child zone.
        for (const starmark of [false, true]) {
          const remaining = deadline - Date.now();
          if (remaining <= 0) throw timeout();
          let timer;
          let body;
          try {
            const runtime = new Tea.RuntimeOptions({ autoretry: false, maxAttempts: 1, connectTimeout: Math.min(5000, remaining), readTimeout: Math.min(8000, remaining) });
            const request = new AliDns.DescribeDomainsRequest({ keyWord: candidate, searchMode: 'EXACT', pageNumber: 1, pageSize: 100, starmark });
            body = (await Promise.race([
              Promise.resolve().then(() => client.describeDomainsWithOptions(request, runtime)).catch((error) => { throw lookupError(error); }),
              new Promise((_, reject) => { timer = setTimeout(() => reject(timeout()), remaining); }),
            ]))?.body;
          } finally { clearTimeout(timer); }
          const zones = body?.domains?.domain;
          if (!Array.isArray(zones) || !Number.isSafeInteger(body.totalCount) || body.totalCount !== zones.length || zones.length > 1 || zones.some((zone) => normalize(zone?.punyCode || zone?.domainName) !== candidate || !zone?.domainId)) throw incomplete();
          if (zones.length === 1) return { domain: candidates[0], dnsZone: candidate, checkedAt: new Date().toISOString() };
        }
      }
      throw automationError('当前阿里云账号中未找到匹配的解析区域；请确认 DNS 托管账号，或手动填写 DNS 主域名', 404);
    } finally { this.active -= 1; }
  }
}
