import net from 'node:net';

const text = (value) => String(value ?? '').trim();
const flag = (value) => value === true || value === 'true' || value === 1;
const number = (value, fallback, min, max) => Math.max(min, Math.min(max, Number.isFinite(Number(value)) ? Math.trunc(Number(value)) : fallback));
const pick = (input, keys) => Object.fromEntries(keys.filter((key) => Object.hasOwn(input, key)).map((key) => [key, input[key]]));
const domain = (value) => text(value).toLowerCase().replace(/\.$/, '');
const fail = (message) => { throw Object.assign(new Error(message), { status: 400 }); };
const runtime = () => ({ lastRunAt: null, lastSuccessAt: null, lastError: null });
export const FREE_PRODUCT_CODE = 'digicert-free-1-free';
export const DDNS_PROVIDERS = { cloudflare: 'Cloudflare', aliyun: '阿里云 DNS', dnspod: '腾讯云 DNSPod' };
export const defaultDdns = () => ({
  provider: 'cloudflare', zoneId: '', apiToken: '', enabled: false, recordName: '', recordType: 'A', proxied: false, ttl: 1, intervalMinutes: 10,
  aliyun: { accessKeyId: '', accessKeySecret: '', dnsZone: '', line: 'default' },
  dnspod: { secretId: '', secretKey: '', dnsZone: '', line: '默认' },
  lastIp: null, lastChanged: null, ...runtime(),
});
export function normalizeDdns(saved = {}) {
  const defaults = defaultDdns();
  return { ...defaults, ...saved, aliyun: { ...defaults.aliyun, ...saved.aliyun }, dnspod: { ...defaults.dnspod, ...saved.dnspod } };
}
export const defaultIssuance = () => ({
  provider: 'aliyun-free',
  acme: { zoneId: '', apiToken: '', email: '', domains: [], environment: 'staging', autoRenew: false, renewDays: 30, accountKeyPem: '', certificateId: null, phase: 'idle', ...runtime() },
  aliyun: { apiVersion: 'v2', contactId: '', accessKeyId: '', accessKeySecret: '', domain: '', dnsZone: '', username: '', phone: '', email: '', autoRenew: false, renewDays: 15, certificateId: null, order: null, quota: null, phase: 'idle', ...runtime() },
});

export function validDomain(value, wildcard = false) {
  const name = wildcard ? domain(value).replace(/^\*\./, '') : domain(value);
  return Boolean(name && !net.isIP(name) && name.length <= 253 && name.includes('.') && name.split('.').every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(label)));
}

export function migrateDomainAutomation(integrations) {
  const legacy = integrations.domainAutomation;
  if (!legacy) return false;
  // Copy once: later changes to either feature must never alter the other one.
  integrations.ddns ||= { ...defaultDdns(), ...legacy.ddns, zoneId: legacy.zoneId || '', apiToken: legacy.apiToken || '' };
  integrations.certificateIssuance ||= { ...defaultIssuance(), provider: 'acme', acme: { ...defaultIssuance().acme, ...legacy.acme, zoneId: legacy.zoneId || '', apiToken: legacy.apiToken || '' } };
  delete integrations.domainAutomation;
  return true;
}

function cloudflare(input, existing) {
  const zoneId = text(input.zoneId ?? existing.zoneId);
  const apiToken = text(input.apiToken) || (flag(input.clearApiToken) ? '' : existing.apiToken);
  if (zoneId && !/^[a-z0-9_-]{16,80}$/i.test(zoneId)) fail('Cloudflare Zone ID 格式无效');
  return { zoneId, apiToken };
}

export function updateDdnsConfig(existing, input = {}) {
  existing = normalizeDdns(existing);
  if (input.provider !== undefined && !Object.hasOwn(DDNS_PROVIDERS, input.provider)) fail('不支持的 DDNS 服务商');
  const next = { ...existing, ...pick(input, ['provider', 'enabled', 'recordName', 'recordType', 'proxied', 'ttl', 'intervalMinutes']), ...cloudflare(input, existing) };
  for (const [provider, id, secret, clear] of [['aliyun', 'accessKeyId', 'accessKeySecret', 'clearAccessKeySecret'], ['dnspod', 'secretId', 'secretKey', 'clearSecretKey']]) {
    const patch = input[provider] || {};
    const old = existing[provider];
    const config = { ...old, ...pick(patch, [id, 'dnsZone', 'line']) };
    config[id] = text(config[id]);
    config[secret] = text(patch[secret]) || (flag(patch[clear]) ? '' : old[secret]);
    config.dnsZone = domain(config.dnsZone);
    config.line = text(config.line) || (provider === 'aliyun' ? 'default' : '默认');
    if (config[id] !== old[id] && old[secret] && !text(patch[secret]) && !flag(patch[clear])) fail('更换云账号 ID 时请同时填写对应的新密钥');
    if (config.dnsZone && !validDomain(config.dnsZone)) fail(`${DDNS_PROVIDERS[provider]} 主域名格式无效`);
    if (config.line.length > 128 || /[\r\n\x00-\x1f]/.test(config.line)) fail('解析线路格式无效');
    next[provider] = config;
  }
  next.enabled = flag(next.enabled);
  if (next.provider !== existing.provider && !Object.hasOwn(input, 'enabled')) next.enabled = false;
  next.proxied = flag(next.proxied);
  next.recordName = domain(next.recordName);
  if (!['A', 'AAAA'].includes(next.recordType)) fail('DDNS 仅支持 A 或 AAAA 记录');
  next.ttl = number(next.ttl, 1, 1, 86400);
  if (next.provider !== existing.provider && next.provider !== 'cloudflare' && next.ttl === 1) next.ttl = 600;
  next.intervalMinutes = number(next.intervalMinutes, 10, 5, 1440);
  if (next.recordName && !validDomain(next.recordName)) fail('DDNS 记录名称格式无效');
  if (next.provider === 'cloudflare') {
    if (next.ttl !== 1 && next.ttl < 60) fail('Cloudflare TTL 请使用自动（1）或至少 60 秒');
  } else {
    if (next.ttl < 60) fail('阿里云 / 腾讯云 TTL 至少 60 秒，建议使用 600 秒');
    const zone = next[next.provider].dnsZone;
    if (zone && next.recordName && next.recordName !== zone && !next.recordName.endsWith(`.${zone}`)) fail('完整记录名称必须属于所填 DNS 主域名');
  }
  if (next.enabled) assertDdnsReady(next);
  const target = (config) => JSON.stringify([config.provider, config.recordName, config.recordType, config.ttl, config.provider === 'cloudflare' ? [config.zoneId, config.apiToken, config.proxied] : config[config.provider]]);
  if (target(next) !== target(existing)) Object.assign(next, runtime(), { lastIp: null, lastChanged: null });
  return next;
}

export function assertDdnsReady(config) {
  if (!Object.hasOwn(DDNS_PROVIDERS, config.provider)) fail('不支持的 DDNS 服务商');
  if (!validDomain(config.recordName) || !['A', 'AAAA'].includes(config.recordType)) fail('请先保存有效的 DDNS 完整记录名称与记录类型');
  if (config.provider === 'cloudflare') {
    if (!config.zoneId || !config.apiToken) fail('请先保存 DDNS 的 Cloudflare Zone ID 和 API Token');
  } else {
    const settings = config[config.provider];
    if (!settings?.dnsZone || (config.provider === 'aliyun' ? !settings.accessKeyId || !settings.accessKeySecret : !settings.secretId || !settings.secretKey)) fail(`请先保存 DDNS 的${DDNS_PROVIDERS[config.provider]}凭据与 DNS 主域名`);
    if (!validDomain(settings.dnsZone) || config.recordName !== settings.dnsZone && !config.recordName.endsWith(`.${settings.dnsZone}`)) fail('完整记录名称必须属于所填 DNS 主域名');
  }
}

export function updateIssuanceConfig(existing, input = {}) {
  if (input.provider && !['acme', 'aliyun-free'].includes(input.provider)) fail('不支持的证书签发服务');
  const a = input.acme || {};
  const y = input.aliyun || {};
  const acme = { ...existing.acme, ...pick(a, ['email', 'domains', 'environment', 'autoRenew', 'renewDays']), ...cloudflare(a, existing.acme) };
  acme.email = text(acme.email).toLowerCase();
  acme.domains = [...new Set((Array.isArray(acme.domains) ? acme.domains : text(acme.domains).split(/[,，;；\s]+/)).map(domain).filter(Boolean))];
  acme.environment = acme.environment === 'production' ? 'production' : 'staging';
  acme.autoRenew = flag(acme.autoRenew);
  acme.renewDays = number(acme.renewDays, 30, 7, 60);
  if (acme.domains.length > 100 || acme.domains.some((name) => !validDomain(name, true))) fail('ACME 域名格式无效');
  if (acme.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(acme.email)) fail('ACME 联系邮箱格式无效');
  if (acme.autoRenew && (!acme.zoneId || !acme.apiToken || !acme.email || !acme.domains.length)) fail('启用 ACME 自动轮换前请填写 DNS 凭据、邮箱和域名');
  if (acme.environment !== existing.acme.environment || acme.domains.join(',') !== existing.acme.domains.join(',')) {
    acme.certificateId = null; acme.lastRunAt = null; acme.lastSuccessAt = null; acme.phase = 'idle'; acme.lastError = null;
  }
  const aliyun = { ...existing.aliyun, ...pick(y, ['apiVersion', 'contactId', 'accessKeyId', 'domain', 'dnsZone', 'username', 'phone', 'email', 'autoRenew', 'renewDays']) };
  for (const key of ['accessKeyId', 'username', 'phone', 'email']) aliyun[key] = text(aliyun[key]);
  aliyun.accessKeySecret = text(y.accessKeySecret) || (y.clearAccessKeySecret ? '' : existing.aliyun.accessKeySecret);
  if (aliyun.accessKeyId !== existing.aliyun.accessKeyId && existing.aliyun.accessKeySecret && !text(y.accessKeySecret) && !y.clearAccessKeySecret) fail('更换 AccessKey ID 时请同时填写对应的新 Secret');
  if (aliyun.accessKeyId !== existing.aliyun.accessKeyId || aliyun.accessKeySecret !== existing.aliyun.accessKeySecret) {
    aliyun.quota = null;
    aliyun.lastError = null;
  }
  if (!['v1', 'v2'].includes(aliyun.apiVersion)) fail('请选择新版实例或旧版资源包');
  aliyun.contactId = text(aliyun.contactId);
  if (aliyun.contactId && (!/^\d+$/.test(aliyun.contactId) || !Number.isSafeInteger(Number(aliyun.contactId)) || Number(aliyun.contactId) < 1)) fail('联系人 ID 应为正整数');
  if (aliyun.apiVersion !== existing.aliyun.apiVersion) { aliyun.quota = null; aliyun.lastError = null; if (!Object.hasOwn(y, 'autoRenew')) aliyun.autoRenew = false; }
  aliyun.domain = domain(aliyun.domain); aliyun.dnsZone = domain(aliyun.dnsZone);
  aliyun.autoRenew = flag(aliyun.autoRenew);
  aliyun.renewDays = number(aliyun.renewDays, 15, 7, 30);
  if (aliyun.domain && !validDomain(aliyun.domain)) fail('阿里云免费证书仅支持单个普通域名，不支持通配符');
  if (aliyun.dnsZone && !validDomain(aliyun.dnsZone)) fail('阿里云 DNS 主域名格式无效');
  if (aliyun.domain && aliyun.dnsZone && aliyun.domain !== aliyun.dnsZone && !aliyun.domain.endsWith(`.${aliyun.dnsZone}`)) fail('证书域名必须属于所填 DNS 主域名');
  if (aliyun.email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(aliyun.email)) fail('阿里云联系邮箱格式无效');
  if (aliyun.autoRenew && (!aliyun.accessKeyId || !aliyun.accessKeySecret || !aliyun.domain || !aliyun.dnsZone)) fail('启用阿里云自动轮换前请填写 AccessKey、证书域名和 DNS 主域名');
  const pending = existing.aliyun.order;
  if (pending && ['apiVersion', 'domain', 'dnsZone', 'accessKeyId'].some((key) => aliyun[key] !== existing.aliyun[key])) fail('当前订单尚未结束，请先完成或处理该订单，再更改域名与账号');
  if (aliyun.domain !== existing.aliyun.domain) {
    aliyun.certificateId = null; aliyun.lastRunAt = null; aliyun.lastSuccessAt = null; aliyun.phase = 'idle'; aliyun.lastError = null;
  }
  return { provider: input.provider || existing.provider, acme, aliyun };
}

export function publicDdns(config) {
  const { apiToken, aliyun, dnspod, ...rest } = normalizeDdns(config);
  const { accessKeySecret, ...publicAliyun } = aliyun;
  const { secretKey, ...publicDnspod } = dnspod;
  return { ...rest, hasApiToken: Boolean(apiToken), aliyun: { ...publicAliyun, hasAccessKeySecret: Boolean(accessKeySecret) }, dnspod: { ...publicDnspod, hasSecretKey: Boolean(secretKey) } };
}
export function publicIssuance(config) {
  const { apiToken, accountKeyPem, ...acme } = config.acme;
  const { accessKeySecret, order, ...aliyun } = config.aliyun;
  return {
    provider: config.provider,
    acme: { ...acme, hasApiToken: Boolean(apiToken), hasAccount: Boolean(accountKeyPem) },
    aliyun: { ...aliyun, hasAccessKeySecret: Boolean(accessKeySecret), productCode: FREE_PRODUCT_CODE, order: order ? { id: order.id || null, apiVersion: order.apiVersion || 'v1', domain: order.domain, phase: order.phase, createdAt: order.createdAt, dnsName: order.dnsName || null } : null },
  };
}
