import Cas from '@alicloud/cas20200407';
import AliDns from '@alicloud/alidns20150109';
import OpenApi from '@alicloud/openapi-client';
import Tea from '@alicloud/tea-util';
import { FREE_PRODUCT_CODE } from './automation-config.js';

export const automationError = (message, status = 400) => Object.assign(new Error(message), { status });

// Never include SDK messages, request dumps, signed URLs, or cloud key material in logs/UI.
export function safeCloudError(error) {
  const code = String(error?.code || '').replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 80);
  const requestId = String(error?.data?.RequestId || error?.requestId || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 80);
  return `阿里云请求失败${code ? `（${code}）` : '（网络或服务暂不可用）'}${requestId ? `，请求 ID：${requestId}` : ''}；请检查 RAM 权限、凭据与云端订单`;
}

export function validationRecord(recordDomain, zone, allowApexValidation = false) {
  const name = String(recordDomain || '').trim().toLowerCase().replace(/\.$/, '');
  if (!name || (!allowApexValidation && !name.startsWith('_')) || !/^[a-z0-9_.-]+$/.test(name) || name.includes('..')) throw automationError('阿里云返回的 DNS 验证记录名称无效');
  if (allowApexValidation && name !== zone && !name.endsWith(`.${zone}`)) throw automationError('验证记录不属于所选 DNS 区域');
  const fqdn = name === zone && allowApexValidation ? name : name.endsWith(`.${zone}`) ? name : `${name}.${zone}`;
  if (fqdn.length > 253 || fqdn.split('.').some((label) => !label || label.length > 63)) throw automationError('DNS 验证记录名称过长');
  return { name: fqdn, rr: fqdn === zone ? '@' : fqdn.slice(0, -(zone.length + 1)) };
}

export class AliyunClient {
  constructor(config, { casClient, dnsClient } = {}) {
    const credentials = { accessKeyId: config.accessKeyId, accessKeySecret: config.accessKeySecret, regionId: 'cn-hangzhou' };
    this.cas = casClient || new Cas.default(new OpenApi.Config({ ...credentials, endpoint: 'cas.aliyuncs.com' }));
    this.dns = dnsClient || new AliDns.default(new OpenApi.Config({ ...credentials, endpoint: 'alidns.aliyuncs.com' }));
    // CreateCertificateForPackageRequest has no idempotency token. Never let the SDK retry it.
    this.runtime = new Tea.RuntimeOptions({ autoretry: false, maxAttempts: 1, connectTimeout: 10_000, readTimeout: 20_000 });
  }

  async call(client, sdk, action, input) {
    try { return (await client[`${action[0].toLowerCase()}${action.slice(1)}WithOptions`](new sdk[`${action}Request`](input), this.runtime)).body; }
    catch (error) { throw automationError(safeCloudError(error), 502); }
  }

  async quota() {
    const body = await this.call(this.cas, Cas, 'DescribePackageState', { productCode: FREE_PRODUCT_CODE });
    if (body.productCode && body.productCode !== FREE_PRODUCT_CODE) throw automationError('云端返回了非免费证书套餐，已停止申请', 502);
    if (![body.totalCount, body.usedCount, body.issuedCount].every((value) => Number.isSafeInteger(value) && value >= 0)) throw automationError('阿里云免费额度返回不完整，请稍后重试', 502);
    // UsedCount is cumulative submissions, including failed requests. It is not
    // consumed quota. Pending orders elsewhere may still occupy this upper bound;
    // only the free-product create API can decide actual availability.
    return { total: body.totalCount, used: body.usedCount, issued: body.issuedCount, remaining: Math.max(0, body.totalCount - body.issuedCount), estimated: true, scope: 'legacy-package', checkedAt: new Date().toISOString() };
  }
  checkZone(dnsZone) { return this.call(this.dns, AliDns, 'DescribeDomainInfo', { domainName: dnsZone }); }
  async create(config, csr) {
    const body = await this.call(this.cas, Cas, 'CreateCertificateForPackageRequest', {
      productCode: FREE_PRODUCT_CODE, domain: config.domain, csr, validateType: 'DNS',
      ...(config.username ? { username: config.username } : {}), ...(config.phone ? { phone: config.phone } : {}), ...(config.email ? { email: config.email } : {}),
    });
    if (!Number.isSafeInteger(body.orderId) || body.orderId <= 0) throw automationError('未收到有效订单 ID，请到阿里云控制台核对后关联订单；不会重复申请', 502);
    return String(body.orderId);
  }
  describe(orderId) {
    if (!/^\d+$/.test(String(orderId)) || !Number.isSafeInteger(Number(orderId)) || Number(orderId) <= 0) throw automationError('阿里云订单 ID 无效');
    return this.call(this.cas, Cas, 'DescribeCertificateState', { orderId: Number(orderId) });
  }
  async ensureRecord(zone, state) {
    if (state.validateType !== 'DNS' || !['TXT', 'CNAME'].includes(state.recordType) || !state.recordValue) throw automationError('订单不是可自动处理的 DNS 验证，请在阿里云控制台检查');
    const { name, rr } = validationRecord(state.recordDomain, zone, state.allowApexValidation === true);
    const body = await this.call(this.dns, AliDns, 'DescribeSubDomainRecords', { subDomain: name, pageSize: 500, pageNumber: 1 });
    const records = body.domainRecords?.record || [];
    if (Number(body.totalCount) > records.length) throw automationError('验证记录数量过多，请先在阿里云 DNS 控制台整理');
    const identical = records.find((item) => item.type === state.recordType && item.value.replace(/\.$/, '') === state.recordValue.replace(/\.$/, ''));
    if (identical) return { id: identical.recordId, owned: false, name, type: state.recordType, value: state.recordValue };
    if (records.some((item) => item.type === 'CNAME') || state.recordType === 'CNAME' && records.length) throw automationError(`验证记录 ${name} 与已有记录冲突；请检查 DNS，不会覆盖原记录`);
    const added = await this.call(this.dns, AliDns, 'AddDomainRecord', { domainName: zone, RR: rr, type: state.recordType, value: state.recordValue, TTL: 600 });
    if (!added.recordId) throw automationError('未收到 DNS 记录 ID；下次将核对已有记录', 502);
    return { id: added.recordId, owned: true, name, type: state.recordType, value: state.recordValue };
  }
  async removeRecord(record) {
    if (!record.owned || !record.id) return;
    const body = await this.call(this.dns, AliDns, 'DescribeSubDomainRecords', { subDomain: record.name, pageSize: 500, pageNumber: 1 });
    const current = (body.domainRecords?.record || []).find((item) => item.recordId === record.id);
    // The user may have edited the record after we created it. Never delete their replacement.
    if (current && current.type === record.type && current.value === record.value) await this.call(this.dns, AliDns, 'DeleteDomainRecord', { recordId: record.id });
  }
}
