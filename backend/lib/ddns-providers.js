import net from 'node:net';
import AliDns from '@alicloud/alidns20150109';
import OpenApi from '@alicloud/openapi-client';
import Tea from '@alicloud/tea-util';
import Tencent from 'tencentcloud-sdk-nodejs-dnspod';
import { CloudflareDnsClient } from './cloudflare-dns.js';
import { automationError } from './aliyun-client.js';
import { validDomain } from './automation-config.js';

const clean = (value) => String(value ?? '').trim().toLowerCase().replace(/\.$/, '');
const invalid = () => automationError('DNS 查询响应不完整，已停止写入；请稍后重试', 502);
export function relativeRecord(name, zone) {
  name = clean(name); zone = clean(zone);
  if (!validDomain(name) || !validDomain(zone) || name !== zone && !name.endsWith(`.${zone}`)) throw automationError('完整记录名称必须属于所填 DNS 主域名');
  return name === zone ? '@' : name.slice(0, -(zone.length + 1));
}
export function sameIp(left, right) {
  if (!net.isIP(left) || net.isIP(left) !== net.isIP(right)) return false;
  return net.isIP(left) === 6 ? new URL(`http://[${left}]/`).hostname === new URL(`http://[${right}]/`).hostname : left === right;
}
function safeDnsError(error, label) {
  const code = String(error?.code || '').replace(/[^a-zA-Z0-9_.-]/g, '').slice(0, 80);
  const requestId = String(error?.data?.RequestId || error?.requestId || '').replace(/[^a-zA-Z0-9-]/g, '').slice(0, 80);
  return automationError(`${label}请求失败${code ? `（${code}）` : '（网络超时或服务暂不可用）'}${requestId ? `，请求 ID：${requestId}` : ''}；请检查 DNS 权限、凭据、主域名、线路和 TTL`, 502);
}
function selectRecord(records, { rr, type, line }) {
  const named = records.filter((record) => clean(record.name) === clean(rr));
  if (named.some((record) => ['CNAME', 'NS', 'REDIRECT_URL', 'FORWARD_URL', '显性URL', '隐性URL'].includes(record.type) && !(rr === '@' && record.type === 'NS'))) throw automationError('同名 DNS 记录存在 CNAME、委派或 URL 转发冲突，不会覆盖原记录', 409);
  const matching = named.filter((record) => record.type === type && record.line === line);
  if (matching.length > 1) throw automationError('同名、同类型、同线路存在多条解析，请先在云端整理；不会任选一条覆盖', 409);
  const record = matching[0];
  if (record && (!record.id || !record.value || !Number.isFinite(record.ttl))) throw invalid();
  if (record && (record.status?.toUpperCase() !== 'ENABLE' || record.locked || record.weight > 0)) throw automationError('目标解析已暂停、锁定或配置了负载均衡，请先在云端处理', 409);
  return record || null;
}

export class AliyunDdnsClient {
  constructor(config, { dnsClient } = {}) {
    this.config = config;
    this.client = dnsClient || new AliDns.default(new OpenApi.Config({ accessKeyId: config.accessKeyId, accessKeySecret: config.accessKeySecret, regionId: 'cn-hangzhou', endpoint: 'alidns.aliyuncs.com' }));
    this.runtime = new Tea.RuntimeOptions({ autoretry: false, maxAttempts: 1, connectTimeout: 10_000, readTimeout: 15_000 });
  }
  async call(action, input) {
    try { return (await this.client[`${action[0].toLowerCase()}${action.slice(1)}WithOptions`](new AliDns[`${action}Request`](input), this.runtime)).body; }
    catch (error) { throw safeDnsError(error, '阿里云 DNS '); }
  }
  async inspect({ name, type }) {
    const rr = relativeRecord(name, this.config.dnsZone);
    const body = await this.call('DescribeDomainRecords', { domainName: this.config.dnsZone, RRKeyWord: rr, searchMode: 'COMBINATION', pageSize: 500, pageNumber: 1 });
    const records = body?.domainRecords?.record;
    if (!Array.isArray(records) || !Number.isSafeInteger(body.totalCount) || body.totalCount !== records.length || records.some((record) => !record || !record.RR || !record.type || !record.line)) throw invalid();
    return selectRecord(records.map((record) => ({ id: record.recordId, name: record.RR, type: record.type, line: record.line, value: record.value, ttl: record.TTL, status: record.status, locked: record.locked, weight: record.lbaStatus ? 1 : 0 })), { rr, type, line: this.config.line });
  }
  async upsert({ name, type, content, ttl }) {
    const record = await this.inspect({ name, type });
    if (record && sameIp(record.value, content) && record.ttl === ttl) return { changed: false };
    const body = await this.call(record ? 'UpdateDomainRecord' : 'AddDomainRecord', {
      ...(record ? { recordId: record.id } : { domainName: this.config.dnsZone }),
      RR: relativeRecord(name, this.config.dnsZone), type, value: content, TTL: ttl, line: this.config.line,
    });
    if (!body?.recordId || record && String(body.recordId) !== String(record.id)) throw automationError('云端未确认目标记录已更新，下次同步将先核对现有记录', 502);
    return { changed: true };
  }
}

export class DnspodDdnsClient {
  constructor(config, { dnsClient } = {}) {
    this.config = config;
    this.client = dnsClient || new Tencent.dnspod.v20210323.Client({
      credential: { secretId: config.secretId, secretKey: config.secretKey },
      profile: { signMethod: 'TC3-HMAC-SHA256', httpProfile: { endpoint: 'dnspod.tencentcloudapi.com', protocol: 'https://', reqMethod: 'POST', reqTimeout: 15 } },
    });
  }
  async call(action, input) {
    try { return await this.client[action](input); }
    catch (error) { throw safeDnsError(error, '腾讯云 DNSPod '); }
  }
  async inspect({ name, type }) {
    const rr = relativeRecord(name, this.config.dnsZone);
    // ErrorOnEmpty distinguishes an absent record from authentication/domain/transport errors.
    const body = await this.call('DescribeRecordList', { Domain: this.config.dnsZone, SubDomain: rr, Offset: 0, Limit: 3000, ErrorOnEmpty: 'no' });
    const records = body?.RecordList;
    const total = body?.RecordCountInfo?.TotalCount;
    if (!Array.isArray(records) || !Number.isSafeInteger(total) || total !== records.length || records.some((record) => !record || !record.Name || !record.Type || !record.Line || !Number.isSafeInteger(record.RecordId) || record.RecordId <= 0)) throw invalid();
    return selectRecord(records.map((record) => ({ id: record.RecordId, name: record.Name, type: record.Type, line: record.Line, value: record.Value, ttl: record.TTL, status: record.Status, weight: record.Weight })), { rr, type, line: this.config.line });
  }
  async upsert({ name, type, content, ttl }) {
    const record = await this.inspect({ name, type });
    if (record && sameIp(record.value, content) && record.ttl === ttl) return { changed: false };
    const body = await this.call(record ? 'ModifyRecord' : 'CreateRecord', {
      Domain: this.config.dnsZone, SubDomain: relativeRecord(name, this.config.dnsZone), RecordType: type,
      RecordLine: this.config.line, Value: content, TTL: ttl, ...(record ? { RecordId: record.id } : {}),
    });
    if (!Number.isSafeInteger(body?.RecordId) || body.RecordId <= 0 || record && body.RecordId !== record.id) throw automationError('云端未确认目标记录已更新，下次同步将先核对现有记录', 502);
    return { changed: true };
  }
}

export function createDdnsClient(config, { fetchFn = globalThis.fetch } = {}) {
  if (config.provider === 'aliyun') return new AliyunDdnsClient(config.aliyun);
  if (config.provider === 'dnspod') return new DnspodDdnsClient(config.dnspod);
  if (config.provider === 'cloudflare') return new CloudflareDnsClient({ zoneId: config.zoneId, apiToken: config.apiToken, fetchFn });
  throw automationError('不支持的 DDNS 服务商');
}
