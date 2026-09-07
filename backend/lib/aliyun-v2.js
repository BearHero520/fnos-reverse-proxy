import Cas from '@alicloud/cas20200407';
import { AliyunClient, automationError } from './aliyun-client.js';

const normalize = (s) => String(s || '').trim().toLowerCase().replace(/\.$/, '');
const timestamp = (n) => Number(n) < 1e12 ? Number(n) * 1000 : Number(n);
const positiveId = (n) => Number.isSafeInteger(n) && n > 0;
const instanceId = (id) => typeof id === 'string' && /^cas[-_][a-zA-Z0-9_-]{1,100}$/.test(id);
const noInstance = () => automationError('没有可用的新版免费实例。请在阿里云领取「个人测试证书（免费）＋基础版」，确认 ¥0 后回到这里重试；不会购买或续购付费套餐。');

// Only the short-duration TEST DV SKU is eligible. Unknown SKUs, missing
// subscription dates, PRO durations and formal certificates fail closed.
export function isFreeInstance(item) {
  const duration = timestamp(item.orderEndTime) - timestamp(item.orderStartTime);
  return instanceId(item.instanceId) && item.instanceType === 'TEST' && item.certificateType === 'DV'
    && item.spec === 'ss.dv.t' && item.fullDomainCount === 1 && item.wildcardDomainCount === 0
    && Number.isFinite(duration) && duration > 0 && duration <= 100 * 86400000
    && !['payed', 'issued'].includes(item.upgradeStatus);
}

export function isUnusedInstance(item, domain) {
  return isFreeInstance(item) && item.status === 'inactive' && !item.certificateId
    && !item.csr && (!item.pendingResult || item.pendingResult === 'none')
    && (!normalize(item.domain) || normalize(item.domain) === domain)
    && (!item.usingProductList || item.usingProductList.length === 0);
}

export class AliyunV2Client extends AliyunClient {
  constructor(config, options) { super(config, options); this.config = config; }
  rpc(action, input) { return this.call(this.cas, Cas, action, input); }
  async instances() {
    const rows = []; let total;
    for (let page = 1; page <= 20; page += 1) {
      const body = await this.rpc('ListInstances', { instanceType: 'TEST', currentPage: page, showSize: 100 });
      if (!Number.isSafeInteger(body.totalCount) || body.totalCount < 0 || !Array.isArray(body.instanceList)
        || (total !== undefined && total !== body.totalCount)) throw automationError('新版实例列表不完整或发生变化，请重试', 502);
      total = body.totalCount;
      rows.push(...body.instanceList);
      if (rows.length >= total) {
        if (rows.length !== total || new Set(rows.map((r) => r.instanceId)).size !== rows.length) throw automationError('新版实例列表重复或不完整', 502);
        return rows;
      }
      if (!body.instanceList.length) break;
    }
    throw automationError('新版实例数量过多或分页不完整，请在控制台核对', 502);
  }
  async quota() {
    const all = await this.instances();
    const free = all.filter(isFreeInstance);
    const usable = free.filter((item) => isUnusedInstance(item, this.config.domain));
    return { total: free.length, used: free.length - usable.length, issued: free.filter((r) => r.certificateId).length,
      remaining: usable.length, excluded: all.length - free.length, estimated: false, scope: 'v2-instances', checkedAt: new Date().toISOString() };
  }
  async detail(id) {
    if (!instanceId(id)) throw automationError('新版实例 ID 无效');
    const body = await this.rpc('GetInstanceDetail', { instanceId: id });
    if (body.instanceId !== id || !isFreeInstance(body)) throw automationError('实例规格无法确认为短期个人测试证书，已停止；请检查是否选择免费版、是否已升级');
    return body;
  }
  async select() {
    const candidates = (await this.instances()).filter((r) => isUnusedInstance(r, this.config.domain))
      .sort((a, b) => Number(Boolean(b.domain)) - Number(Boolean(a.domain)) || a.instanceId.localeCompare(b.instanceId));
    for (const candidate of candidates) {
      const detail = await this.detail(candidate.instanceId);
      if (isUnusedInstance(detail, this.config.domain)) return detail;
    }
    throw noInstance();
  }
  async contacts(detail) {
    if (this.config.contactId) return [Number(this.config.contactId)];
    if (detail.contactIdList?.length && detail.contactIdList.every(positiveId)) return detail.contactIdList;
    const body = await this.rpc('ListContact', { currentPage: 1, showSize: 100 });
    if (body.totalCount !== 1 || body.contactList?.length !== 1 || !positiveId(body.contactList[0].contactId))
      throw automationError('请在阿里云设置一个证书联系人；存在多个联系人时，在高级设置填写要使用的联系人 ID。无需在本应用保存姓名、手机和邮箱。');
    return [body.contactList[0].contactId];
  }
  async configure(order) {
    const detail = await this.detail(order.id);
    if (detail.status !== 'inactive' || detail.certificateId || (detail.csr && detail.csr.trim() !== order.csr.trim())
      || (normalize(detail.domain) && normalize(detail.domain) !== order.domain)) throw automationError('实例已被其他操作占用，停止申请并保留当前订单');
    await this.rpc('UpdateInstance', { instanceId: order.id, domain: order.domain, csr: order.csr,
      generateCsrMethod: 'upload', validationMethod: 'DNS', keyAlgorithm: 'RSA_2048',
      autoReissue: 'disable', contactIdList: order.contactIds });
  }
  async prepareApply(order) {
    const detail = await this.detail(order.id);
    this.assertBinding(detail, order);
    if (detail.status !== 'inactive' || detail.certificateId) throw automationError('实例已提交或状态已变化；请继续查询，不会再次提交');
  }
  apply(order) { return this.rpc('ApplyCertificate', { instanceId: order.id }); }
  assertBinding(detail, order) {
    if (normalize(detail.domain) !== order.domain || !detail.csr || detail.csr.trim() !== order.csr.trim()
      || detail.validationMethod !== 'DNS' || detail.generateCsrMethod !== 'upload' || detail.autoReissue !== 'disable')
      throw automationError('云端实例的域名、CSR 或验证设置已变化，已停止以保护原证书');
  }
  task(id) { return this.rpc('GetTaskAttribute', { taskId: id, taskType: 'ApplyCertificate' }); }
  async download(detail) {
    if (!positiveId(detail.certificateId)) throw automationError('云端尚未返回有效证书 ID');
    const body = await this.rpc('GetUserCertificateDetail', { certId: detail.certificateId, certFilter: false });
    if (body.id !== detail.certificateId || body.instanceId !== detail.instanceId || !body.cert)
      throw automationError('下载证书与实例不一致或内容缺失，旧证书保持不变', 502);
    return body.cert; // Never use or persist the cloud-returned private key.
  }
  validationRecords(detail, order, zone) {
    if (!Array.isArray(detail.domainValidationList) || detail.domainValidationList.length > 10) throw automationError('云端域名验证信息不完整');
    return detail.domainValidationList.map((r) => {
      if (normalize(r.domain) !== order.domain || !['TXT', 'CNAME'].includes(r.validationType)) throw automationError('云端返回其他域名或不支持的验证方式，停止 DNS 写入');
      const root = normalize(r.rootDomain);
      if (!root || (order.domain !== root && !order.domain.endsWith(`.${root}`))) throw automationError('云端验证主域名不匹配');
      const key = normalize(r.validationKey);
      // ValidationKey is relative to RootDomain, not necessarily the hosted zone.
      const name = key === '@' ? root : key === root || key.endsWith(`.${root}`) ? key : `${key}.${root}`;
      if (!(name === zone || name.endsWith(`.${zone}`)) || !key || !r.validationValue) throw automationError('验证记录不属于所选 DNS 区域或内容为空');
      // Reuse the guarded AliDNS writer. No guessed challenge names.
      return { validateType: 'DNS', recordType: r.validationType, recordDomain: name, recordValue: r.validationValue, allowApexValidation: true };
    });
  }
}

export async function advanceAliyunV2(service) {
  const config = service.store.issuanceConfig().aliyun;
  const client = service.client(config);
  const patch = (value) => service.store.patchIssuance('aliyun', value);
  let order = config.order;
  const save = (value) => { order = { ...order, ...value }; patch({ order, phase: order.phase }); };
  patch({ lastRunAt: new Date().toISOString(), lastError: null });
  if (!order) {
    const quota = await client.quota(); patch({ quota });
    if (!quota.remaining) throw noInstance();
    await client.checkZone(config.dnsZone);
    const selected = await client.select();
    const contactIds = await client.contacts(selected);
    const [key, csr] = await service.acme.crypto.createCsr({ commonName: config.domain, altNames: [config.domain] });
    order = { id: selected.instanceId, apiVersion: 'v2', phase: 'pending', stage: 'configure', domain: config.domain,
      createdAt: new Date().toISOString(), privateKeyPem: key.toString(), csr: csr.toString(), contactIds, dnsRecords: [] };
    patch({ order, phase: order.phase }); // Intent/key before any cloud mutation.
  }
  if (order.stage === 'cleanup') {
    await service.cleanup(client, order); patch({ order: null, phase: 'issued' });
    return { ok: true, certificateId: config.certificateId };
  }
  if (order.stage === 'configure') { await client.configure(order); save({ stage: 'ready' }); }
  if (order.stage === 'ready') {
    await client.prepareApply(order);
    save({ stage: 'submitted' }); // Crash/timeout: only query this instance thereafter.
    await client.apply(order);
  }
  const detail = await client.detail(order.id);
  client.assertBinding(detail, order);
  if (detail.certificateStatus === 'issued' && detail.certificateId) {
    const certificatePem = await client.download(detail);
    const saved = await service.onCertificate({ name: `阿里云 · ${order.domain}`, provider: 'aliyun-free', environment: 'production',
      domains: [order.domain], targetCertificateId: config.certificateId, certificatePem, privateKeyPem: order.privateKeyPem, orderId: order.id });
    order = { ...order, stage: 'cleanup', phase: 'issued', privateKeyPem: '', csr: '' };
    patch({ order, phase: 'issued', certificateId: saved.certificate.id, lastSuccessAt: new Date().toISOString(), lastError: null });
    await service.cleanup(client, order); patch({ order: null });
    return { ok: true, ...saved };
  }
  if (['closed', 'refund', 'expired'].includes(detail.status)) throw automationError('新版实例已关闭或到期，请在控制台处理；不会购买替代证书');
  const task = await client.task(order.id);
  if (task.taskStatus === 'failed') { save({ phase: 'verify_fail' }); throw automationError('新版证书申请未通过，请在阿里云核对联系人和申请信息后重试；旧证书不变'); }
  if (!['processing', 'success'].includes(task.taskStatus)) throw automationError('提交结果尚未确认，请在控制台核对该实例；不会重复提交');
  const records = client.validationRecords(detail, order, config.dnsZone);
  for (const validation of records) {
    const record = await client.ensureRecord(config.dnsZone, validation);
    if (!order.dnsRecords.some((r) => r.id === record.id)) save({ dnsRecords: [...order.dnsRecords, record] });
  }
  save({ phase: records.length ? 'domain_verify' : 'process', dnsName: records[0]?.recordDomain });
  return { pending: true, orderId: order.id, phase: order.phase };
}
