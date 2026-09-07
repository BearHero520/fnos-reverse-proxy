import { UISelect } from './UISelect.jsx';
import { IssuanceLog } from './IssuanceLog.jsx';
import { Dialog } from '@base-ui/react/dialog';
import { cloneElement, useEffect, useId, useRef, useState } from 'react';
import { AliyunZoneField } from './AliyunZoneField.jsx';

export const emptyDdns = {
  provider: 'cloudflare', zoneId: '', hasApiToken: false, enabled: false, recordName: '', recordType: 'A', ttl: 1, proxied: false, intervalMinutes: 10,
  aliyun: { accessKeyId: '', hasAccessKeySecret: false, dnsZone: '', line: 'default' },
  dnspod: { secretId: '', hasSecretKey: false, dnsZone: '', line: '默认' },
};
const ddnsProviders = { cloudflare: 'Cloudflare', aliyun: '阿里云 DNS', dnspod: '腾讯云 DNSPod' };
export const emptyIssuance = {
  provider: 'aliyun-free', running: [],
  acme: { zoneId: '', hasApiToken: false, email: '', domains: [], environment: 'staging', autoRenew: false, renewDays: 30, phase: 'idle' },
  aliyun: { apiVersion: 'v2', contactId: '', accessKeyId: '', hasAccessKeySecret: false, domain: '', dnsZone: '', username: '', phone: '', email: '', autoRenew: false, renewDays: 15, phase: 'idle', quota: null, order: null },
};
const moment = (value) => value ? new Date(value).toLocaleString() : '尚未运行';
const date = (value) => value ? new Date(value).toLocaleDateString() : '尚未签发';
const Icon = ({ name }) => <i className={`bi ${name}`} aria-hidden="true" />;
export function Field({ label, hint, children, required = false }) {
  const id = useId();
  return <div className="form-field"><label className="field-label" htmlFor={id}>{label}{required ? <b aria-hidden="true">*</b> : null}</label>{cloneElement(children, { id, 'aria-describedby': hint ? `${id}-hint` : undefined, 'aria-required': required })}{hint ? <small id={`${id}-hint`}>{hint}</small> : null}</div>;
}
export function Check({ checked, onChange, title, description }) {
  return <label className="check-row"><input type="checkbox" checked={Boolean(checked)} onChange={(event) => onChange(event.target.checked)} /><span><strong>{title}</strong><small>{description}</small></span></label>;
}
function Chip({ tone = 'disabled', children }) { return <span className={`state-chip ${tone}`}><Icon name={tone === 'healthy' ? 'bi-check-circle-fill' : tone === 'warning' ? 'bi-exclamation-triangle-fill' : 'bi-circle'} />{children}</span>; }
export function Notice({ children, error = false, focusRef }) { return <aside ref={focusRef} tabIndex={focusRef ? -1 : undefined} className={`automation-notice${error ? ' error' : ''}`} role={error ? 'alert' : 'status'}><Icon name={error ? 'bi-exclamation-triangle' : 'bi-info-circle'} /><span>{children}</span></aside>; }
function Editor({ open, title, description, busy, onClose, onSubmit, children, error, lookupBusy = false }) {
  const errorRef = useRef(null);
  useEffect(() => { if (open && error) { errorRef.current?.scrollIntoView({ block: 'start', behavior: 'auto' }); errorRef.current?.focus({ preventScroll: true }); } }, [open, error]);
  return <Dialog.Root open={open} onOpenChange={(value) => { if (!value && !busy) onClose(); }}><Dialog.Portal><Dialog.Backdrop className="dialog-backdrop" /><Dialog.Popup className="dialog-popup automation-editor"><form onSubmit={onSubmit}><header className="dialog-header"><div><Dialog.Title>{title}</Dialog.Title><Dialog.Description>{description}</Dialog.Description></div><Dialog.Close className="dialog-close" aria-label="关闭设置" disabled={busy}><Icon name="bi-x-lg" /></Dialog.Close></header><div className="dialog-body automation-form">{error ? <Notice error focusRef={errorRef}>{error}</Notice> : null}<fieldset className="automation-fields" disabled={busy}>{children}</fieldset></div><footer className="dialog-actions"><Dialog.Close className="secondary-button" disabled={busy}>取消</Dialog.Close><button type="submit" className="primary-button" disabled={busy || lookupBusy}><Icon name={busy ? 'bi-arrow-repeat' : 'bi-floppy'} />{busy ? '正在保存…' : '保存设置'}</button></footer></form></Dialog.Popup></Dialog.Portal></Dialog.Root>;
}
function CloudflareFields({ draft, set }) {
  return <div className="form-grid two"><Field label="Cloudflare Zone ID"><input value={draft.zoneId} autoComplete="off" onChange={(event) => set('zoneId', event.target.value)} placeholder="目标域名的 Zone ID" /></Field><Field label="API Token" hint={draft.hasApiToken ? '已保存，留空保留；不会回显' : '仅授予目标 Zone 的 DNS 编辑权限'}><input type="password" autoComplete="new-password" value={draft.apiToken || ''} onChange={(event) => set('apiToken', event.target.value)} placeholder={draft.hasApiToken ? '已保存（留空保留）' : 'Cloudflare API Token'} /></Field></div>;
}

function DdnsCloudFields({ provider, draft, set, recordName, savedAccessKeyId, active, locked, onLookupBusy }) {
  const isAliyun = provider === 'aliyun';
  const idKey = isAliyun ? 'accessKeyId' : 'secretId';
  const secretKey = isAliyun ? 'accessKeySecret' : 'secretKey';
  const hasSecret = isAliyun ? draft.hasAccessKeySecret : draft.hasSecretKey;
  const clearKey = isAliyun ? 'clearAccessKeySecret' : 'clearSecretKey';
  return <>
    <div className="form-grid two">
      <Field label={isAliyun ? 'AccessKey ID' : 'SecretId'}><input value={draft[idKey]} autoComplete="off" onChange={(event) => set(idKey, event.target.value)} placeholder={isAliyun ? 'RAM 用户 AccessKey ID' : '腾讯云 API 密钥 SecretId'} /></Field>
      <Field label={isAliyun ? 'AccessKey Secret' : 'SecretKey'} hint={hasSecret ? '已保存，留空保留；不会回显' : '仅保存在本机，不进入导出与诊断包'}><input type="password" value={draft[secretKey] || ''} autoComplete="new-password" onChange={(event) => set(secretKey, event.target.value)} placeholder={hasSecret ? '已保存（留空保留）' : isAliyun ? 'RAM 用户 AccessKey Secret' : '腾讯云 API 密钥 SecretKey'} /></Field>
      {isAliyun ? <AliyunZoneField value={draft.dnsZone} onChange={(value) => set('dnsZone', value)} domain={recordName} credentials={draft} savedAccessKeyId={savedAccessKeyId} scope="ddns" active={active} locked={locked} onBusy={onLookupBusy} /> : <Field label="DNS 主域名" hint="服务商控制台中管理的解析区域"><input value={draft.dnsZone} onChange={(event) => set('dnsZone', event.target.value)} placeholder="example.com" /></Field>}
    </div>
    {hasSecret ? <Check checked={draft[clearKey]} onChange={(value) => set(clearKey, value)} title="清除已保存的 DDNS 密钥" description="仅清除当前服务商的 DDNS 密钥。" /> : null}
    <details className="automation-details"><summary>解析线路与权限</summary>
      <Field label="解析线路" hint={isAliyun ? '填写阿里云线路代码，通常为 default' : '填写 DNSPod 线路名称，通常为「默认」'}><input value={draft.line} onChange={(event) => set('line', event.target.value)} /></Field>
      <p>仅需目标解析区域的查询、添加、修改记录权限，无需删除权限。{isAliyun ? '与证书签发使用独立凭据。' : '使用腾讯云 SecretId / SecretKey，不是旧版 DNSPod Token。'}<a href={isAliyun ? 'https://help.aliyun.com/zh/dns/api-alidns-2015-01-09-overview' : 'https://cloud.tencent.com/document/product/1427/56194'} target="_blank" rel="noreferrer">查看接口说明</a></p>
      {isAliyun ? <p>自动识别另需 <code>alidns:DescribeDomains</code> 查询权限；不授予该权限时仍可手动填写。</p> : null}
    </details>
  </>;
}

export function DdnsPage({ integration, busy, detectBusy, onDetect, onSave, onSync, onTest }) {
  const status = { ...emptyDdns, ...integration, aliyun: { ...emptyDdns.aliyun, ...integration?.aliyun }, dnspod: { ...emptyDdns.dnspod, ...integration?.dnspod } };
  const [open, setOpen] = useState(false);
  const [draft, setDraft] = useState(status);
  const [error, setError] = useState('');
  const [detectType, setDetectType] = useState(status.recordType);
  const [lookupBusy, setLookupBusy] = useState(false);
  const detection = status.detection?.results?.[detectType];
  useEffect(() => { if (open) { setDraft({ ...status, apiToken: '', clearApiToken: false, aliyun: { ...status.aliyun, accessKeySecret: '', clearAccessKeySecret: false }, dnspod: { ...status.dnspod, secretKey: '', clearSecretKey: false } }); setError(''); } }, [open]);
  const set = (key, value) => { setDraft((current) => ({ ...current, [key]: value })); setError(''); };
  const setCloud = (key, value) => { setDraft((current) => ({ ...current, [current.provider]: { ...current[current.provider], [key]: value } })); setError(''); };
  const setProvider = (provider) => { setDraft((current) => ({ ...current, provider, enabled: false, ttl: provider !== 'cloudflare' && Number(current.ttl) === 1 ? 600 : current.ttl })); setError(''); };
  const save = async (event) => { event.preventDefault(); const result = await onSave(draft); if (result === true) setOpen(false); else setError(result?.error?.message || '保存失败，请检查填写内容'); };
  const isCloudflare = status.provider === 'cloudflare';
  const ready = status.recordName && (isCloudflare ? status.zoneId && status.hasApiToken : status.provider === 'aliyun' ? status.aliyun.accessKeyId && status.aliyun.hasAccessKeySecret && status.aliyun.dnsZone : status.dnspod.secretId && status.dnspod.hasSecretKey && status.dnspod.dnsZone);
  return <section className="view automation-page" aria-label="DDNS 同步">
    <article className="matte-surface certificate-surface">
      <div className="section-heading"><div><h2>自动获取公网 IP</h2><p>由 NAS 请求外部检测服务，无需手动填写 IP。</p></div><span className="state-chip disabled">只读检测</span></div>
      <div className="ip-detection-controls"><Field label="检测地址类型"><UISelect value={detectType} disabled={detectBusy} onChange={(event) => setDetectType(event.target.value)}><option value="A">IPv4 · A 记录</option><option value="AAAA">IPv6 · AAAA 记录</option></UISelect></Field><button className="secondary-button" disabled={detectBusy} onClick={() => onDetect(detectType)}><Icon name={detectBusy ? 'bi-arrow-repeat' : 'bi-crosshair'} />{detectBusy ? '正在检测…' : `检测公网 IPv${detectType === 'A' ? '4' : '6'}`}</button></div>
      <dl className="automation-facts" aria-live="polite"><div><dt>{detection?.error && detection.ip ? '上次检测地址（非最新）' : '检测到的公网地址'}</dt><dd className="ip-address">{detection?.ip || (status.demoMode ? '演示模式 · 不读取真实 IP' : '点击检测后显示')}</dd></div><div><dt>检测来源</dt><dd>{detectType === 'A' ? 'api.ipify.org' : 'api6.ipify.org'}</dd></div><div><dt>检测时间</dt><dd>{detection?.detectedAt ? moment(detection.detectedAt) : '尚未检测'}</dd></div></dl>
      {detection?.error ? <Notice error>{detection.error}</Notice> : null}
      <p className="automation-caption">开启「设置 → 定时同步」后，每 {status.intervalMinutes} 分钟重新检测；A 自动获取 IPv4，AAAA 自动获取 IPv6。此处检测不会修改 DNS。</p>
      <details className="automation-details"><summary>有公网地址，为什么仍可能无法访问？</summary><p>检测的是 NAS 的公网出口，不是浏览器设备或局域网 IP。运营商共享地址（CGNAT）、路由器端口映射、防火墙或 VPN 出口都可能影响入站连接；DDNS 仅更新解析，不提供内网穿透。</p></details>
    </article>
    <article className="matte-surface certificate-surface">
      <div className="section-heading"><div><h2>动态 DNS</h2><p>公网地址变化后，自动更新云端解析记录。</p></div><button className="secondary-button" disabled={busy} onClick={() => setOpen(true)}><Icon name="bi-sliders" />设置</button></div>
      <div className="automation-domain"><span className="automation-service-icon"><Icon name="bi-broadcast-pin" /></span><div><strong>{status.recordName || '尚未配置域名'}</strong><small>{ddnsProviders[status.provider]} · {status.recordType} 记录 · {isCloudflare ? status.proxied ? '代理已开启' : '仅 DNS' : status[status.provider]?.line}</small></div><Chip tone={status.lastError ? 'warning' : status.enabled ? 'healthy' : 'disabled'}>{status.lastError ? '同步异常' : status.enabled ? '自动同步' : '手动同步'}</Chip></div>
      <dl className="automation-facts"><div><dt>上次成功同步的 IP</dt><dd>{status.lastIp || '尚未同步'}</dd></div><div><dt>同步频率</dt><dd>{status.enabled ? `每 ${status.intervalMinutes} 分钟` : '定时同步未开启'}</dd></div><div><dt>上次成功</dt><dd>{moment(status.lastSuccessAt)}</dd></div></dl>
      {status.lastError ? <Notice error>{status.lastError}</Notice> : null}
      {status.demoMode ? <Notice>本地演示模式，不会读取公网地址或修改 DNS。</Notice> : null}
      <div className="automation-actions"><button className="primary-button" disabled={busy || !ready} title={!ready ? '先设置凭据和记录名称' : ''} onClick={onSync}><Icon name={busy ? 'bi-arrow-repeat' : 'bi-arrow-clockwise'} />{busy ? '正在处理…' : '立即同步'}</button><button className="secondary-button" disabled={busy || !ready} onClick={onTest} title="查询已保存配置，不修改 DNS"><Icon name="bi-plug" />测试连接</button><small>{ready ? '查询测试不写入；地址和设置未变时不重复更新' : '支持 Cloudflare、阿里云、腾讯云 DNSPod'}</small></div>
    </article>
    <Editor open={open} title="DDNS 设置" description="这里只负责地址同步，不影响证书签发。" busy={busy} lookupBusy={lookupBusy} onClose={() => setOpen(false)} onSubmit={save} error={error}>
      <section className="form-card">
        <Field label="DNS 服务商" hint="域名的权威 DNS 需托管在所选服务商；每次同步一个目标。"><UISelect value={draft.provider} onChange={(event) => setProvider(event.target.value)}>{Object.entries(ddnsProviders).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</UISelect></Field>
        {draft.provider !== status.provider ? <Notice>切换服务商已暂停定时同步；确认配置后可重新开启。原服务商凭据会保留。</Notice> : null}
        {draft.provider === 'cloudflare' ? <><CloudflareFields draft={draft} set={set} />{draft.hasApiToken ? <Check checked={draft.clearApiToken} onChange={(value) => set('clearApiToken', value)} title="清除已保存的 DDNS 令牌" description="仅清除 DDNS 的凭据，不影响证书签发。" /> : null}</> : <DdnsCloudFields key={draft.provider} provider={draft.provider} draft={draft[draft.provider]} set={setCloud} recordName={draft.recordName} savedAccessKeyId={status.aliyun.accessKeyId} active={open} locked={busy} onLookupBusy={setLookupBusy} />}
      </section>
      <section className="form-card">
        <Check checked={draft.enabled} onChange={(value) => set('enabled', value)} title="启用定时同步" description="应用运行期间按设定周期检查公网地址。" />
        <div className="form-grid two">
          <Field label="完整记录名称" hint="根域名直接填 example.com，子域名填 home.example.com"><input value={draft.recordName} onChange={(event) => set('recordName', event.target.value)} placeholder="home.example.com" /></Field>
          <Field label="记录类型"><UISelect value={draft.recordType} onChange={(event) => set('recordType', event.target.value)}><option value="A">A · IPv4</option><option value="AAAA">AAAA · IPv6</option></UISelect></Field>
          <Field label="检查间隔（分钟）" hint="5–1440 分钟"><input type="number" min="5" max="1440" value={draft.intervalMinutes} onChange={(event) => set('intervalMinutes', event.target.value)} /></Field>
          <Field label="TTL（秒）" hint={draft.provider === 'cloudflare' ? '1 为自动，其他值至少 60' : '建议 600 秒，最低值以云端套餐为准'}><input type="number" min={draft.provider === 'cloudflare' ? 1 : 60} max="86400" value={draft.ttl} onChange={(event) => set('ttl', event.target.value)} /></Field>
        </div>
        {draft.provider === 'cloudflare' ? <Check checked={draft.proxied} onChange={(value) => set('proxied', value)} title="启用 Cloudflare 代理" description="仅适用于 Cloudflare 支持代理的 Web 端口。" /> : null}
      </section>
    </Editor>
  </section>;
}

const phases = { idle: '待配置 / 待签发', checking: '检查免费额度', creating: '提交申请', uncertain: '需要核对订单', pending: '等待订单信息', domain_verify: 'DNS 验证中', process: 'CA 审核中', verify_fail: '审核未通过', payed: '需要在云端提交申请', unknown: '等待云端状态', cleanup: '清理验证记录', issued: '已签发', issuing: '正在签发', error: '上次操作失败' };
function IssuanceEditor({ open, provider, integration, busy, onClose, onSave, expectedDomains = [] }) {
  const isAliyun = provider === 'aliyun-free';
  const config = isAliyun ? integration.aliyun : integration.acme;
  const [lookupBusy, setLookupBusy] = useState(false);
  const [draft, setDraft] = useState(config);
  const [error, setError] = useState('');
  useEffect(() => { if (open) { setDraft({ ...config, accessKeySecret: '', apiToken: '', domainsText: (expectedDomains.length ? expectedDomains : config.domains || []).join('\n'), ...(isAliyun && expectedDomains.length && !config.order ? { domain: expectedDomains[0], dnsZone: config.domain === expectedDomains[0] ? config.dnsZone : '' } : {}) }); setError(''); } }, [open]);
  const set = (key, value) => { setDraft((current) => ({ ...current, [key]: value })); setError(''); };
  const save = async (event) => {
    event.preventDefault();
    const payload = isAliyun ? { aliyun: Object.fromEntries(['apiVersion', 'contactId', 'accessKeyId', 'accessKeySecret', 'domain', 'dnsZone', 'username', 'phone', 'email', 'autoRenew', 'renewDays'].map((key) => [key, draft[key]])) } : { acme: { ...draft, domains: draft.domainsText.split(/[,，;；\s]+/).map((item) => item.trim()).filter(Boolean) } };
    const result = await onSave(payload);
    if (result === true) onClose(); else setError(result?.error?.message || '保存失败，请检查填写内容');
  };
  return <Editor open={open} title={isAliyun ? '阿里云免费证书设置' : 'ACME 签发设置'} description={isAliyun ? '只需 AccessKey 和证书域名，DNS 主域名自动识别。' : '使用独立的 Cloudflare 凭据完成 DNS-01 验证。'} busy={busy} lookupBusy={lookupBusy} onClose={onClose} onSubmit={save} error={error}>
    {expectedDomains.length && config.certificateId ? <Notice>此服务目前使用一组签发域名。保存不同域名会调整后续自动轮换范围；原证书及其代理规则保持不变。</Notice> : null}
    <section className="form-card">{isAliyun ? <><Field label="阿里云证书版本" hint="切换版本会暂停自动轮换，正在处理的申请不允许切换。"><UISelect value={draft.apiVersion} disabled={Boolean(config.order)} onChange={(event) => { set('apiVersion', event.target.value); set('autoRenew', false); }}><option value="v2">新版 V2.0 · 已领取实例</option><option value="v1">旧版 V1.0 · 历史资源包</option></UISelect></Field><div className="form-grid two"><Field label="AccessKey ID"><input value={draft.accessKeyId} autoComplete="off" disabled={Boolean(config.order)} onChange={(event) => set('accessKeyId', event.target.value)} placeholder="RAM 用户 AccessKey ID" /></Field><Field label="AccessKey Secret" hint={draft.hasAccessKeySecret ? '已保存，留空保留；不会回显' : '仅保存在本机，不进入导出与诊断包'}><input type="password" autoComplete="new-password" value={draft.accessKeySecret} onChange={(event) => set('accessKeySecret', event.target.value)} placeholder={draft.hasAccessKeySecret ? '已保存（留空保留）' : 'RAM 用户 AccessKey Secret'} /></Field><Field label="证书域名" hint="免费套餐仅支持单个域名"><input value={draft.domain} disabled={Boolean(config.order)} onChange={(event) => set('domain', event.target.value)} placeholder="home.example.com" /></Field><AliyunZoneField value={draft.dnsZone} onChange={(value) => set('dnsZone', value)} domain={draft.domain} credentials={draft} savedAccessKeyId={config.accessKeyId} scope="certificate-issuance" active={open} locked={busy || Boolean(config.order)} onBusy={setLookupBusy} /></div>{config.order ? <Notice>订单处理期间锁定域名与账号；仍可更新 Secret 或关闭自动轮换。</Notice> : null}<details className="automation-details"><summary>联系人与权限说明</summary>{draft.apiVersion === 'v2' ? <Field label="联系人 ID（可选）" hint="优先复用实例联系人；账号只有一个联系人时自动使用。"><input inputMode="numeric" value={draft.contactId || ''} onChange={(event) => set('contactId', event.target.value)} /></Field> : <><p>可选：仅在云端提示缺少联系人时填写。</p><div className="form-grid two"><Field label="联系人姓名"><input value={draft.username} onChange={(event) => set('username', event.target.value)} autoComplete="name" /></Field><Field label="手机号码"><input type="tel" value={draft.phone} onChange={(event) => set('phone', event.target.value)} autoComplete="tel" /></Field><Field label="联系邮箱"><input type="email" value={draft.email} onChange={(event) => set('email', event.target.value)} autoComplete="email" /></Field></div></>}<p>RAM 需允许新版实例列表/详情、更新实例、申请、任务查询、下载证书与联系人查询；旧版需要证书额度查询、申请、订单查询，以及目标 DNS 区域的查询、添加和删除记录。自动识别另需 alidns:DescribeDomains 查询权限；也可手动填写主域名。<a href={draft.apiVersion === 'v2' ? 'https://help.aliyun.com/zh/ssl-certificate/product-overview/announcement-ssl-certificate-v2-0-api-interface-release-notes' : 'https://help.aliyun.com/zh/ssl-certificate/developer-reference/api-cas-2020-04-07-createcertificateforpackagerequest'} target="_blank" rel="noreferrer">查看接口权限</a></p></details></> : <><CloudflareFields draft={draft} set={set} /><div className="form-grid two"><Field label="联系邮箱"><input type="email" value={draft.email} onChange={(event) => set('email', event.target.value)} placeholder="admin@example.com" /></Field><Field label="签发环境"><UISelect value={draft.environment} onChange={(event) => set('environment', event.target.value)}><option value="staging">测试环境 · 不受浏览器信任</option><option value="production">正式环境 · 受签发限额约束</option></UISelect></Field></div><Field label="证书域名" hint="逗号、空格或换行分隔，支持通配符"><textarea rows="3" value={draft.domainsText} onChange={(event) => set('domainsText', event.target.value)} placeholder={'example.com\n*.example.com'} /></Field><Notice>测试证书独立保存，不会覆盖正在使用的正式证书。</Notice></>}</section>
    <section className="form-card"><Check checked={draft.autoRenew} onChange={(value) => set('autoRenew', value)} title="到期前自动轮换" description="先签发新证书，成功后保留原 ID 和规则绑定并热更新；失败保留旧证书。" /><details className="automation-details"><summary>高级轮换设置</summary><Field label="提前轮换（天）" hint={isAliyun ? '7–30 天，默认提前 15 天' : '7–60 天，默认提前 30 天'}><input type="number" min="7" max={isAliyun ? 30 : 60} value={draft.renewDays} onChange={(event) => set('renewDays', event.target.value)} /></Field></details>{isAliyun ? <Notice>每次重新签发使用免费额度；额度不足时停止申请，不会购买付费证书。</Notice> : null}</section>
  </Editor>;
}

export function IssuancePage({ integration, certificates, busy, onSave, onIssue, onQuota, onAssociate, onRetry, onReset, onCertificates, onRefresh, expectedDomains = [] }) {
  const status = { ...emptyIssuance, ...integration, acme: { ...emptyIssuance.acme, ...integration?.acme }, aliyun: { ...emptyIssuance.aliyun, ...integration?.aliyun } };
  const isAliyun = status.provider === 'aliyun-free';
  const isV2 = status.aliyun.apiVersion === 'v2';
  const config = isAliyun ? status.aliyun : status.acme;
  const [open, setOpen] = useState(false);
  const [orderId, setOrderId] = useState('');
  const [localError, setLocalError] = useState('');
  const running = busy || status.running?.length > 0;
  const domainKey = (values) => [...new Set(values.map((value) => value.trim().toLowerCase()))].sort().join(',');
  const scopeMatches = !expectedDomains.length || domainKey(expectedDomains) === domainKey(isAliyun ? [config.domain || ''] : config.domains);
  const ready = scopeMatches && (isAliyun ? config.accessKeyId && config.hasAccessKeySecret && config.domain && config.dnsZone : config.zoneId && config.hasApiToken && config.email && config.domains.length);
  const certificate = certificates.find((item) => item.id === config.certificateId);
  const pending = isAliyun && config.order;
  const needsAssociation = pending && !pending.id;
  const issue = () => {
    if (!pending && (isAliyun || config.environment === 'production') && !window.confirm(isAliyun ? '将使用阿里云免费额度申请一张新证书，不会购买付费套餐。继续吗？' : '正式签发将计入 Let’s Encrypt 限额。继续吗？')) return;
    void onIssue();
  };
  const retry = () => { if (window.confirm('重新申请可能使用新的免费额度。建议先在阿里云处理失败订单，确定继续吗？')) void onRetry(); };
  const reset = () => { if (window.confirm('请先在阿里云控制台确认：本次申请没有生成任何订单。重置后将清除本次申请并关闭自动轮换，旧证书不变。确认云端没有订单吗？')) void onReset(); };
  const associate = async (event) => { event.preventDefault(); const result = await onAssociate(orderId); if (result !== true) setLocalError(result?.error?.message || '关联失败'); else { setLocalError(''); setOrderId(''); } };
  const renewalAt = certificate?.validTo ? new Date(Date.parse(certificate.validTo) - config.renewDays * 86400000).toLocaleDateString() : null;
  return <section className="view automation-page" aria-label="证书签发">
    {expectedDomains.length ? <Notice>当前规则域名：{expectedDomains.join('、')}。{!scopeMatches ? '请先打开设置，确认并保存这些域名。' : '申请成功后自动选入当前规则，保存规则后生效。'}{isAliyun && expectedDomains.length > 1 ? '阿里云免费证书仅支持单域名，请使用 Let’s Encrypt 或上传多域名证书。' : ''}</Notice> : null}
    <div className="issuance-providers" aria-label="证书签发服务">{[['aliyun-free', '阿里云免费证书', '中国站 · 单域名 · 免费额度', 'bi-cloud-check'], ['acme', 'Let’s Encrypt', 'Cloudflare DNS-01 · 支持通配符', 'bi-shield-check']].map(([value, label, note, icon]) => <button key={value} type="button" aria-pressed={status.provider === value} className={`issuance-provider${status.provider === value ? ' selected' : ''}`} disabled={running} onClick={() => { if (value !== status.provider) void onSave({ provider: value }); }}><Icon name={icon} /><span><strong>{label}</strong><small>{note}</small></span><Icon name={status.provider === value ? 'bi-check-circle-fill' : 'bi-circle'} /></button>)}</div>
    <article className="matte-surface certificate-surface"><div className="section-heading"><div><h2>{isAliyun ? '阿里云自动签发' : 'ACME 自动签发'}</h2><p>{isAliyun ? (isV2 ? '使用已领取的免费实例，自动验证、签发并轮换。' : '使用旧版资源包，自动验证、签发并轮换。') : 'DNS-01 签发与轮换，不依赖 DDNS 是否启用。'}</p></div><button className="secondary-button" disabled={running} onClick={() => setOpen(true)}><Icon name="bi-sliders" />设置</button></div>
      <div className="automation-domain"><span className="automation-service-icon"><Icon name="bi-shield-lock" /></span><div><strong>{isAliyun ? config.domain || '尚未配置证书域名' : config.domains.join('、') || '尚未配置证书域名'}</strong><small>{config.autoRenew ? `提前 ${config.renewDays} 天自动轮换` : '自动轮换未开启'}{!isAliyun ? ` · ${config.environment === 'production' ? '正式环境' : '测试环境'}` : ''}</small></div><Chip tone={config.lastError ? 'warning' : config.phase === 'issued' ? 'healthy' : 'disabled'}>{running ? '正在处理' : phases[config.phase] || config.phase}</Chip></div>
      <dl className="automation-facts"><div><dt>当前证书到期</dt><dd>{date(certificate?.validTo)}</dd></div><div><dt>预计开始轮换</dt><dd>{config.autoRenew ? renewalAt || '首次自动申请' : '自动轮换未开启'}</dd></div><div><dt>最近成功签发</dt><dd>{moment(config.lastSuccessAt)}</dd></div></dl>
      {isAliyun ? <><ol className="issuance-progress" aria-label="签发流程">{['免费额度', 'DNS 验证', 'CA 签发', '热更新'].map((label, index) => <li key={label} className={index === (['issued', 'cleanup'].includes(config.phase) ? 3 : config.phase === 'process' ? 2 : config.phase === 'domain_verify' ? 1 : 0) && config.phase !== 'idle' ? 'current' : ''}><span>{index + 1}</span>{label}</li>)}</ol><div className="issuance-quota"><div><strong>{isV2 ? '已领取的免费实例' : '自动申请资源包'}</strong><span>{config.quota ? `${config.quota.estimated ? '最多可申请' : '可用'} ${config.quota.remaining} / ${isV2 ? '实例' : '资源包'} ${config.quota.total}` : '尚未查询'}<small>{config.quota ? `已申请 ${config.quota.used} · 已签发 ${config.quota.issued} · ${moment(config.quota.checkedAt)}` : (isV2 ? '查询可供此域名使用的空闲免费实例' : '查询当前 AccessKey 的旧版免费资源包')}</small></span></div><button className="secondary-button compact-button" disabled={running || !config.accessKeyId || !config.hasAccessKeySecret} onClick={onQuota}><Icon name="bi-arrow-clockwise" />查询额度</button></div><details className="automation-details" open={Boolean(config.quota && config.quota.remaining === 0)}><summary>免费实例与自动轮换</summary><p>{isV2 ? '先在阿里云领取免费实例，应用会自动选取空闲实例完成申请、DNS 验证与下载。临期轮换使用下一张空闲实例；用完后停止并提醒，不会下单。' : '旧版累计申请次数包含失败申请；可申请上限按总额减已签发估算，以云端受理为准。'}</p><p><a href="https://yundun.console.aliyun.com/?p=cas_buy&amp;microFrontVersionName=newInstance#/testSSL/cn-hangzhou" target="_blank" rel="noreferrer">领取免费实例</a> · <a href="https://yundun.console.aliyun.com/?p=cas#/instance/test/cn-hangzhou" target="_blank" rel="noreferrer">查看新版实例</a></p><p>选择「个人测试证书（免费）＋基础版＋不需要人工服务」，确认应付 ¥0。未知规格和付费证书不会使用。</p>{config.quota?.excluded ? <p>另有 {config.quota.excluded} 个实例未能确认为支持的免费规格，已排除。</p> : null}</details>{pending ? <Notice>{pending.id ? `订单 ${pending.id} · ${phases[pending.phase] || pending.phase}${pending.dnsName ? ` · ${pending.dnsName}` : ''}` : '提交结果待核对。请从阿里云控制台找到本次申请的订单 ID，关联后继续。'}<small>关闭页面或重启应用不会重复申请；正在处理的订单会继续跟进。</small></Notice> : null}{needsAssociation ? <form className="associate-order" onSubmit={associate}><Field label="关联本次申请的订单 ID"><input inputMode="numeric" pattern="[0-9]+" required value={orderId} onChange={(event) => setOrderId(event.target.value)} placeholder="阿里云控制台中的订单 ID" /></Field><button className="secondary-button" disabled={running}>关联订单</button></form> : null}</> : null}
      {localError || config.lastError ? <Notice error>{localError || config.lastError}</Notice> : null}
      {needsAssociation ? <div className="automation-actions"><button type="button" className="secondary-button" disabled={running} onClick={reset}>确认无订单，重置申请</button></div> : null}
      {status.demoMode ? <Notice>本地演示模式，不请求云端、不消耗额度，不生成真实证书。</Notice> : null}
      {!certificate && !pending ? <p className="automation-purpose">{expectedDomains.length ? "签发成功后自动选入当前规则，保存规则后生效。" : "在代理规则的 HTTPS 与证书中选择此证书，后续轮换自动更新。"}</p> : null}
      <div className="automation-actions"><button className="primary-button" disabled={running || !ready || needsAssociation || pending?.phase === 'verify_fail'} title={!ready ? '先完成签发设置' : ''} onClick={issue}><Icon name={running ? 'bi-arrow-repeat' : pending ? 'bi-arrow-clockwise' : 'bi-shield-plus'} />{running ? '正在处理…' : pending ? '继续查询订单' : certificate ? '立即轮换' : '立即签发'}</button>{pending?.phase === 'verify_fail' ? <button className="secondary-button" disabled={running || !scopeMatches} onClick={retry}>重新申请</button> : null}<button className="secondary-button" onClick={onCertificates}><Icon name="bi-collection" />查看证书</button>{isAliyun ? <a href="https://yundun.console.aliyun.com/?p=cas" target="_blank" rel="noreferrer">领取额度 / 查看订单<Icon name="bi-box-arrow-up-right" /></a> : null}</div>
    </article>{status.provider === 'aliyun-free' ? <IssuanceLog status={status} onRefresh={onRefresh} /> : null}<IssuanceEditor open={open} provider={status.provider} integration={status} expectedDomains={expectedDomains} busy={running} onClose={() => setOpen(false)} onSave={onSave} />
  </section>;
}
