import { Dialog } from '@base-ui/react/dialog';
import { cloneElement, isValidElement, useCallback, useDeferredValue, useEffect, useId, useMemo, useRef, useState } from 'react';
import { api, apiUrl } from './api.js';

const ROUTES = {
  rules: { label: '代理规则', icon: 'bi-diagram-3', title: '代理规则', description: '查看来源到目标的实际流向，集中管理全部转发。' },
  certificates: { label: '证书', icon: 'bi-shield-lock', title: '证书', description: '仅在本应用接收并解密 HTTPS / WSS 时使用；TCP / UDP 原样转发不需要证书。' },
  logs: { label: '日志', icon: 'bi-file-earmark-text', title: '日志', description: '查看运行事件，快速定位监听与目标连接问题。' },
  settings: { label: '设置', icon: 'bi-gear', title: '设置', description: '调整检测频率、备份配置并查看系统信息。' },
  about: { label: '关于', icon: 'bi-info-circle', title: '关于', description: '查看版本、项目地址与许可信息。' },
};

const PROJECT_URL = 'https://github.com/BearHero520/fnos-reverse-proxy';

const blankRule = {
  name: '', protocol: 'http', protocols: ['http'], listenHost: '0.0.0.0', listenPort: 8080, listenPortStart: 8080, listenPortEnd: 8080, listenPorts: [8080], listenPortsText: '8080', domains: [],
  targetProtocol: 'http', targetProtocols: ['http'], targetHost: '127.0.0.1', targetPort: 80, targetPortStart: 80, targetPortEnd: 80, targetPorts: [80], targetPortsText: '80', enabled: true,
  timeoutMs: 30000, uploadLimitMb: 50, preserveHost: false, hsts: false, forceHttps: false,
  rejectUnauthorized: true, customHeaders: {}, allowIps: [], blockIps: [],
  realIp: { enabled: true, header: 'X-Forwarded-For' }, tls: { certId: '' },
};

const protocolLabels = { http: 'HTTP', ws: 'WebSocket', https: 'HTTPS', wss: 'WSS', tcp: 'TCP', udp: 'UDP', 'tcp+udp': 'TCP + UDP' };
const sourceProtocolOptions = [
  ['http', 'HTTP', '网页与 API'], ['ws', 'WebSocket', '长连接升级'], ['https', 'HTTPS', 'TLS 加密网页'],
  ['wss', 'WSS', 'TLS 长连接'], ['tcp', 'TCP', 'SSH、数据库'], ['udp', 'UDP', '游戏与实时数据'],
];
const targetProtocolOptions = [
  ['http', 'HTTP', '明文 Web'], ['ws', 'WebSocket', '长连接目标'], ['https', 'HTTPS', '加密 Web'],
  ['wss', 'WSS', '加密长连接'], ['tcp', 'TCP', '流式目标'], ['udp', 'UDP', '数据报目标'],
];
const protocolFamilyGroups = [
  { key: 'plain-web', label: 'Web 明文', protocols: ['http', 'ws'] },
  { key: 'secure-web', label: 'Web 加密', protocols: ['https', 'wss'] },
  { key: 'transport', label: '端口转发', protocols: ['tcp', 'udp'] },
];
const tcpFamilyFor = (protocol) => ['http', 'ws'].includes(protocol) ? 'plain-web' : ['https', 'wss'].includes(protocol) ? 'secure-web' : protocol === 'tcp' ? 'tcp' : null;
const tcpFamilyLabels = { 'plain-web': 'HTTP / WebSocket', 'secure-web': 'HTTPS / WSS', tcp: 'TCP' };
const activeTcpFamily = (protocols = []) => protocols.map(tcpFamilyFor).find(Boolean) || null;
const sourceDisabledReasons = (protocols = []) => {
  const activeFamily = activeTcpFamily(protocols);
  return Object.fromEntries(sourceProtocolOptions.map(([protocol]) => {
    const candidateFamily = tcpFamilyFor(protocol);
    const reason = !protocols.includes(protocol) && activeFamily && candidateFamily && candidateFamily !== activeFamily
      ? `${tcpFamilyLabels[activeFamily]} 已使用当前端口；请先取消已选项`
      : '';
    return [protocol, reason];
  }));
};
const targetDisabledReasons = (source = [], targets = []) => {
  const activeFamily = activeTcpFamily(targets);
  const sourceHasWeb = hasWebProtocol(source);
  return Object.fromEntries(targetProtocolOptions.map(([protocol]) => {
    if (targets.includes(protocol)) return [protocol, ''];
    if (protocol === 'tcp' && !source.includes('tcp')) return [protocol, '来源未启用 TCP'];
    if (protocol === 'udp' && !source.includes('udp')) return [protocol, '来源未启用 UDP'];
    if (['http', 'ws', 'https', 'wss'].includes(protocol) && !sourceHasWeb) return [protocol, '来源未启用 Web 协议'];
    const candidateFamily = tcpFamilyFor(protocol);
    const reason = activeFamily && candidateFamily && candidateFamily !== activeFamily
      ? `与当前 ${tcpFamilyLabels[activeFamily]} 目标互斥；请先取消已选项`
      : '';
    return [protocol, reason];
  }));
};
const stateLabels = { healthy: '正常', warning: '目标异常', error: '启动失败', disabled: '已停用', starting: '加载中' };
const lines = (value) => Array.isArray(value) ? value.join('\n') : String(value || '');
const parseLines = (value) => [...new Set(String(value || '').split(/[\n,]/).map((item) => item.trim()).filter(Boolean))];
const headersToText = (value = {}) => Object.entries(value).map(([key, item]) => `${key}: ${item}`).join('\n');
const parseHeadersText = (value) => {
  const headers = {};
  const names = new Set();
  const rows = String(value || '').split('\n');
  for (let index = 0; index < rows.length; index += 1) {
    const row = rows[index].trim();
    if (!row) continue;
    const separator = row.indexOf(':');
    if (separator <= 0) return { headers, error: `第 ${index + 1} 行缺少“名称: 值”中的冒号` };
    const name = row.slice(0, separator).trim();
    const headerValue = row.slice(separator + 1).trim();
    if (!/^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/.test(name)) return { headers, error: `第 ${index + 1} 行的请求头名称无效` };
    const normalizedName = name.toLowerCase();
    if (names.has(normalizedName)) return { headers, error: `第 ${index + 1} 行与前面的“${name}”重复` };
    names.add(normalizedName);
    headers[name] = headerValue;
  }
  return { headers, error: '' };
};
const textToHeaders = (value) => parseHeadersText(value).headers;
const number = (value, fallback) => String(value ?? '').trim() !== '' && Number.isFinite(Number(value)) ? Number(value) : fallback;
const errorText = (error, fallback = '操作未完成，请检查后重试') => {
  const details = Array.isArray(error?.details)
    ? error.details
    : error?.details && typeof error.details === 'object'
      ? Object.values(error.details)
      : error?.details ? [error.details] : [];
  return [...new Set([error?.message, ...details].filter(Boolean).map(String))].join('；') || fallback;
};
const ruleProtocols = (rule) => rule.protocols?.length ? rule.protocols : rule.protocol === 'tcp+udp' ? ['tcp', 'udp'] : [rule.protocol || 'http'];
const ruleTargetProtocols = (rule) => rule.targetProtocols?.length ? rule.targetProtocols : [rule.targetProtocol || 'http'];
const expandLocalRange = (start, end = start) => {
  const first = Number(start); const last = Number(end ?? start);
  if (!Number.isInteger(first) || !Number.isInteger(last) || first < 1 || last < first || last > 65535) return [];
  return Array.from({ length: last - first + 1 }, (_, index) => first + index);
};
const portsForRule = (rule, kind) => {
  const ports = rule?.[`${kind}Ports`];
  if (Array.isArray(ports) && ports.length) return ports.map(Number);
  return expandLocalRange(rule?.[`${kind}PortStart`] ?? rule?.[`${kind}Port`], rule?.[`${kind}PortEnd`] ?? rule?.[`${kind}Port`]);
};
const formatPortSpec = (ports = []) => {
  const values = [...new Set(ports.map(Number).filter((port) => Number.isInteger(port)))];
  const parts = [];
  for (let index = 0; index < values.length; index += 1) {
    const start = values[index]; let end = start;
    while (index + 1 < values.length && values[index + 1] === end + 1) { index += 1; end = values[index]; }
    parts.push(end === start ? String(start) : `${start}-${end}`);
  }
  return parts.join(', ');
};
const parsePortInput = (value) => {
  const normalized = String(value ?? '').trim().replace(/\s*[-–—~～]\s*/g, '-');
  const tokens = normalized.split(/[,，;；\s]+/).map((item) => item.trim()).filter(Boolean);
  if (!tokens.length) return { ports: [], error: '请输入至少一个端口' };
  const ports = []; const seen = new Set();
  const add = (port) => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) return `端口 ${port} 超出 1–65535`;
    if (!seen.has(port)) { seen.add(port); ports.push(port); }
    return ports.length > 256 ? '单条规则最多设置 256 个端口' : '';
  };
  for (const token of tokens) {
    if (/^\d+$/.test(token)) { const error = add(Number(token)); if (error) return { ports, error }; continue; }
    const range = token.match(/^(\d+)-(\d+)$/);
    if (!range) return { ports, error: `“${token}”格式无效` };
    const start = Number(range[1]); const end = Number(range[2]);
    if (start > end) return { ports, error: `“${token}”的结束端口不能小于起始端口` };
    if (start < 1 || end > 65535) return { ports, error: `“${token}”超出 1–65535` };
    for (let port = start; port <= end; port += 1) { const error = add(port); if (error) return { ports, error }; }
  }
  return { ports, error: '' };
};
const portListLabel = (rule, kind) => formatPortSpec(portsForRule(rule, kind)) || '—';
const legacyPortRangeEnd = (ports) => ports.every((port, index) => index === 0 || port === ports[index - 1] + 1) ? ports.at(-1) : ports[0];
const hasWebProtocol = (protocols) => protocols.some((protocol) => ['http', 'ws', 'https', 'wss'].includes(protocol));
const hasTlsProtocol = (protocols) => protocols.some((protocol) => ['https', 'wss'].includes(protocol));
const isUniversalPair = (protocols = [], targets = []) => protocols.length === 2 && targets.length === 2 && ['tcp', 'udp'].every((protocol) => protocols.includes(protocol) && targets.includes(protocol));
const fileUpload = async (file) => {
  const dataUrl = await new Promise((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = () => reject(reader.error); reader.readAsDataURL(file); });
  return { name: file.name, type: file.type, data: dataUrl.slice(dataUrl.indexOf(',') + 1), size: file.size };
};

const isSystemCertificate = (certificate = {}) => certificate.source === 'system' || certificate.managed === true;
const certificateTimestamp = (value) => value === null || value === undefined || String(value).trim() === '' ? Number.NaN : new Date(value).getTime();

function certificateState(certificate = {}) {
  const now = Date.now();
  const declaredStatus = String(certificate.status || '').toLowerCase();
  const startsAt = certificateTimestamp(certificate.validFrom);
  const expiresAt = certificateTimestamp(certificate.validTo);
  if (declaredStatus === 'not-yet-valid' || Number.isFinite(startsAt) && startsAt > now) {
    return { state: 'warning', label: '尚未生效', message: Number.isFinite(startsAt) ? `${new Date(startsAt).toLocaleDateString()} 开始生效` : '证书尚未进入有效期', days: null, usable: false };
  }
  const days = Number.isFinite(expiresAt) ? Math.ceil((expiresAt - now) / 86400000) : null;
  if (declaredStatus === 'expired' || days !== null && days <= 0) return { state: 'error', label: '已过期', message: '证书已经过期', days, usable: false };
  if (certificate.available === false) return { state: 'error', label: '不可用', message: certificate.lastError || '服务端未能校验证书或私钥', days, usable: false };
  if (days === null) {
    if (declaredStatus === 'valid') return { state: 'healthy', label: '有效', message: '已由服务端校验', days, usable: true };
    return { state: 'warning', label: '日期未知', message: '未读取到有效期', days, usable: false };
  }
  if (days <= 30) return { state: 'warning', label: `${days} 天后到期`, message: `剩余 ${days} 天`, days, usable: true };
  return { state: 'healthy', label: '有效', message: `剩余 ${days} 天`, days, usable: true };
}

const isCertificateUsable = (certificate) => certificateState(certificate).usable;

function certificateOptionLabel(certificate) {
  const validity = certificateState(certificate);
  const suffix = !validity.usable
    ? `${validity.label}（不可用）`
    : certificate.stale
      ? '上次可用副本'
      : validity.state === 'warning'
        ? validity.label
        : isSystemCertificate(certificate) ? '系统托管' : '';
  return `${certificate.name}${suffix ? ` · ${suffix}` : ''}`;
}

function formatCertificateDate(value) {
  const timestamp = certificateTimestamp(value);
  return Number.isFinite(timestamp) ? new Date(timestamp).toLocaleDateString() : '未知';
}

function downloadJson(data, filename) {
  const blob = new Blob([`${JSON.stringify(data, null, 2)}\n`], { type: 'application/json;charset=utf-8' });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url; anchor.download = filename; anchor.click(); URL.revokeObjectURL(url);
}

function StatusChip({ state = 'starting', message, label }) {
  const text = label || stateLabels[state] || state;
  return <span className={`state-chip ${state}`} title={message || text} aria-label={message ? `${text}：${message}` : text}><i className={`bi ${state === 'healthy' ? 'bi-check-circle-fill' : state === 'disabled' ? 'bi-pause-circle-fill' : state === 'starting' ? 'bi-arrow-repeat' : 'bi-exclamation-triangle-fill'}`} aria-hidden="true" />{text}</span>;
}

function Toggle({ checked, onChange, label, disabled = false }) {
  return <button type="button" className={`toggle${checked ? ' checked' : ''}`} role="switch" aria-checked={checked} aria-label={label} title={label} disabled={disabled} onClick={() => onChange(!checked)}><span className="toggle-track"><span /></span></button>;
}

function Toast({ toast }) {
  if (!toast) return null;
  return <div className={`toast ${toast.type}`} role={toast.type === 'error' ? 'alert' : 'status'} aria-live={toast.type === 'error' ? 'assertive' : 'polite'}><i className={`bi ${toast.type === 'error' ? 'bi-exclamation-octagon' : 'bi-check-circle'}`} aria-hidden="true" /><span>{toast.message}</span></div>;
}

function Sidebar({ route, onNavigate, serviceState, version }) {
  const serviceLabel = serviceState === 'loading' ? '检测中' : serviceState === 'healthy' ? '运行中' : '服务不可用';
  const serviceDetail = serviceState === 'loading' ? '正在连接管理服务' : serviceState === 'healthy' ? '系统运行正常' : '请检查管理服务';
  return <aside className="sidebar">
    <div className="brand"><span className="brand-mark"><i className="bi bi-signpost-split-fill" aria-hidden="true" /></span><div><strong>反向代理管理器</strong><small>Reverse Proxy</small></div></div>
    <nav className="nav-list" aria-label="主导航">{Object.entries(ROUTES).map(([key, item]) => <button key={key} type="button" className={`nav-item${route === key ? ' active' : ''}`} aria-current={route === key ? 'page' : undefined} onClick={() => onNavigate(key)}><i className={`bi ${item.icon}`} aria-hidden="true" /><span>{item.label}</span></button>)}</nav>
    <footer className="sidebar-footer"><div className={`sidebar-health ${serviceState}`}><span><i className={`status-dot ${serviceState === 'healthy' ? 'online' : serviceState === 'loading' ? 'warning' : 'offline'}`} aria-hidden="true" />{serviceLabel}</span><small>{serviceDetail} · v{version || '1.0.3'}</small></div></footer>
  </aside>;
}

function PageHeader({ route, serviceState, loading, onRefresh }) {
  const info = ROUTES[route];
  const serviceLabel = serviceState === 'loading' ? '正在检测' : serviceState === 'healthy' ? '服务运行中' : '连接失败';
  return <header className="page-header"><div><span className="page-icon"><i className={`bi ${info.icon}`} aria-hidden="true" /></span><div><h1>{info.title}</h1><p>{info.description}</p></div></div><div className="header-actions">
    <Dialog.Root><Dialog.Trigger className="icon-button" aria-label="查看使用说明" title="使用说明"><i className="bi bi-question-circle" aria-hidden="true" /></Dialog.Trigger><Dialog.Portal><Dialog.Backdrop className="dialog-backdrop" /><Dialog.Popup className="dialog-popup compact"><Dialog.Title>反向代理</Dialog.Title><Dialog.Description>选择入口与目标协议，再填写地址和端口。端口支持 80,22,445、逐行填写或 8000-8010 连续范围。只有 HTTPS / WSS 由本应用解密时才需要证书；TCP / UDP 原样转发不需要。</Dialog.Description><div className="dialog-actions"><Dialog.Close className="secondary-button">知道了</Dialog.Close></div></Dialog.Popup></Dialog.Portal></Dialog.Root>
    <button type="button" className={`icon-button${loading ? ' busy' : ''}`} aria-label="刷新数据" title="刷新数据" disabled={loading} onClick={onRefresh}><i className="bi bi-arrow-clockwise" aria-hidden="true" /></button>
    <span className="service-pill"><i className={`status-dot ${serviceState === 'healthy' ? 'online' : serviceState === 'loading' ? 'warning' : 'offline'}`} aria-hidden="true" /><span>{serviceLabel}</span></span>
  </div></header>;
}

function EmptyState({ icon, title, description, action, onAction }) {
  return <div className="empty-state"><span><i className={`bi ${icon}`} aria-hidden="true" /></span><strong>{title}</strong><p>{description}</p>{action ? <button type="button" className="secondary-button" onClick={onAction}>{action}</button> : null}</div>;
}

function ProtocolBadges({ protocols }) {
  return <span className="protocol-stack">{protocols.map((protocol) => <span className={`protocol-badge ${protocol}`} key={protocol}>{protocol.toUpperCase()}</span>)}</span>;
}

function RuleActionMenu({ rule, pending, testUnavailable, onToggle: onRuleToggle, onTest, onEdit, onDuplicate, onDelete }) {
  const [open, setOpen] = useState(false);
  const detailsRef = useRef(null);
  useEffect(() => {
    if (!open) return undefined;
    const closeOutside = (event) => {
      if (!detailsRef.current?.contains(event.target)) setOpen(false);
    };
    const closeWithEscape = (event) => {
      if (event.key !== 'Escape') return;
      event.preventDefault();
      setOpen(false);
      window.requestAnimationFrame(() => detailsRef.current?.querySelector('summary')?.focus());
    };
    document.addEventListener('pointerdown', closeOutside, true);
    document.addEventListener('keydown', closeWithEscape);
    return () => {
      document.removeEventListener('pointerdown', closeOutside, true);
      document.removeEventListener('keydown', closeWithEscape);
    };
  }, [open]);
  const run = (action) => {
    setOpen(false);
    action();
  };
  return <details ref={detailsRef} className="action-menu" open={open} onToggle={(event) => setOpen(event.currentTarget.open)}>
    <summary aria-label={`打开 ${rule.name} 的操作菜单`} aria-expanded={open}><i className="bi bi-three-dots-vertical" aria-hidden="true" /></summary>
    <div><span className="menu-toggle"><span>{rule.enabled ? '规则已启用' : '规则已停用'}</span><Toggle checked={rule.enabled} label={`${rule.enabled ? '停用' : '启用'} ${rule.name}`} disabled={pending} onChange={(enabled) => run(() => onRuleToggle(rule, enabled))} /></span><button type="button" disabled={pending || testUnavailable} aria-describedby={testUnavailable ? `test-help-${rule.id}` : undefined} onClick={() => run(() => onTest(rule))}><i className="bi bi-activity" aria-hidden="true" />测试目标</button>{testUnavailable ? <p className="menu-help" id={`test-help-${rule.id}`}>规则正常运行后才能测试目标。</p> : null}<button type="button" onClick={() => run(() => onEdit(rule))}><i className="bi bi-pencil" aria-hidden="true" />编辑规则</button><button type="button" disabled={pending} onClick={() => run(() => onDuplicate(rule))}><i className="bi bi-copy" aria-hidden="true" />创建副本</button><button type="button" className="danger" disabled={pending} onClick={() => run(() => onDelete(rule))}><i className="bi bi-trash3" aria-hidden="true" />删除规则</button></div>
  </details>;
}

function RulesPage({ status, rules, runtime, onCreate, onEdit, onToggle, onDuplicate, onDelete, onTest, busy }) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('all');
  const deferredQuery = useDeferredValue(query.toLowerCase());
  const visible = useMemo(() => rules.filter((rule) => {
    const protocols = ruleProtocols(rule);
    const matchesFilter = filter === 'all' || filter === 'enabled' && rule.enabled || filter === 'disabled' && !rule.enabled || protocols.includes(filter);
    const searchable = `${rule.name} ${protocols.join(' ')} ${rule.listenHost} ${portsForRule(rule, 'listen').join(' ')} ${rule.targetHost} ${portsForRule(rule, 'target').join(' ')} ${(rule.domains || []).join(' ')}`.toLowerCase();
    return matchesFilter && (!deferredQuery || searchable.includes(deferredQuery));
  }), [rules, filter, deferredQuery]);
  return <section className="view rules-view" aria-label="代理规则">
    <article className="matte-surface rules-surface">
      <header className="rules-heading"><div><span>代理规则</span><StatusChip state={!status?.ok ? 'error' : status?.rules?.warning ? 'warning' : 'healthy'} label={!status?.ok ? '服务不可用' : status?.rules?.warning ? `${status.rules.warning} 个异常` : `${status?.rules?.healthy || 0} 个运行中`} /></div><button type="button" className="primary-button" onClick={onCreate}><i className="bi bi-plus-lg" aria-hidden="true" />新建规则</button></header>
      <div className="rules-toolbar"><div className="search-box"><i className="bi bi-search" aria-hidden="true" /><input value={query} onChange={(event) => setQuery(event.target.value)} aria-label="搜索规则" placeholder="搜索名称、域名、IP 或端口" /></div><div className="filter-tabs" aria-label="规则筛选">{[['all', '全部'], ['enabled', '已启用'], ['http', 'HTTP'], ['tcp', 'TCP'], ['udp', 'UDP'], ['disabled', '已停用']].map(([value, label]) => <button type="button" key={value} className={filter === value ? 'active' : ''} aria-pressed={filter === value} onClick={() => setFilter(value)}>{label}</button>)}</div></div>
      <div className="rule-list" role="list">{visible.map((rule) => {
        const item = runtime?.[rule.id] || { state: rule.enabled ? 'starting' : 'disabled' };
        const protocols = ruleProtocols(rule);
        const targetProtocols = ruleTargetProtocols(rule);
        const universal = isUniversalPair(protocols, targetProtocols);
        const pending = busy.has(rule.id);
        const visibleState = pending ? 'starting' : item.state;
        const testUnavailable = !rule.enabled || ['disabled', 'error', 'starting'].includes(item.state);
        return <article className="rule-item" role="listitem" key={rule.id}>
          <button type="button" className="rule-flow" onClick={() => onEdit(rule)} aria-label={`编辑规则 ${rule.name}；${universal ? 'TCP、UDP 原样转发' : `协议 ${protocols.map((protocol) => protocolLabels[protocol]).join('、')}`}；来源 ${rule.listenHost}:${portListLabel(rule, 'listen')}；目标 ${rule.targetHost}:${portListLabel(rule, 'target')}；状态 ${stateLabels[visibleState] || visibleState}`}>
            <span className="rule-identity"><ProtocolBadges protocols={protocols} /><span><strong>{rule.name}</strong><small>{universal ? 'TCP + UDP 原样转发' : (rule.domains || []).length ? rule.domains.join('、') : protocols.map((protocol) => protocolLabels[protocol]).join(' · ')}</small></span></span>
            <span className="flow-endpoint source"><small>来源</small><code>{rule.listenHost === '0.0.0.0' ? '所有地址' : rule.listenHost}<b>:{portListLabel(rule, 'listen')}</b></code></span>
            <span className="flow-arrow"><i className="bi bi-arrow-right" aria-hidden="true" /></span>
            <span className="flow-endpoint target"><small>{universal ? '原样转发' : targetProtocols.map((protocol) => protocol.toUpperCase()).join(' · ')}</small><code>{rule.targetHost}<b>:{portListLabel(rule, 'target')}</b></code></span>
            <span className="rule-state"><StatusChip state={visibleState} message={pending ? '正在等待服务器确认' : item.message} />{pending ? <small>正在等待服务器确认</small> : item.message && !['healthy', 'disabled'].includes(item.state) ? <small>{item.message}</small> : <small>{item.activeConnections || 0} 当前 · {item.connections || 0} 累计</small>}</span>
          </button>
          <RuleActionMenu rule={rule} pending={pending} testUnavailable={testUnavailable} onToggle={onToggle} onTest={onTest} onEdit={onEdit} onDuplicate={onDuplicate} onDelete={onDelete} />
        </article>;
      })}{!visible.length ? <EmptyState icon="bi-inboxes" title="没有符合条件的规则" description="调整搜索或筛选条件，或者新建一条规则。" action="新建规则" onAction={onCreate} /> : null}</div>
    </article>
  </section>;
}

function Field({ label, hint, required, children, error }) {
  const generatedId = `field-${useId().replaceAll(':', '')}`;
  const inputId = isValidElement(children) && children.props.id ? children.props.id : generatedId;
  const hintId = hint ? `${inputId}-hint` : null;
  const errorId = error ? `${inputId}-error` : null;
  const describedBy = isValidElement(children) ? [children.props['aria-describedby'], hintId, errorId].filter(Boolean).join(' ') || undefined : undefined;
  const control = isValidElement(children) ? cloneElement(children, { id: inputId, 'aria-required': required || undefined, 'aria-invalid': error ? true : undefined, 'aria-describedby': describedBy }) : children;
  return <div className={`form-field${error ? ' invalid' : ''}`}><label className="field-label" htmlFor={inputId}>{label}{required ? <b aria-hidden="true">*</b> : null}</label>{control}{hint ? <small id={hintId}>{hint}</small> : null}{error ? <em id={errorId} role="alert">{error}</em> : null}</div>;
}

function CheckRow({ checked, onChange, title, description, disabled = false }) {
  return <label className={`check-row${disabled ? ' disabled' : ''}`}><input type="checkbox" checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} /><span><strong>{title}</strong><small>{description}</small></span></label>;
}

function ProtocolPicker({ id, label, options, value, onChange, error, disabledReasons = {}, helper }) {
  const selected = new Set(value);
  const optionMap = new Map(options.map((option) => [option[0], option]));
  const generatedGroupId = `protocol-${useId().replaceAll(':', '')}`;
  const groupId = id || generatedGroupId;
  const helperId = helper ? `${groupId}-help` : undefined;
  const errorId = error ? `${groupId}-error` : undefined;
  const describedBy = [helperId, errorId].filter(Boolean).join(' ') || undefined;
  return <fieldset id={groupId} className={`protocol-picker${error ? ' invalid' : ''}`} aria-required="true" aria-invalid={Boolean(error)} aria-describedby={describedBy}>
    <legend><span>{label}<b>*</b></span><small><i className="bi bi-check2-circle" aria-hidden="true" />已选 {value.length} 项</small></legend>
    <div className="protocol-choice-grid">{protocolFamilyGroups.map((group) => <section className="protocol-family-group" key={group.key} aria-label={group.label}><span className="protocol-family-label">{group.label}</span><div className="protocol-family-options">{group.protocols.map((protocol) => optionMap.get(protocol)).filter(Boolean).map(([protocol, name, description]) => { const active = selected.has(protocol); const reason = active ? '' : disabledReasons[protocol]; const unavailable = Boolean(reason); return <button key={protocol} type="button" className={`${active ? 'selected' : ''}${unavailable ? ' unavailable' : ''}`} aria-pressed={active} aria-disabled={unavailable} title={reason || `${active ? '取消' : '选择'} ${name}`} onClick={() => { if (!unavailable) onChange(active ? value.filter((item) => item !== protocol) : [...value, protocol]); }}><span className={`protocol-choice-icon ${protocol}`}><i className={`bi ${['http', 'https'].includes(protocol) ? 'bi-globe2' : ['ws', 'wss'].includes(protocol) ? 'bi-arrow-left-right' : protocol === 'udp' ? 'bi-broadcast' : 'bi-ethernet'}`} aria-hidden="true" /></span><span><strong>{name}</strong><small>{reason || description}</small></span><i className={`bi ${active ? 'bi-check-circle-fill' : unavailable ? 'bi-lock-fill' : 'bi-circle'}`} aria-hidden="true" /></button>; })}</div></section>)}</div>
    {helper ? <p className="protocol-picker-help" id={helperId}><i className="bi bi-info-circle" aria-hidden="true" />{helper}</p> : null}
    {error ? <em id={errorId} role="alert">{error}</em> : null}
  </fieldset>;
}

function UniversalForwardingNote({ compact = false }) {
  return <div className={`universal-forwarding-note${compact ? ' compact' : ''}`}><i className="bi bi-arrow-left-right" aria-hidden="true" /><span><strong>TCP + UDP 原样转发</strong><small>这是已有规则的传输方式；应用不解析内容，也不使用证书。</small></span></div>;
}

function ProtocolFlow({ source, targets, universal = false }) {
  const labels = (items) => items.length ? items.map((protocol) => protocolLabels[protocol]).join(' + ') : '未选择';
  return <div className={`protocol-flow${universal ? ' universal' : ''}`} aria-live="polite"><span><small>来源</small><strong>{universal ? 'TCP + UDP 端口' : labels(source)}</strong></span><i className="bi bi-arrow-right" aria-hidden="true" /><span><small>转发到</small><strong>{universal ? 'TCP + UDP 原样转发' : labels(targets)}</strong></span></div>;
}

function PortListField({ label, value, onChange, error, hint }) {
  const parsed = parsePortInput(value);
  const preview = parsed.error ? '' : formatPortSpec(parsed.ports);
  const inputId = label.includes('监听') ? 'rule-listen-ports' : 'rule-target-ports';
  const errorId = `${inputId}-error`;
  const statusId = `${inputId}-status`;
  const hintId = hint ? `${inputId}-hint` : undefined;
  const describedBy = [statusId, hintId, error ? errorId : null].filter(Boolean).join(' ');
  return <div className={`form-field port-list-field${error || parsed.error ? ' invalid' : ''}`}><span className="range-field-heading"><label className="field-label" htmlFor={inputId}>{label}<b aria-hidden="true">*</b></label><small className={parsed.error ? 'warning' : ''}>{parsed.error ? '格式待检查' : `${parsed.ports.length} 个端口`}</small></span><textarea id={inputId} rows="2" inputMode="text" spellCheck="false" value={value} aria-required="true" aria-invalid={Boolean(error || parsed.error)} aria-describedby={describedBy} onChange={(event) => onChange(event.target.value)} placeholder={'80, 22, 445\n或 8000-8010'} /><div id={statusId} className={`port-input-status${parsed.error ? ' invalid' : ''}`} aria-live="polite"><i className={`bi ${parsed.error ? 'bi-exclamation-circle' : 'bi-check2-circle'}`} aria-hidden="true" /><span>{parsed.error || `识别为：${preview}`}</span></div>{hint ? <small id={hintId}>{hint}</small> : null}{error ? <em id={errorId} role="alert">{error}</em> : null}</div>;
}

function PortMappingPreview({ sourceText, targetText, targetHost, universal = false }) {
  const source = parsePortInput(sourceText); const target = parsePortInput(targetText);
  const invalid = source.error || target.error || target.ports.length !== 1 && target.ports.length !== source.ports.length;
  if (invalid) return <div className="port-mapping-preview pending"><i className="bi bi-diagram-3" aria-hidden="true" /><span>端口填写完成后，这里会显示实际映射关系。</span></div>;
  const rows = source.ports.slice(0, 6).map((port, index) => [port, target.ports.length === 1 ? target.ports[0] : target.ports[index]]);
  return <div className="port-mapping-preview"><div className="port-mapping-head"><span><i className="bi bi-diagram-3" aria-hidden="true" />{universal ? 'TCP + UDP 端口映射' : '实时端口映射'}</span><small>{target.ports.length === 1 && source.ports.length > 1 ? `${source.ports.length} 个入口共用 1 个目标` : `${source.ports.length} 组一一映射`}</small></div><div className="port-mapping-list">{rows.map(([listen, targetPort]) => <span key={`${listen}-${targetPort}`}>{universal ? <b className="mapping-transport">TCP+UDP</b> : null}<code>{listen}</code><i className="bi bi-arrow-right" aria-hidden="true" /><code>{targetHost || '目标'}:{targetPort}</code></span>)}{source.ports.length > rows.length ? <span className="more">另有 {source.ports.length - rows.length} 组</span> : null}</div></div>;
}

function RuleDialog({ open, rule, certificates, certificatesAvailable, onClose, onSave, saving }) {
  const [tab, setTab] = useState('basic');
  const [draft, setDraft] = useState(blankRule);
  const [mode, setMode] = useState('precise');
  const [errors, setErrors] = useState({});
  const [compatibilityNotice, setCompatibilityNotice] = useState('');
  const [submitError, setSubmitError] = useState('');
  useEffect(() => {
    if (!open) return;
    const value = rule || {};
    const protocols = rule ? ruleProtocols(value) : blankRule.protocols;
    const targetProtocols = rule ? ruleTargetProtocols(value) : blankRule.targetProtocols;
    const nextMode = isUniversalPair(protocols, targetProtocols) ? 'universal' : 'precise';
    setMode(nextMode);
    setDraft({ ...blankRule, ...value, protocols, targetProtocols, listenPortsText: rule ? formatPortSpec(portsForRule(value, 'listen')) : blankRule.listenPortsText, targetPortsText: rule ? formatPortSpec(portsForRule(value, 'target')) : blankRule.targetPortsText, realIp: { ...blankRule.realIp, ...(rule?.realIp || {}) }, tls: { ...blankRule.tls, ...(rule?.tls || {}) }, domainsText: lines(rule?.domains), allowText: lines(rule?.allowIps), blockText: lines(rule?.blockIps), headersText: headersToText(rule?.customHeaders) });
    setTab('basic'); setErrors({}); setCompatibilityNotice(''); setSubmitError('');
  }, [open, rule]);
  const clearValidationErrors = (...keys) => setErrors((current) => {
    if (!keys.some((key) => current[key])) return current;
    const next = { ...current };
    keys.forEach((key) => delete next[key]);
    return next;
  });
  const set = (key, value, errorKey = key) => {
    setSubmitError('');
    clearValidationErrors(errorKey);
    setDraft((current) => ({ ...current, [key]: value }));
  };
  const validate = () => {
    const next = {};
    const source = draft.protocols || [];
    const targets = draft.targetProtocols || [];
    const tcpModes = [source.some((item) => ['http', 'ws'].includes(item)), source.some((item) => ['https', 'wss'].includes(item)), source.includes('tcp')].filter(Boolean).length;
    if (!draft.name.trim()) next.name = '请输入规则名称';
    if (!source.length) next.protocols = '至少选择一种来源协议';
    else if (tcpModes > 1) next.protocols = '同一组监听端口只能选择 HTTP/WS、HTTPS/WSS 或 TCP 中的一组';
    if (!targets.length) next.targetProtocols = '至少选择一种目标协议';
    const targetTcpModes = [targets.some((item) => ['http', 'ws'].includes(item)), targets.some((item) => ['https', 'wss'].includes(item)), targets.includes('tcp')].filter(Boolean).length;
    if (targetTcpModes > 1) next.targetProtocols = '同一入口只能选择一组 Web 或 TCP 目标协议';
    if (source.some((item) => ['http', 'ws', 'https', 'wss'].includes(item)) && !targets.some((item) => ['http', 'ws', 'https', 'wss'].includes(item))) next.targetProtocols = 'Web 入口需要 HTTP、HTTPS、WebSocket 或 WSS 目标';
    if (source.includes('tcp') && !targets.includes('tcp')) next.targetProtocols = 'TCP 入口需要 TCP 目标';
    if (source.includes('udp') && !targets.includes('udp')) next.targetProtocols = 'UDP 入口需要 UDP 目标';
    if (!source.includes('tcp') && targets.includes('tcp') || !source.includes('udp') && targets.includes('udp') || !hasWebProtocol(source) && hasWebProtocol(targets)) next.targetProtocols = '目标协议需要与来源协议类型对应';
    if (!draft.targetHost.trim()) next.targetHost = '请输入目标主机';
    if (hasTlsProtocol(source) && draft.enabled && !certificatesAvailable) next.certId = '证书数据暂不可用，请先返回页面重试同步';
    else if (hasTlsProtocol(source) && draft.enabled && !draft.tls.certId) next.certId = '启用 HTTPS / WSS 规则前请选择证书';
    else if (hasTlsProtocol(source) && draft.enabled) {
      const selectedCertificate = certificates.find((certificate) => certificate.id === draft.tls.certId);
      if (!selectedCertificate) next.certId = '原证书已不存在，请选择可用证书后再启用';
      else if (!isCertificateUsable(selectedCertificate)) next.certId = `“${selectedCertificate.name}”${certificateState(selectedCertificate).label}，不能用于启用规则`;
    }
    const headersResult = parseHeadersText(draft.headersText);
    if (mode === 'precise' && headersResult.error) next.headers = headersResult.error;
    const listenResult = parsePortInput(draft.listenPortsText); const targetResult = parsePortInput(draft.targetPortsText);
    if (listenResult.error) next.listenPort = listenResult.error;
    if (targetResult.error) next.targetPort = targetResult.error;
    else if (!listenResult.error && targetResult.ports.length !== 1 && targetResult.ports.length !== listenResult.ports.length) next.targetPort = `目标需填写 1 个端口，或填写 ${listenResult.ports.length} 个端口进行一一映射`;
    setErrors(next);
    if (Object.keys(next).length) {
      const basicError = ['name', 'protocols', 'targetProtocols', 'targetHost', 'listenPort', 'targetPort'].some((key) => next[key]);
      const targetTab = basicError ? 'basic' : next.certId || next.headers ? 'advanced' : 'security';
      setTab(targetTab);
      const order = targetTab === 'basic'
        ? [['name', 'rule-name'], ['protocols', 'source-protocols'], ['listenPort', 'rule-listen-ports'], ['targetProtocols', 'target-protocols'], ['targetHost', 'rule-target-host'], ['targetPort', 'rule-target-ports']]
        : [['certId', 'rule-certificate'], ['headers', 'rule-custom-headers']];
      const first = order.find(([key]) => next[key]);
      window.requestAnimationFrame(() => {
        const element = first ? document.getElementById(first[1]) : null;
        (element?.matches('fieldset') ? element.querySelector('button:not([disabled]):not([aria-disabled="true"])') : element)?.focus();
      });
    }
    return !Object.keys(next).length;
  };
  const submit = async (event) => {
    event.preventDefault();
    setSubmitError('');
    if (!validate()) return;
    const listenPorts = parsePortInput(draft.listenPortsText).ports;
    const targetPorts = parsePortInput(draft.targetPortsText).ports;
    const headersResult = parseHeadersText(draft.headersText);
    const { listenPortsText, targetPortsText, ...payload } = draft;
    const saved = await onSave({ ...payload, protocol: draft.protocols[0], protocols: draft.protocols, listenPort: listenPorts[0], listenPortStart: listenPorts[0], listenPortEnd: legacyPortRangeEnd(listenPorts), listenPorts, targetProtocol: draft.targetProtocols[0], targetProtocols: draft.targetProtocols, targetPort: targetPorts[0], targetPortStart: targetPorts[0], targetPortEnd: legacyPortRangeEnd(targetPorts), targetPorts, timeoutMs: number(draft.timeoutMs, 30000), uploadLimitMb: number(draft.uploadLimitMb, 50), domains: parseLines(draft.domainsText), allowIps: parseLines(draft.allowText), blockIps: parseLines(draft.blockText), customHeaders: mode === 'universal' && headersResult.error ? draft.customHeaders || {} : headersResult.headers });
    if (saved !== true) setSubmitError(`${errorText(saved?.error, '保存未完成，请根据提示修正后重试')}。当前表单内容已保留。`);
  };
  const sourceProtocolsChanged = (next) => {
    const current = draft;
    const added = next.find((protocol) => !current.protocols.includes(protocol));
    const targetProtocols = current.targetProtocols.filter((protocol) => protocol === 'udp' ? next.includes('udp') : protocol === 'tcp' ? next.includes('tcp') : hasWebProtocol(next));
    const removed = current.targetProtocols.filter((protocol) => !targetProtocols.includes(protocol));
    const ensure = (protocol) => { if (!targetProtocols.includes(protocol)) targetProtocols.push(protocol); };
    if (added === 'tcp' || added === 'udp') ensure(added);
    if (added && ['http', 'ws', 'https', 'wss'].includes(added) && !targetProtocols.some((protocol) => ['http', 'ws', 'https', 'wss'].includes(protocol))) ensure(added === 'https' || added === 'wss' ? 'https' : added);
    setSubmitError('');
    clearValidationErrors('protocols', 'targetProtocols', 'certId');
    setCompatibilityNotice(removed.length ? `来源类型已变化，已移除不兼容的目标协议：${removed.map((protocol) => protocolLabels[protocol]).join('、')}。请确认新的目标协议。` : '');
    setDraft({ ...current, protocols: next, targetProtocols });
  };
  const targetProtocolsChanged = (next) => {
    setSubmitError('');
    clearValidationErrors('targetProtocols');
    setDraft((current) => ({ ...current, targetProtocols: next }));
  };
  const selectedCertificate = certificates.find((certificate) => certificate.id === draft.tls.certId);
  const selectedCertificateValidity = selectedCertificate ? certificateState(selectedCertificate) : null;
  const certificateHint = !certificatesAvailable
    ? '证书数据暂不可用；停用规则仍可保留原证书引用'
    : draft.tls.certId && !selectedCertificate
      ? '原证书已不存在；可先停用保存，重新启用前需选择可用证书'
      : selectedCertificateValidity && !selectedCertificateValidity.usable
        ? `${selectedCertificateValidity.label}：${selectedCertificateValidity.message}`
        : certificates.length ? '应用证书优先；fnOS 系统证书为实验性只读来源' : '请先到证书页面导入应用证书';
  return <Dialog.Root open={open} onOpenChange={(value) => { if (!value && !saving) onClose(); }}><Dialog.Portal><Dialog.Backdrop className="dialog-backdrop" /><Dialog.Popup className="dialog-popup rule-dialog"><form onSubmit={submit}><header className="dialog-header"><div><span className="section-kicker">{rule ? 'EDIT ROUTE' : 'NEW ROUTE'}</span><Dialog.Title>{rule ? '编辑代理规则' : '添加代理规则'}</Dialog.Title><Dialog.Description>{mode === 'universal' ? '此已有规则同时监听 TCP 与 UDP，并将内容原样转发。' : '选择入口和目标协议，再填写对应地址与端口。'}</Dialog.Description></div><Dialog.Close className="dialog-close" aria-label="关闭" disabled={saving}><i className="bi bi-x-lg" aria-hidden="true" /></Dialog.Close></header><div className="dialog-tabs">{[['basic', '常规'], ['advanced', mode === 'universal' ? '转发设置' : '请求与 TLS'], ['security', '访问控制']].map(([value, label]) => <button key={value} type="button" aria-pressed={tab === value} className={tab === value ? 'active' : ''} onClick={() => setTab(value)}>{label}</button>)}</div><div className="dialog-body">
    {submitError ? <div className="form-error-banner persistent" role="alert"><i className="bi bi-exclamation-octagon" aria-hidden="true" />{submitError}</div> : null}
    {tab === 'basic' ? <div className="form-stack">
      <Field label="规则名称" required error={errors.name}><input id="rule-name" value={draft.name} onChange={(event) => set('name', event.target.value)} placeholder="例如：家庭面板" /></Field>
      {mode === 'universal' ? <UniversalForwardingNote /> : null}
      <fieldset className="form-card"><legend>来源设置</legend>
        {mode === 'precise' ? <ProtocolPicker id="source-protocols" label="来源协议（同组可多选）" options={sourceProtocolOptions} value={draft.protocols} onChange={sourceProtocolsChanged} error={errors.protocols} disabledReasons={sourceDisabledReasons(draft.protocols)} helper="同一端口只能使用一组 TCP 类协议：HTTP/WS、HTTPS/WSS 或 TCP；UDP 可以与任一组同时启用。切换组时先取消当前已选项。" /> : null}
        <div className="form-grid two endpoint-grid"><Field label="监听地址" hint="0.0.0.0 表示所有网卡"><input id="rule-listen-host" value={draft.listenHost} onChange={(event) => set('listenHost', event.target.value)} /></Field><PortListField label="监听端口" value={draft.listenPortsText} onChange={(value) => set('listenPortsText', value, 'listenPort')} error={errors.listenPort} hint="支持逗号、空格或换行；连续范围用短横线，最多 256 个" /></div>
        {mode === 'precise' && hasWebProtocol(draft.protocols) ? <Field label="域名" hint="每行一个；支持 *.example.com。留空允许所有域名"><textarea rows="2" value={draft.domainsText} onChange={(event) => set('domainsText', event.target.value)} placeholder="home.example.com" /></Field> : null}
      </fieldset>
      <ProtocolFlow source={draft.protocols} targets={draft.targetProtocols} universal={mode === 'universal'} />
      {compatibilityNotice ? <div className="compatibility-notice" role="status"><i className="bi bi-info-circle" aria-hidden="true" />{compatibilityNotice}</div> : null}
      <fieldset className="form-card"><legend>目标设置</legend>
        {mode === 'precise' ? <ProtocolPicker id="target-protocols" label="目标协议（同组可多选）" options={targetProtocolOptions} value={draft.targetProtocols} onChange={targetProtocolsChanged} error={errors.targetProtocols} disabledReasons={targetDisabledReasons(draft.protocols, draft.targetProtocols)} helper="目标必须与来源类型对应；灰色锁定项会直接显示不可选原因。来源变化时，必要的目标协议会自动同步。" /> : null}
        <div className="form-grid two endpoint-grid"><Field label="主机名 / IP" required error={errors.targetHost}><input id="rule-target-host" value={draft.targetHost} onChange={(event) => set('targetHost', event.target.value)} placeholder="192.168.1.10" /></Field><PortListField label="目标端口" value={draft.targetPortsText} onChange={(value) => set('targetPortsText', value, 'targetPort')} error={errors.targetPort} hint="填 1 个端口会被全部入口复用；与来源等量时按顺序映射" /></div>
        <PortMappingPreview sourceText={draft.listenPortsText} targetText={draft.targetPortsText} targetHost={draft.targetHost} universal={mode === 'universal'} />
      </fieldset>
      <CheckRow checked={draft.enabled} onChange={(value) => set('enabled', value, 'certId')} title="保存后立即启用" description="系统会先校验协议组合与全部端口，失败时保留规则并显示原因。" />
    </div> : null}
    {tab === 'advanced' ? mode === 'universal' ? <div className="form-stack"><UniversalForwardingNote compact /><div className="universal-timeout"><Field label="连接超时（毫秒）" hint="推荐 30000；空闲连接超过此时间会关闭"><input type="number" min="1000" max="300000" step="1000" value={draft.timeoutMs} onChange={(event) => set('timeoutMs', event.target.value)} /></Field></div></div> : <div className="form-stack"><div className="form-grid two"><Field label="代理超时（毫秒）" hint="推荐 30000"><input type="number" min="1000" max="300000" step="1000" value={draft.timeoutMs} onChange={(event) => set('timeoutMs', event.target.value)} /></Field><Field label="上传限制（MB）" hint="0 表示不限制"><input type="number" min="0" max="10240" value={draft.uploadLimitMb} onChange={(event) => set('uploadLimitMb', event.target.value)} /></Field></div>{hasTlsProtocol(draft.protocols) ? <Field label="入口证书" required={draft.enabled} error={errors.certId} hint={certificateHint}><select id="rule-certificate" disabled={!certificatesAvailable} value={draft.tls.certId} onChange={(event) => { setSubmitError(''); clearValidationErrors('certId'); setDraft((current) => ({ ...current, tls: { ...current.tls, certId: event.target.value } })); }}><option value="">{certificatesAvailable ? draft.enabled ? '选择证书' : '停用规则可暂不选择' : '证书数据暂不可用'}</option>{draft.tls.certId && !selectedCertificate ? <option value={draft.tls.certId} disabled>原证书已不存在（仅保留引用）</option> : null}{certificates.some((certificate) => !isSystemCertificate(certificate)) ? <optgroup label="应用证书">{certificates.filter((certificate) => !isSystemCertificate(certificate)).map((certificate) => <option key={certificate.id} value={certificate.id} disabled={!isCertificateUsable(certificate)}>{certificateOptionLabel(certificate)}</option>)}</optgroup> : null}{certificates.some(isSystemCertificate) ? <optgroup label="fnOS 系统证书（实验性 · 只读）">{certificates.filter(isSystemCertificate).map((certificate) => <option key={certificate.id} value={certificate.id} disabled={!isCertificateUsable(certificate)}>{certificateOptionLabel(certificate)}</option>)}</optgroup> : null}</select></Field> : null}<Field label="自定义请求头" error={errors.headers} hint="每行一个，格式：名称: 值"><textarea id="rule-custom-headers" rows="5" value={draft.headersText} onChange={(event) => set('headersText', event.target.value, 'headers')} placeholder={'X-Proxy-By: fnOS\nX-Forwarded-Proto: https'} /></Field><div className="check-grid"><CheckRow checked={draft.preserveHost} onChange={(value) => set('preserveHost', value)} title="保留原始 Host" description="目标服务依赖访问域名时启用。" /><CheckRow checked={draft.forceHttps} disabled={!draft.protocols.some((protocol) => ['http', 'ws'].includes(protocol))} onChange={(value) => set('forceHttps', value)} title="强制跳转 HTTPS" description="仅 HTTP / WebSocket 入口可用，返回 308 跳转。" /><CheckRow checked={draft.hsts} disabled={!hasTlsProtocol(draft.protocols)} onChange={(value) => set('hsts', value)} title="启用 HSTS" description="仅 HTTPS / WSS 入口可用。" /><CheckRow checked={draft.rejectUnauthorized} disabled={!draft.targetProtocols.some((protocol) => ['https', 'wss'].includes(protocol))} onChange={(value) => set('rejectUnauthorized', value)} title="校验目标证书" description="目标使用自签名证书时可关闭。" /></div></div> : null}
    {tab === 'security' ? <div className="form-stack"><div className="access-note"><i className="bi bi-shield-check" aria-hidden="true" /><span>黑名单优先于白名单；白名单留空时允许所有来源。支持单个 IP 和 CIDR 网段。</span></div><div className="form-grid two"><Field label="白名单（Allow IPs）" hint="每行一个，例如 192.168.1.0/24"><textarea rows="7" value={draft.allowText} onChange={(event) => set('allowText', event.target.value)} placeholder="留空允许所有" /></Field><Field label="黑名单（Block IPs）" hint="黑名单始终优先"><textarea rows="7" value={draft.blockText} onChange={(event) => set('blockText', event.target.value)} placeholder="例如 10.0.0.8" /></Field></div>{mode === 'precise' ? <><CheckRow checked={draft.realIp.enabled} onChange={(value) => setDraft((current) => ({ ...current, realIp: { ...current.realIp, enabled: value } }))} title="传递真实客户端 IP" description="自动添加 X-Forwarded-For 等转发头。" />{draft.realIp.enabled ? <Field label="真实 IP 请求头"><input value={draft.realIp.header} onChange={(event) => setDraft((current) => ({ ...current, realIp: { ...current.realIp, header: event.target.value } }))} /></Field> : null}</> : null}</div> : null}
  </div><footer className="dialog-actions"><Dialog.Close className="secondary-button" disabled={saving}>取消</Dialog.Close><button type="submit" className="primary-button" disabled={saving}><i className={`bi ${saving ? 'bi-arrow-repeat' : 'bi-floppy'}`} aria-hidden="true" />{saving ? '正在保存…' : '保存并应用'}</button></footer></form></Dialog.Popup></Dialog.Portal></Dialog.Root>;
}

function CertificateRow({ certificate, rules, rulesAvailable, onDelete }) {
  const systemManaged = isSystemCertificate(certificate);
  const used = rulesAvailable ? rules.filter((rule) => rule.tls?.certId === certificate.id) : null;
  const currentValidity = certificateState(certificate);
  const validity = certificate.stale && currentValidity.usable
    ? { ...currentValidity, state: 'warning', label: currentValidity.state === 'healthy' ? '缓存副本' : `${currentValidity.label} · 缓存`, message: certificate.lastError || `系统读取异常，正在继续使用上一份有效证书；${currentValidity.message}` }
    : currentValidity;
  const deleteBlockedReason = systemManaged || certificate.deletable === false
    ? '系统托管证书为只读，请在 fnOS 中管理'
    : !rulesAvailable
      ? '规则数据暂不可用，无法确认引用关系'
      : used.length ? '证书正在使用中，无法删除' : '';
  const systemState = !currentValidity.usable
    ? '当前不可用'
    : certificate.stale
    ? '读取异常，上一份仍可用'
    : '已读取，可用于规则';

  return <article className={`certificate-row${systemManaged ? ' system-managed' : ''}${currentValidity.usable ? '' : ' unavailable'}`}>
    <span className="certificate-icon"><i className={`bi ${systemManaged ? 'bi-hdd-network' : 'bi-shield-lock'}`} aria-hidden="true" /></span>
    <div className="certificate-primary">
      <div><h3>{certificate.name}</h3><StatusChip state={validity.state} label={validity.label} message={validity.message} /><span className={`certificate-source-badge ${systemManaged ? 'system' : 'manual'}`}>{systemManaged ? '系统托管' : '应用'}</span></div>
      <p title={certificate.subjectAltNames?.join(', ') || certificate.subject}>{certificate.subjectAltNames?.join('、') || certificate.domains?.join('、') || certificate.subject || '未读取到证书主体'}</p>
      <span>{certificate.format || (systemManaged ? 'SYSTEM' : 'PEM')} · {(certificate.keyType || 'key').toUpperCase()}{certificate.chainLength > 1 ? ` · ${certificate.chainLength} 级证书链` : ''}</span>
    </div>
    <dl className="certificate-facts">
      <div><dt>有效期</dt><dd>{formatCertificateDate(certificate.validFrom)} – {formatCertificateDate(certificate.validTo)}</dd></div>
      <div><dt>{systemManaged ? '系统状态' : '使用规则'}</dt><dd title={systemManaged ? certificate.lastError || systemState : undefined}>{systemManaged ? systemState : !rulesAvailable ? '无法确认' : used.length ? used.map((rule) => rule.name).join('、') : '未使用'}</dd></div>
    </dl>
    {systemManaged ? <span className="certificate-readonly" title="由 fnOS 管理，不能在这里删除、替换或导出"><i className="bi bi-lock" aria-hidden="true" />只读</span> : <button type="button" className="row-action danger" disabled={Boolean(deleteBlockedReason)} aria-label={`删除证书 ${certificate.name}`} title={deleteBlockedReason || '删除证书'} onClick={() => onDelete(certificate)}><i className="bi bi-trash3" aria-hidden="true" /></button>}
  </article>;
}

function CertificatesPage({ certificates, systemSource, rules, rulesAvailable, systemReloading, onCreate, onDelete, onReloadSystem }) {
  const applicationCertificates = certificates.filter((certificate) => !isSystemCertificate(certificate));
  const systemCertificates = certificates.filter(isSystemCertificate);
  const reportedSourceState = systemSource?.state;
  const sourceState = ['ready', 'degraded', 'unavailable'].includes(reportedSourceState)
    ? reportedSourceState
    : systemSource?.available ? 'ready' : 'unavailable';
  const sourceChipState = sourceState === 'ready' ? 'healthy' : sourceState === 'degraded' ? 'warning' : 'disabled';
  const sourceLabel = sourceState === 'ready' ? '读取正常' : sourceState === 'degraded' ? '正在回退' : '暂不可用';
  const sourceMessage = systemSource?.message || (sourceState === 'unavailable'
    ? '当前环境未提供可读取的 fnOS 系统证书；应用证书仍可正常使用。'
    : '正在继续使用上一份已通过校验的系统证书。');
  const sourceErrorEntry = systemSource?.errors?.[0];
  const sourceError = typeof sourceErrorEntry === 'string' ? sourceErrorEntry : sourceErrorEntry?.message || '';
  const lastSuccessAt = certificateTimestamp(systemSource?.lastSuccessAt);

  return <section className="view certificate-groups" aria-label="证书">
    <article className="matte-surface certificate-surface">
      <div className="section-heading"><div><h2>应用证书</h2><p>由本应用终止 HTTPS / WSS 时使用；支持 PEM、CRT、PFX 与 P12 等常见格式。</p></div><button type="button" className="primary-button" onClick={onCreate}><i className="bi bi-upload" aria-hidden="true" />导入证书</button></div>
      <div className="certificate-list">{applicationCertificates.map((certificate) => <CertificateRow key={certificate.id} certificate={certificate} rules={rules} rulesAvailable={rulesAvailable} onDelete={onDelete} />)}{!applicationCertificates.length ? <EmptyState icon="bi-shield-lock" title="还没有应用证书" description="一次选择证书链和私钥，或直接导入带密码的 PFX / P12。" action="导入证书" onAction={onCreate} /> : null}</div>
    </article>

    <article className="matte-surface certificate-surface system-certificate-surface">
      <div className="section-heading certificate-group-heading"><div><div className="certificate-title-line"><h2>fnOS 系统证书</h2><span className="experimental-badge">实验性</span><span className="readonly-badge">只读</span></div><p>直接复用 fnOS 已配置的 HTTPS / WSS 证书。</p></div><button type="button" className="secondary-button" disabled={systemReloading} onClick={onReloadSystem}><i className={`bi ${systemReloading ? 'bi-arrow-repeat' : 'bi-arrow-clockwise'}`} aria-hidden="true" />{systemReloading ? '正在读取…' : '重新读取'}</button></div>
      <aside className={`system-source-notice ${sourceState}`} role="status" aria-live="polite">
        <i className={`bi ${sourceState === 'ready' ? 'bi-check-circle' : sourceState === 'degraded' ? 'bi-exclamation-triangle' : 'bi-info-circle'}`} aria-hidden="true" />
        <div><span><StatusChip state={sourceChipState} label={sourceLabel} message={sourceMessage} />{Number.isFinite(lastSuccessAt) ? <small>上次成功读取 {new Date(lastSuccessAt).toLocaleString()}</small> : null}</span><p>{sourceMessage}{sourceError && !sourceMessage.includes(sourceError) ? ` ${sourceError}` : ''}</p></div>
      </aside>
      <div className="certificate-list">{systemCertificates.map((certificate) => <CertificateRow key={certificate.id} certificate={certificate} rules={rules} rulesAvailable={rulesAvailable} onDelete={onDelete} />)}{!systemCertificates.length ? <EmptyState icon="bi-hdd-network" title={sourceState === 'unavailable' ? '暂时无法读取系统证书' : 'fnOS 暂无可用系统证书'} description={sourceState === 'unavailable' ? '可继续导入应用证书，或在规则中使用 TLS 透传。' : '在 fnOS 中配置证书后，点击“重新读取”同步到这里。'} /> : null}</div>
    </article>

  </section>;
}

function CertificateDialog({ open, onClose, onInspect, onSave, saving }) {
  const [mode, setMode] = useState('files');
  const [form, setForm] = useState({ name: '', certificate: '', privateKey: '', passphrase: '', files: [] });
  const [selectedFiles, setSelectedFiles] = useState([]);
  const [previews, setPreviews] = useState([]);
  const [warnings, setWarnings] = useState([]);
  const [localError, setLocalError] = useState('');
  const [inspecting, setInspecting] = useState(false);
  const inspectRequest = useRef(0);
  useEffect(() => { inspectRequest.current += 1; setMode('files'); setForm({ name: '', certificate: '', privateKey: '', passphrase: '', files: [] }); setSelectedFiles([]); setPreviews([]); setWarnings([]); setLocalError(''); setInspecting(false); }, [open]);
  const inspectFiles = async (files = selectedFiles, passphrase = form.passphrase) => {
    if (!files.length) { setLocalError('请选择证书文件'); return; }
    const requestId = ++inspectRequest.current;
    setInspecting(true); setLocalError(''); setWarnings([]); setPreviews([]);
    try { const uploads = await Promise.all(files.map(fileUpload)); const result = await onInspect({ files: uploads, passphrase, name: form.name }); if (requestId !== inspectRequest.current) return; setForm((current) => ({ ...current, files: uploads })); setPreviews(result.candidates || []); setWarnings(result.warnings || []); }
    catch (error) { if (requestId === inspectRequest.current) setLocalError(error.message); }
    finally { if (requestId === inspectRequest.current) setInspecting(false); }
  };
  const chooseFiles = (files) => {
    const next = Array.from(files || []);
    inspectRequest.current += 1;
    setForm((current) => ({ ...current, files: [] })); setPreviews([]); setWarnings([]); setInspecting(false);
    if (next.length > 20) { setSelectedFiles([]); setLocalError('一次最多选择 20 个文件'); return; }
    const tooLarge = next.find((file) => file.size > 2 * 1024 * 1024);
    if (tooLarge) { setSelectedFiles([]); setLocalError(`${tooLarge.name} 超过单文件 2 MB 限制`); return; }
    const totalSize = next.reduce((sum, file) => sum + file.size, 0);
    if (totalSize > 11 * 1024 * 1024) { setSelectedFiles([]); setLocalError('所选文件总大小过大，请分批导入'); return; }
    setSelectedFiles(next); setLocalError(''); if (next.length) void inspectFiles(next);
  };
  const updateInspectionInput = (key, value, message) => {
    const hasInspection = Boolean(selectedFiles.length);
    if (hasInspection) inspectRequest.current += 1;
    setInspecting(false); setPreviews([]); setWarnings([]);
    setForm((current) => ({ ...current, [key]: value, files: hasInspection ? [] : current.files }));
    setLocalError(hasInspection ? message : '');
  };
  const submit = async (event) => {
    event.preventDefault();
    setLocalError('');
    if (mode === 'files' && (!previews.length || !form.files.length)) { setLocalError('请先选择文件并完成解析'); return; }
    const saved = await onSave(mode === 'files' ? { kind: 'files', files: form.files, passphrase: form.passphrase, name: form.name } : { kind: 'paste', name: form.name, certificate: form.certificate, privateKey: form.privateKey });
    if (saved !== true) setLocalError(`${errorText(saved?.error, '导入未完成，请检查证书、私钥或密码')}。当前内容已保留。`);
  };
  return <Dialog.Root open={open} onOpenChange={(value) => { if (!value && !saving) onClose(); }}><Dialog.Portal><Dialog.Backdrop className="dialog-backdrop" /><Dialog.Popup className="dialog-popup certificate-dialog"><form onSubmit={submit}><header className="dialog-header"><div><span className="section-kicker">IMPORT CERTIFICATE</span><Dialog.Title>导入 HTTPS 证书</Dialog.Title><Dialog.Description>支持多文件、证书链和 PKCS#12，导入前会自动解析并校验私钥。</Dialog.Description></div><Dialog.Close className="dialog-close" aria-label="关闭" disabled={saving}><i className="bi bi-x-lg" aria-hidden="true" /></Dialog.Close></header><div className="dialog-tabs certificate-tabs">{[['files', '文件导入'], ['paste', '粘贴 PEM']].map(([value, label]) => <button key={value} type="button" aria-pressed={mode === value} className={mode === value ? 'active' : ''} onClick={() => { inspectRequest.current += 1; setInspecting(false); setMode(value); setForm((current) => ({ ...current, files: [] })); setPreviews([]); setWarnings([]); setLocalError(''); }}>{label}</button>)}</div><div className="dialog-body form-stack">{mode === 'files' ? <><Field label="证书名称" hint="可选；留空时自动读取域名或文件名"><input value={form.name} onChange={(event) => updateInspectionInput('name', event.target.value, '名称已更改，请重新解析')} placeholder="例如：家庭域名证书" /></Field><label className={`certificate-dropzone${inspecting ? ' busy' : ''}`}><input type="file" multiple accept=".pem,.crt,.cer,.key,.der,.pfx,.p12,application/x-pkcs12" onChange={(event) => { chooseFiles(event.target.files); event.target.value = ''; }} /><span className="dropzone-icon"><i className={`bi ${inspecting ? 'bi-arrow-repeat' : 'bi-cloud-arrow-up'}`} aria-hidden="true" /></span><strong>{inspecting ? '正在识别证书与私钥…' : '选择证书文件'}</strong><small>可多选 PEM / CRT / CER / KEY / DER，或直接选择 PFX / P12</small></label>{selectedFiles.length ? <div className="selected-file-list">{selectedFiles.map((file) => <span key={`${file.name}-${file.size}`}><i className="bi bi-file-earmark-lock" aria-hidden="true" /><b>{file.name}</b><small>{Math.max(1, Math.round(file.size / 1024))} KB</small></span>)}</div> : null}{selectedFiles.length ? <div className="pfx-passphrase"><Field label="文件密码" hint="用于 PFX、P12 或加密私钥；无密码时留空"><input type="password" value={form.passphrase} onChange={(event) => updateInspectionInput('passphrase', event.target.value, '密码已更改，请重新解析')} /></Field><button type="button" className="secondary-button" disabled={inspecting} onClick={() => void inspectFiles()}><i className="bi bi-arrow-clockwise" aria-hidden="true" />重新解析</button></div> : null}{previews.length ? <div className="certificate-preview-list"><div className="preview-heading"><strong>解析成功 · {previews.length} 张证书</strong><span>保存前请确认域名和有效期</span></div>{previews.map((certificate) => <article key={certificate.id}><span className="preview-check"><i className="bi bi-check-lg" aria-hidden="true" /></span><div><strong>{certificate.name}</strong><small>{certificate.subjectAltNames?.join('、') || certificate.subject}</small><span>{certificate.format} · {(certificate.keyType || '').toUpperCase()} · {certificate.chainLength} 级证书链</span></div><time>{new Date(certificate.validTo).toLocaleDateString()} 到期</time></article>)}</div> : null}{warnings.length ? <div className="import-warnings"><i className="bi bi-exclamation-triangle" aria-hidden="true" /><span>{warnings.join('；')}</span></div> : null}</> : <><Field label="证书名称" required><input required value={form.name} onChange={(event) => setForm((current) => ({ ...current, name: event.target.value }))} placeholder="例如：home.example.com" /></Field><Field label="证书与证书链（PEM）" required><textarea className="mono-input" required rows="7" value={form.certificate} onChange={(event) => setForm((current) => ({ ...current, certificate: event.target.value }))} placeholder="-----BEGIN CERTIFICATE-----" /></Field><Field label="私钥（PEM）" required><textarea className="mono-input" required rows="7" value={form.privateKey} onChange={(event) => setForm((current) => ({ ...current, privateKey: event.target.value }))} placeholder="-----BEGIN PRIVATE KEY-----" /></Field></>}{localError ? <div className="form-error-banner persistent" role="alert"><i className="bi bi-exclamation-octagon" aria-hidden="true" />{localError}</div> : null}</div><footer className="dialog-actions"><Dialog.Close className="secondary-button" disabled={saving}>取消</Dialog.Close><button className="primary-button" disabled={saving || inspecting || mode === 'files' && !previews.length}><i className={`bi ${saving ? 'bi-arrow-repeat' : 'bi-shield-check'}`} aria-hidden="true" />{saving ? '正在导入…' : mode === 'files' ? previews.length ? `导入 ${previews.length} 张证书` : '导入证书' : '校验并保存'}</button></footer></form></Dialog.Popup></Dialog.Portal></Dialog.Root>;
}

function LogsPage({ logs, onRefresh, onClear }) {
  const [level, setLevel] = useState('all'); const [search, setSearch] = useState(''); const deferred = useDeferredValue(search.toLowerCase());
  const visible = logs.filter((entry) => (level === 'all' || entry.level === level) && (!deferred || `${entry.message} ${JSON.stringify(entry.meta)}`.toLowerCase().includes(deferred)));
  const download = () => downloadJson({ generatedAt: new Date().toISOString(), entries: visible }, `reverse-proxy-logs-${new Date().toISOString().slice(0, 10)}.json`);
  return <section className="view" aria-label="日志"><article className="matte-surface logs-surface"><div className="log-toolbar"><div className="search-box"><i className="bi bi-search" aria-hidden="true" /><input value={search} onChange={(event) => setSearch(event.target.value)} placeholder="搜索消息、规则或错误代码" aria-label="搜索日志" /></div><select value={level} onChange={(event) => setLevel(event.target.value)} aria-label="日志级别"><option value="all">全部级别</option><option value="error">ERROR</option><option value="warn">WARN</option><option value="info">INFO</option><option value="debug">DEBUG</option></select><button className="secondary-button" type="button" onClick={onRefresh}><i className="bi bi-arrow-clockwise" aria-hidden="true" />刷新</button><button className="secondary-button" type="button" onClick={download}><i className="bi bi-download" aria-hidden="true" />导出</button><button className="danger-button" type="button" onClick={onClear}><i className="bi bi-trash3" aria-hidden="true" />清空</button></div><div className="log-list">{visible.map((entry) => <article className="log-entry" key={entry.id}><span className={`log-level ${entry.level}`}>{entry.level.toUpperCase()}</span><time>{new Date(entry.at).toLocaleString()}</time><div><strong>{entry.message}</strong>{Object.keys(entry.meta || {}).length ? <code>{JSON.stringify(entry.meta)}</code> : null}</div></article>)}{!visible.length ? <EmptyState icon="bi-card-text" title="没有符合条件的日志" description="尝试更换日志级别或清除搜索内容。" /> : null}</div></article></section>;
}

function SettingsPage({ settings, network, status, statusState, networkAvailable, onSave, onImport, onDiagnostics, onDirtyChange, saving, importing }) {
  const [draft, setDraft] = useState(settings);
  const [dirty, setDirty] = useState(false);
  const [intervalError, setIntervalError] = useState('');
  const [submitError, setSubmitError] = useState('');
  useEffect(() => { if (!dirty) { setDraft(settings); setIntervalError(''); setSubmitError(''); } }, [settings, dirty]);
  useEffect(() => { onDirtyChange(dirty); }, [dirty, onDirtyChange]);
  const update = (key, value) => { setDirty(true); setSubmitError(''); if (key === 'healthCheckInterval') setIntervalError(''); setDraft((current) => ({ ...current, [key]: value })); };
  const save = async () => {
    const interval = Number(draft.healthCheckInterval);
    if (!Number.isInteger(interval) || interval < 5 || interval > 3600) { setIntervalError('请输入 5–3600 之间的整数秒数'); return; }
    const result = await onSave({ ...draft, healthCheckInterval: interval });
    if (result === true) { setDirty(false); setIntervalError(''); }
    else setSubmitError(errorText(result?.error, '设置保存未完成，请重试'));
  };
  const importFile = async (file) => {
    if (dirty && !window.confirm('当前设置尚未保存。继续导入会放弃这些修改，确定继续吗？')) return;
    const result = await onImport(file);
    if (result === true || result?.error?.uncertain) {
      setDirty(false);
      setIntervalError('');
      setSubmitError('');
    }
  };
  const statusChipState = statusState === 'loading' ? 'starting' : statusState === 'healthy' ? 'healthy' : 'error';
  const availableAddresses = networkAvailable ? [...new Set((network.interfaces || []).map((item) => item.address).filter(Boolean))] : [];
  return <section className="view" aria-label="设置"><div className="settings-grid"><article className="matte-surface settings-card"><div className="section-heading"><div><h2>运行检测</h2><p>定期检查全部目标端口，及时发现不可用的后端服务。</p></div>{dirty ? <span className="unsaved-badge">未保存</span> : null}</div><div className="form-stack">{submitError ? <div className="form-error-banner persistent" role="alert"><i className="bi bi-exclamation-octagon" aria-hidden="true" />{submitError}</div> : null}<Field label="健康检查间隔（秒）" hint="可设置 5–3600 秒" error={intervalError}><input type="number" min="5" max="3600" value={draft.healthCheckInterval ?? ''} onChange={(event) => update('healthCheckInterval', event.target.value)} /></Field><Field label="日志记录级别"><select value={draft.logLevel || 'info'} onChange={(event) => update('logLevel', event.target.value)}><option value="debug">DEBUG（详细）</option><option value="info">INFO（日常）</option><option value="warn">WARN（仅警告）</option><option value="error">ERROR（仅错误）</option></select></Field><button type="button" className="primary-button align-start" disabled={saving || importing || !dirty} onClick={() => void save()}><i className={`bi ${saving ? 'bi-arrow-repeat' : 'bi-floppy'}`} aria-hidden="true" />{saving ? '正在保存…' : '保存设置'}</button></div></article><article className="matte-surface settings-card"><div className="section-heading"><div><h2>配置备份</h2><p>导出规则与设置。为保护安全，备份不会包含证书私钥。</p></div></div><div className="backup-actions"><a className="primary-button" href={apiUrl('/export')} download><i className="bi bi-download" aria-hidden="true" />导出配置</a><label className="secondary-button file-button" aria-disabled={saving || importing}><i className={`bi ${importing ? 'bi-arrow-repeat' : 'bi-upload'}`} aria-hidden="true" />{importing ? '正在导入…' : '导入配置'}<input type="file" accept="application/json,.json" disabled={saving || importing} onChange={(event) => { const file = event.target.files?.[0]; if (file) void importFile(file); event.target.value = ''; }} /></label><button type="button" className="secondary-button" onClick={onDiagnostics}><i className="bi bi-file-earmark-medical" aria-hidden="true" />诊断包</button></div><div className="backup-note"><i className="bi bi-info-circle" aria-hidden="true" /><span>合并导入时会重新生成规则标识，并保持规则停用，避免端口冲突。</span></div></article><article className="matte-surface settings-card system-card"><div className="section-heading"><div><h2>系统信息</h2></div><StatusChip state={statusChipState} label={statusChipState === 'starting' ? '检测中' : undefined} /></div><dl className="system-list"><div><dt>NAS 主机名</dt><dd>{networkAvailable ? network.hostname || '未知' : '暂无法读取'}</dd></div><div><dt>统一网关</dt><dd><code>/app/reverse-proxy</code></dd></div><div className="address-row"><dt>可用地址</dt><dd className="address-list">{!networkAvailable ? '暂无法读取' : availableAddresses.length ? availableAddresses.map((address) => <code key={address}>{address}</code>) : '未检测到'}</dd></div><div><dt>运行模式</dt><dd>{statusState === 'loading' ? '检测中' : statusState === 'error' ? '暂无法读取' : status?.demoMode ? '本地演示' : '真实代理'}</dd></div><div><dt>版本</dt><dd>{status?.version || '1.0.3'}</dd></div></dl></article></div></section>;
}

function AboutPage({ version }) {
  return <section className="view" aria-label="关于"><article className="matte-surface about-card">
    <div className="about-brand"><img src="/app/reverse-proxy/images/reverse-proxy.png" alt="反向代理：请求经过网关转发到目标服务" /><div><h2>反向代理</h2><p>面向飞牛 fnOS 的多协议反向代理工具。</p></div></div>
    <dl className="about-list">
      <div><dt>版本</dt><dd>{version || '1.0.3'}</dd></div>
      <div><dt>项目地址</dt><dd><a href={PROJECT_URL} target="_blank" rel="noreferrer">{PROJECT_URL}<i className="bi bi-box-arrow-up-right" aria-hidden="true" /></a></dd></div>
      <div><dt>许可</dt><dd>Copyright © 2026 BearHero</dd></div>
    </dl>
  </article></section>;
}

const resourceKeys = ['status', 'rules', 'certificates', 'logs', 'settings', 'network'];
const createResourceState = () => Object.fromEntries(resourceKeys.map((key) => [key, { loading: true, error: '', hasData: false, lastSuccessAt: null }]));

function DataNotice({ messages, onRetry }) {
  if (!messages.length) return null;
  return <aside className="data-notice" role="alert"><i className="bi bi-cloud-slash" aria-hidden="true" /><div><strong>部分数据暂时无法同步</strong><p>{messages.join('；')}。已加载的数据会继续保留，修复连接后可重新同步。</p></div><button type="button" className="secondary-button" onClick={onRetry}><i className="bi bi-arrow-clockwise" aria-hidden="true" />重试</button></aside>;
}

function ResourceUnavailable({ message, onRetry }) {
  return <section className="view matte-surface resource-unavailable" role="alert"><span><i className="bi bi-cloud-slash" aria-hidden="true" /></span><h2>暂时无法读取数据</h2><p>{message || '管理服务没有返回数据，请检查应用状态后重试。'}</p><button type="button" className="primary-button" onClick={onRetry}><i className="bi bi-arrow-clockwise" aria-hidden="true" />重新加载</button></section>;
}

export function App() {
  const [route, setRoute] = useState(() => Object.hasOwn(ROUTES, location.hash.slice(1)) ? location.hash.slice(1) : 'rules');
  const [status, setStatus] = useState(null);
  const [rules, setRules] = useState([]);
  const [runtime, setRuntime] = useState({});
  const [certificates, setCertificates] = useState([]);
  const [certificateSources, setCertificateSources] = useState({ system: null });
  const [logs, setLogs] = useState([]);
  const [settings, setSettings] = useState({ healthCheckInterval: 30, logLevel: 'info' });
  const [network, setNetwork] = useState({ interfaces: [] });
  const [resources, setResources] = useState(createResourceState);
  const [settingsDirty, setSettingsDirty] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(() => new Set());
  const [toast, setToast] = useState(null);
  const [ruleDialog, setRuleDialog] = useState({ open: false, rule: null });
  const [certificateOpen, setCertificateOpen] = useState(false);
  const toastTimer = useRef(null);
  const coreRequest = useRef(0);
  const logsRequest = useRef(0);
  const settingsRequest = useRef(0);
  const mainRef = useRef(null);
  const routeRef = useRef(route);
  const settingsDirtyRef = useRef(settingsDirty);
  const settingsSavingRef = useRef(false);
  const busyRef = useRef(new Set());

  const notify = useCallback((message, type = 'ok') => {
    window.clearTimeout(toastTimer.current);
    setToast({ message, type });
    toastTimer.current = window.setTimeout(() => setToast(null), 4200);
  }, []);

  useEffect(() => () => window.clearTimeout(toastTimer.current), []);
  useEffect(() => { routeRef.current = route; }, [route]);
  useEffect(() => { settingsDirtyRef.current = settingsDirty; }, [settingsDirty]);
  useEffect(() => {
    const handler = (event) => {
      if (!settingsDirtyRef.current && !settingsSavingRef.current) return;
      event.preventDefault();
      event.returnValue = '';
    };
    addEventListener('beforeunload', handler);
    return () => removeEventListener('beforeunload', handler);
  }, []);
  const navigate = useCallback((next) => {
    if (!Object.hasOwn(ROUTES, next) || next === routeRef.current) return;
    if (routeRef.current === 'settings' && settingsSavingRef.current) { notify('设置操作正在进行，请等待完成后再离开', 'error'); return; }
    if (routeRef.current === 'settings' && settingsDirtyRef.current && !window.confirm('设置尚未保存，确定离开并放弃这些修改吗？')) return;
    settingsDirtyRef.current = false;
    setSettingsDirty(false);
    routeRef.current = next;
    location.hash = next;
    setRoute(next);
  }, [notify]);
  useEffect(() => {
    const handler = () => {
      const next = location.hash.slice(1);
      if (!Object.hasOwn(ROUTES, next) || next === routeRef.current) return;
      if (routeRef.current === 'settings' && settingsSavingRef.current) {
        history.forward();
        notify('设置操作正在进行，请等待完成后再离开', 'error');
        return;
      }
      if (routeRef.current === 'settings' && settingsDirtyRef.current && !window.confirm('设置尚未保存，确定离开并放弃这些修改吗？')) {
        history.forward();
        return;
      }
      settingsDirtyRef.current = false;
      setSettingsDirty(false);
      routeRef.current = next;
      setRoute(next);
    };
    addEventListener('hashchange', handler);
    return () => removeEventListener('hashchange', handler);
  }, [notify]);
  useEffect(() => {
    document.title = `${ROUTES[route].title} · 反向代理管理器`;
    window.scrollTo(0, 0);
    window.requestAnimationFrame(() => mainRef.current?.focus({ preventScroll: true }));
  }, [route]);

  const loadCore = useCallback(async (quiet = false) => {
    const requestId = ++coreRequest.current;
    if (!quiet) {
      setLoading(true);
      setResources((current) => ({
        ...current,
        status: { ...current.status, loading: true },
        rules: { ...current.rules, loading: true },
        certificates: { ...current.certificates, loading: true },
      }));
    }
    const results = await Promise.allSettled([api('/status'), api('/rules'), api('/certificates')]);
    if (requestId !== coreRequest.current) return;
    const [statusResult, rulesResult, certificatesResult] = results;
    const completedAt = Date.now();
    if (statusResult.status === 'fulfilled') setStatus(statusResult.value);
    else setStatus((current) => ({ ...(current || {}), ok: false, version: current?.version || '1.0.3' }));
    if (rulesResult.status === 'fulfilled') { setRules(rulesResult.value.rules || []); setRuntime(rulesResult.value.runtime || {}); }
    if (certificatesResult.status === 'fulfilled') {
      setCertificates(certificatesResult.value.certificates || []);
      setCertificateSources(certificatesResult.value.sources || { system: null });
    }
    setResources((current) => {
      const next = { ...current };
      [['status', statusResult], ['rules', rulesResult], ['certificates', certificatesResult]].forEach(([key, result]) => {
        const success = result.status === 'fulfilled';
        next[key] = {
          ...current[key],
          loading: false,
          error: success ? '' : result.reason?.message || '请求失败',
          hasData: success || current[key].hasData,
          lastSuccessAt: success ? completedAt : current[key].lastSuccessAt,
        };
      });
      return next;
    });
    const failure = results.find((result) => result.status === 'rejected');
    if (failure && !quiet) notify(failure.reason?.message || '部分数据加载失败，请重试', 'error');
    setLoading(false);
  }, [notify]);

  const loadLogs = useCallback(async (quiet = false) => {
    const requestId = ++logsRequest.current;
    setResources((current) => ({ ...current, logs: { ...current.logs, loading: true } }));
    try {
      const data = await api('/logs?limit=500');
      if (requestId !== logsRequest.current) return;
      setLogs(data.entries || []);
      setResources((current) => ({ ...current, logs: { ...current.logs, loading: false, error: '', hasData: true, lastSuccessAt: Date.now() } }));
    } catch (error) {
      if (requestId !== logsRequest.current) return;
      setResources((current) => ({ ...current, logs: { ...current.logs, loading: false, error: error.message || '请求失败' } }));
      if (!quiet) notify(`日志加载失败：${error.message}`, 'error');
    }
  }, [notify]);
  const loadSettings = useCallback(async (quiet = false) => {
    const requestId = ++settingsRequest.current;
    setResources((current) => ({ ...current, settings: { ...current.settings, loading: true }, network: { ...current.network, loading: true } }));
    const results = await Promise.allSettled([api('/settings'), api('/network')]);
    if (requestId !== settingsRequest.current) return;
    if (results[0].status === 'fulfilled') setSettings(results[0].value.settings || {});
    if (results[1].status === 'fulfilled') setNetwork(results[1].value || { interfaces: [] });
    const completedAt = Date.now();
    setResources((current) => {
      const next = { ...current };
      [['settings', results[0]], ['network', results[1]]].forEach(([key, result]) => {
        const success = result.status === 'fulfilled';
        next[key] = {
          ...current[key],
          loading: false,
          error: success ? '' : result.reason?.message || '请求失败',
          hasData: success || current[key].hasData,
          lastSuccessAt: success ? completedAt : current[key].lastSuccessAt,
        };
      });
      return next;
    });
    const failure = results.find((result) => result.status === 'rejected');
    if (failure && !quiet) notify(`设置加载失败：${failure.reason?.message || '请重试'}`, 'error');
  }, [notify]);

  useEffect(() => {
    void loadCore();
    const timer = window.setInterval(() => void loadCore(true), 15000);
    return () => window.clearInterval(timer);
  }, [loadCore]);
  useEffect(() => {
    if (route === 'logs') void loadLogs();
    if (route === 'settings') void loadSettings();
  }, [route, loadLogs, loadSettings]);

  const refreshCurrent = async () => {
    await loadCore();
    if (route === 'logs') await loadLogs();
    if (route === 'settings') await loadSettings();
  };
  const withBusy = async (id, action, reconcile) => {
    const settingsOperation = id === 'settings' || id === 'import';
    if (busyRef.current.has(id) || settingsOperation && settingsSavingRef.current) {
      notify('操作仍在处理中，请等待同步完成', 'error');
      return { ok: false, pending: true, error: new Error('操作仍在处理中') };
    }
    busyRef.current.add(id);
    if (settingsOperation) settingsSavingRef.current = true;
    setBusy((current) => new Set(current).add(id));
    try { await action(); return true; }
    catch (error) {
      notify(errorText(error), 'error');
      if (error?.uncertain && reconcile) {
        await Promise.resolve(reconcile()).catch(() => {});
        await new Promise((resolve) => window.setTimeout(resolve, 2500));
        await Promise.resolve(reconcile()).catch(() => {});
      }
      return { ok: false, error };
    }
    finally {
      if (settingsOperation) settingsSavingRef.current = false;
      busyRef.current.delete(id);
      setBusy((current) => { const next = new Set(current); next.delete(id); return next; });
    }
  };
  const saveRule = (draft) => withBusy('save-rule', async () => {
    const editing = ruleDialog.rule;
    const result = await api(editing ? `/rules/${editing.id}` : '/rules', { method: editing ? 'PUT' : 'POST', body: draft });
    setRuleDialog({ open: false, rule: null });
    const run = result.runtime;
    if (run && !['healthy', 'disabled'].includes(run.state)) notify(`规则已保存，但未能正常启动：${run.message || '请检查配置'}`, 'error');
    else notify(editing ? '规则已更新并应用' : draft.enabled ? '规则已创建并开始监听' : '规则已创建，当前保持停用');
    await loadCore(true);
  }, () => loadCore(true));
  const toggleRule = (rule, enabled) => withBusy(rule.id, async () => {
    const result = await api(`/rules/${rule.id}/toggle`, { method: 'POST', body: { enabled } });
    if (enabled && result.runtime && result.runtime.state !== 'healthy') notify(`规则已启用，但启动失败：${result.runtime.message || '请检查配置'}`, 'error');
    else notify(enabled ? '规则已启用' : '规则已停用');
    await loadCore(true);
  }, () => loadCore(true));
  const duplicateRule = (rule) => withBusy(rule.id, async () => { await api(`/rules/${rule.id}/duplicate`, { method: 'POST' }); notify('已创建停用状态的规则副本'); await loadCore(true); }, () => loadCore(true));
  const deleteRule = (rule) => { if (!window.confirm(`确定删除“${rule.name}”吗？此操作无法撤销。`)) return; void withBusy(rule.id, async () => { await api(`/rules/${rule.id}`, { method: 'DELETE' }); notify('规则已删除'); await loadCore(true); }, () => loadCore(true)); };
  const testRule = (rule) => withBusy(rule.id, async () => { const result = await api(`/rules/${rule.id}/test`, { method: 'POST', timeoutMs: 15000, idempotent: true }); notify(result.runtime?.state === 'healthy' ? `全部目标连接正常，延迟 ${result.runtime.latencyMs || '—'} ms` : result.runtime?.message || '目标连接异常', result.runtime?.state === 'healthy' ? 'ok' : 'error'); await loadCore(true); }, () => loadCore(true));
  const inspectCertificates = (payload) => api('/certificates/inspect', { method: 'POST', body: payload, timeoutMs: 30000, idempotent: true });
  const saveCertificate = (form) => withBusy('save-certificate', async () => { const result = form.kind === 'files' ? await api('/certificates/import', { method: 'POST', body: { files: form.files, passphrase: form.passphrase, name: form.name } }) : await api('/certificates', { method: 'POST', body: form }); setCertificateOpen(false); const count = result.certificates?.length ?? 1; notify(count ? `已解析并导入 ${count} 张证书` : result.warnings?.[0] || '所选证书已存在'); await loadCore(true); }, () => loadCore(true));
  const deleteCertificate = (certificate) => { if (!window.confirm(`确定删除证书“${certificate.name}”吗？`)) return; void withBusy(certificate.id, async () => { await api(`/certificates/${certificate.id}`, { method: 'DELETE' }); notify('证书已删除'); await loadCore(true); }, () => loadCore(true)); };
  const reloadSystemCertificates = () => withBusy('reload-system-certificates', async () => {
    const result = await api('/certificates/system/reload', { method: 'POST', idempotent: true, timeoutMs: 30000 });
    if (result.status) setCertificateSources((current) => ({ ...current, system: result.status }));
    if (result.status?.state === 'ready' && result.ok !== false) notify(`已读取 ${result.status.certificateCount ?? result.certificates?.filter(isSystemCertificate).length ?? 0} 张系统证书`);
    else if (result.status?.state === 'ready') notify(result.tlsReload?.message || result.tlsReload?.failures?.[0]?.message || '系统证书已读取，但部分 HTTPS / WSS 规则未能热更新，请查看规则状态', 'error');
    else if (result.status?.usingLastKnownGood) notify('系统证书读取异常，已继续使用上一份有效副本', 'error');
    else notify(result.status?.message || '系统证书暂不可读取，应用证书不受影响', 'error');
    await loadCore(true);
  }, () => loadCore(true));
  const clearLogs = () => { if (!window.confirm('确定清空诊断日志吗？')) return; void withBusy('clear-logs', async () => { await api('/logs?confirm=clear', { method: 'DELETE' }); notify('日志已清空'); await loadLogs(true); }, () => loadLogs(true)); };
  const importConfig = (file) => withBusy('import', async () => { let config; try { config = JSON.parse(await file.text()); } catch { throw new Error('配置文件不是有效的 JSON'); } const result = await api('/import', { method: 'POST', body: { config, replace: false } }); settingsDirtyRef.current = false; setSettingsDirty(false); notify(`已导入 ${result.imported} 条规则，默认保持停用`); await Promise.all([loadCore(true), loadSettings(true)]); }, () => Promise.all([loadCore(true), loadSettings(true)]));
  const diagnostics = () => withBusy('diagnostics', async () => { const data = await api('/diagnostics'); downloadJson(data, `reverse-proxy-diagnostics-${new Date().toISOString().replace(/[:.]/g, '-')}.json`); notify('诊断包已生成'); });

  const routeResources = {
    rules: ['status', 'rules', 'certificates'],
    certificates: ['status', 'certificates', 'rules'],
    logs: ['status', 'logs'],
    settings: ['status', 'settings', 'network'],
    about: ['status'],
  }[route];
  const primaryKey = { rules: 'rules', certificates: 'certificates', logs: 'logs', settings: 'settings', about: 'status' }[route];
  const primaryResource = resources[primaryKey];
  const resourceLabels = { status: '服务状态', rules: '规则', certificates: '证书', logs: '日志', settings: '设置', network: '网络信息' };
  const resourceErrors = routeResources.filter((key) => resources[key].error).map((key) => `${resourceLabels[key]}：${resources[key].error}`);
  const firstLoadPending = primaryResource.loading && !primaryResource.hasData;
  const firstLoadFailed = Boolean(primaryResource.error && !primaryResource.hasData);
  const pageLoading = loading || primaryResource.loading;
  const serviceState = resources.status.loading && !resources.status.hasData ? 'loading' : resources.status.hasData && status?.ok ? 'healthy' : 'error';

  let page = null;
  if (route === 'rules') page = <RulesPage status={status} rules={rules} runtime={runtime} busy={busy} onCreate={() => setRuleDialog({ open: true, rule: null })} onEdit={(rule) => setRuleDialog({ open: true, rule })} onToggle={toggleRule} onDuplicate={duplicateRule} onDelete={deleteRule} onTest={testRule} />;
  if (route === 'certificates') page = <CertificatesPage certificates={certificates} systemSource={certificateSources.system} rules={rules} rulesAvailable={resources.rules.hasData} systemReloading={busy.has('reload-system-certificates')} onCreate={() => setCertificateOpen(true)} onDelete={deleteCertificate} onReloadSystem={() => void reloadSystemCertificates()} />;
  if (route === 'logs') page = <LogsPage logs={logs} onRefresh={() => void loadLogs()} onClear={clearLogs} />;
  if (route === 'settings') page = <SettingsPage settings={settings} network={network} status={status} statusState={serviceState} networkAvailable={resources.network.hasData} saving={busy.has('settings')} importing={busy.has('import')} onDirtyChange={setSettingsDirty} onSave={(next) => withBusy('settings', async () => { const result = await api('/settings', { method: 'PUT', body: next }); setSettings(result.settings || next); setResources((current) => ({ ...current, settings: { ...current.settings, error: '', hasData: true, lastSuccessAt: Date.now() } })); notify('设置已保存'); }, () => loadSettings(true))} onImport={importConfig} onDiagnostics={diagnostics} />;
  if (route === 'about') page = <AboutPage version={status?.version} />;

  return (
    <div className="app-shell">
      <button type="button" className="skip-link" onClick={() => mainRef.current?.focus()}>跳到主要内容</button>
      <Sidebar route={route} onNavigate={navigate} serviceState={serviceState} version={status?.version} />
      <main className="main-canvas" id="main" ref={mainRef} tabIndex="-1">
        {route !== 'rules' ? <PageHeader route={route} serviceState={serviceState} loading={pageLoading} onRefresh={() => void refreshCurrent()} /> : null}
        {firstLoadPending ? <div className="loading-screen" role="status"><i className="bi bi-arrow-repeat" aria-hidden="true" /><span>正在读取${resourceLabels[primaryKey]}…</span></div> : firstLoadFailed ? <ResourceUnavailable message={primaryResource.error} onRetry={() => void refreshCurrent()} /> : <><DataNotice messages={resourceErrors} onRetry={() => void refreshCurrent()} />{page}</>}
      </main>
      <Toast toast={toast} />
      <RuleDialog open={ruleDialog.open} rule={ruleDialog.rule} certificates={certificates} certificatesAvailable={resources.certificates.hasData} saving={busy.has('save-rule')} onClose={() => setRuleDialog({ open: false, rule: null })} onSave={saveRule} />
      <CertificateDialog open={certificateOpen} saving={busy.has('save-certificate')} onClose={() => setCertificateOpen(false)} onInspect={inspectCertificates} onSave={saveCertificate} />
    </div>
  );
}
