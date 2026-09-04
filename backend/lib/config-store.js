import { randomUUID } from 'node:crypto';
import fs from 'node:fs';
import { validateHeaderName, validateHeaderValue } from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { sanitizeCertificate } from './system-certificate-store.js';

export const SOURCE_PROTOCOLS = new Set(['http', 'ws', 'https', 'wss', 'tcp', 'udp']);
export const TARGET_PROTOCOLS = new Set(['http', 'ws', 'https', 'wss', 'tcp', 'udp']);
export const PROTOCOLS = new Set([...SOURCE_PROTOCOLS, 'tcp+udp']);

const now = () => new Date().toISOString();
const text = (value, fallback = '') => String(value ?? fallback).trim();
const bool = (value, fallback = false) => {
  if (value === undefined) return fallback;
  if (typeof value === 'string') {
    if (/^(false|0|no|off)$/i.test(value.trim())) return false;
    if (/^(true|1|yes|on)$/i.test(value.trim())) return true;
  }
  return Boolean(value);
};
const integer = (value, fallback, min, max) => {
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? Math.max(min, Math.min(max, parsed)) : fallback;
};

export function list(value) {
  if (Array.isArray(value)) return [...new Set(value.map((entry) => text(entry)).filter(Boolean))];
  return [...new Set(text(value).split(/[\n,]/).map((entry) => entry.trim()).filter(Boolean))];
}

export function parseHeaders(value) {
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return Object.fromEntries(Object.entries(value).map(([key, item]) => [text(key), text(item)]).filter(([key]) => key));
  }
  const result = {};
  for (const line of list(value)) {
    const index = line.indexOf(':');
    if (index > 0) result[line.slice(0, index).trim()] = line.slice(index + 1).trim();
  }
  return result;
}

function inputError(message) {
  const error = new Error(message);
  error.status = 400;
  error.details = [message];
  throw error;
}

function normalizedProtocols(value, fallback = ['http'], { strict = false } = {}) {
  const values = list(value);
  if (strict && !values.length) inputError('请至少选择一种来源协议');
  const unsupported = values.filter((protocol) => protocol !== 'tcp+udp' && !SOURCE_PROTOCOLS.has(protocol));
  if (strict && unsupported.length) inputError(`来源协议不受支持：${unsupported.join(', ')}`);
  const normalized = [];
  for (const protocol of values) {
    if (protocol === 'tcp+udp') normalized.push('tcp', 'udp');
    else if (SOURCE_PROTOCOLS.has(protocol)) normalized.push(protocol);
  }
  return [...new Set(normalized.length ? normalized : fallback)];
}

function normalizedTargetProtocols(input, sourceProtocols) {
  if (input.targetProtocols !== undefined) {
    const values = list(input.targetProtocols);
    if (!values.length) inputError('请至少选择一种目标协议');
    const unsupported = values.filter((protocol) => !TARGET_PROTOCOLS.has(protocol));
    if (unsupported.length) inputError(`目标协议不受支持：${unsupported.join(', ')}`);
    return [...new Set(values)];
  }
  if (input.targetProtocol !== undefined && !TARGET_PROTOCOLS.has(input.targetProtocol)) inputError(`目标协议不受支持：${input.targetProtocol}`);
  if (input.protocol === 'tcp+udp') return ['tcp', 'udp'];
  const legacy = TARGET_PROTOCOLS.has(input.targetProtocol) ? input.targetProtocol : null;
  if (legacy) return [legacy];
  return [...new Set(sourceProtocols.map((protocol) => protocol === 'ws' ? 'ws' : protocol === 'wss' ? 'wss' : protocol))];
}

export function sourceGroups(protocols = []) {
  const selected = new Set(normalizedProtocols(protocols));
  const groups = [];
  if (selected.has('http') || selected.has('ws')) groups.push('http');
  if (selected.has('https') || selected.has('wss')) groups.push('https');
  if (selected.has('tcp')) groups.push('tcp');
  if (selected.has('udp')) groups.push('udp');
  return groups;
}

export function targetProtocolFor(sourceProtocol, targetProtocols = []) {
  const selected = new Set(list(targetProtocols));
  if (sourceProtocol === 'http' || sourceProtocol === 'https') {
    if (selected.has('https') || selected.has('wss')) return 'https';
    if (selected.has('http') || selected.has('ws')) return 'http';
    return null;
  }
  return selected.has(sourceProtocol) ? sourceProtocol : null;
}

export function expandPortRange(start, end = start) {
  const first = integer(start, 1, 1, 65535);
  const last = integer(end, first, first, 65535);
  return Array.from({ length: last - first + 1 }, (_, index) => first + index);
}

function portSpecError(message) {
  inputError(message);
}

export function parsePortSpec(value) {
  const source = Array.isArray(value) ? value.join(',') : text(value);
  const normalized = source.replace(/\s*[-–—~～]\s*/g, '-');
  const tokens = normalized.split(/[,，;；\s]+/).map((entry) => entry.trim()).filter(Boolean);
  if (!tokens.length) portSpecError('请输入至少一个端口');
  const ports = [];
  const seen = new Set();
  const add = (port) => {
    if (!Number.isInteger(port) || port < 1 || port > 65535) portSpecError(`端口 ${port} 超出 1–65535`);
    if (!seen.has(port)) { seen.add(port); ports.push(port); }
    if (ports.length > 256) portSpecError('单条规则最多设置 256 个端口');
  };
  for (const token of tokens) {
    if (/^\d+$/.test(token)) { add(Number(token)); continue; }
    const range = token.match(/^(\d+)-(\d+)$/);
    if (!range) portSpecError(`端口格式“${token}”无效`);
    const start = Number(range[1]);
    const end = Number(range[2]);
    if (start > end) portSpecError(`端口范围“${token}”的结束端口不能小于起始端口`);
    if (start < 1 || end > 65535) portSpecError(`端口范围“${token}”超出 1–65535`);
    for (let port = start; port <= end; port += 1) add(port);
  }
  return ports;
}

export function listenPortsFor(rule = {}) {
  if (Array.isArray(rule.listenPorts) && rule.listenPorts.length) return [...rule.listenPorts];
  return expandPortRange(rule.listenPortStart ?? rule.listenPort, rule.listenPortEnd ?? rule.listenPort);
}

export function targetPortsFor(rule = {}) {
  if (Array.isArray(rule.targetPorts) && rule.targetPorts.length) return [...rule.targetPorts];
  return expandPortRange(rule.targetPortStart ?? rule.targetPort, rule.targetPortEnd ?? rule.targetPort);
}

const legacyPortRangeEnd = (ports) => ports.every((port, index) => index === 0 || port === ports[index - 1] + 1) ? ports.at(-1) : ports[0];

export function targetPortFor(rule, listenPort) {
  const targets = targetPortsFor(rule);
  if (targets.length === 1) return targets[0];
  const index = listenPortsFor(rule).indexOf(listenPort);
  return index >= 0 ? targets[index] : targets[0];
}

export function normalizeRule(input = {}, existing = null) {
  const createdAt = existing?.createdAt || input.createdAt || now();
  const hasExplicitSourceProtocols = input.protocols !== undefined || input.protocol !== undefined;
  const protocols = normalizedProtocols(input.protocols ?? input.protocol, ['http'], { strict: hasExplicitSourceProtocols });
  const targetProtocols = normalizedTargetProtocols(input, protocols);
  const legacyListenStart = integer(input.listenPortStart ?? input.listenPort, 8080, 1, 65535);
  const legacyListenEnd = integer(input.listenPortEnd, legacyListenStart, legacyListenStart, 65535);
  const legacyTargetStart = integer(input.targetPortStart ?? input.targetPort, 80, 1, 65535);
  const legacyTargetEnd = integer(input.targetPortEnd, legacyTargetStart, legacyTargetStart, 65535);
  const listenPorts = input.listenPorts !== undefined || input.listenPortSpec !== undefined
    ? parsePortSpec(input.listenPorts ?? input.listenPortSpec)
    : expandPortRange(legacyListenStart, legacyListenEnd);
  const targetPorts = input.targetPorts !== undefined || input.targetPortSpec !== undefined
    ? parsePortSpec(input.targetPorts ?? input.targetPortSpec)
    : expandPortRange(legacyTargetStart, legacyTargetEnd);
  const listenPortStart = listenPorts[0];
  const listenPortEnd = legacyPortRangeEnd(listenPorts);
  const targetPortStart = targetPorts[0];
  const targetPortEnd = legacyPortRangeEnd(targetPorts);
  const protocol = protocols.length === 2 && protocols.includes('tcp') && protocols.includes('udp') ? 'tcp+udp' : protocols[0];
  const targetProtocol = targetProtocols[0];
  return {
    id: existing?.id || text(input.id) || randomUUID(),
    name: text(input.name, '未命名规则'),
    protocol,
    protocols,
    listenHost: text(input.listenHost, '0.0.0.0'),
    listenPort: listenPortStart,
    listenPortStart,
    listenPortEnd,
    listenPorts,
    domains: list(input.domains).map((domain) => domain.toLowerCase()),
    targetProtocol,
    targetProtocols,
    targetHost: text(input.targetHost, '127.0.0.1'),
    targetPort: targetPortStart,
    targetPortStart,
    targetPortEnd,
    targetPorts,
    enabled: bool(input.enabled, true),
    timeoutMs: integer(input.timeoutMs, 30000, 1000, 300000),
    uploadLimitMb: integer(input.uploadLimitMb, 50, 0, 10240),
    preserveHost: bool(input.preserveHost, false),
    hsts: bool(input.hsts, false),
    forceHttps: bool(input.forceHttps, false),
    rejectUnauthorized: bool(input.rejectUnauthorized, true),
    customHeaders: parseHeaders(input.customHeaders),
    allowIps: list(input.allowIps),
    blockIps: list(input.blockIps),
    realIp: {
      enabled: bool(input.realIp?.enabled, true),
      header: text(input.realIp?.header, 'X-Forwarded-For'),
    },
    tls: { certId: text(input.tls?.certId) },
    createdAt,
    updatedAt: now(),
  };
}

function normalizedListenHost(value) {
  const host = text(value).toLowerCase().replace(/^\[|\]$/g, '');
  if (host === '0:0:0:0:0:0:0:0') return '::';
  return host;
}

function listenHostsOverlap(left, right) {
  const a = normalizedListenHost(left);
  const b = normalizedListenHost(right);
  if (a === b) return true;
  if (a === '::' || b === '::') return true;
  const aliases = new Set(['localhost', 'ip6-localhost']);
  if (aliases.has(a) && (aliases.has(b) || b === '127.0.0.1' || b === '::1')) return true;
  if (aliases.has(b) && (a === '127.0.0.1' || a === '::1')) return true;
  if (a === '0.0.0.0') return net.isIP(b) !== 6;
  if (b === '0.0.0.0') return net.isIP(a) !== 6;
  return false;
}

function validateHeaders(rule, errors) {
  for (const [name, value] of Object.entries(rule.customHeaders || {})) {
    try {
      validateHeaderName(name);
      validateHeaderValue(name, value);
    } catch {
      errors.push(`自定义请求头“${name || '(空)'}”无效`);
    }
  }
  if (rule.realIp?.enabled) {
    if (!rule.realIp.header) errors.push('请填写真实 IP 请求头名称');
    else {
      try { validateHeaderName(rule.realIp.header); }
      catch { errors.push(`真实 IP 请求头“${rule.realIp.header}”无效`); }
    }
  }
}

function validateIpEntries(entries, label, errors) {
  for (const entry of entries || []) {
    const parts = String(entry).split('/');
    const address = parts[0];
    const family = net.isIP(address);
    const prefix = parts[1];
    const maxPrefix = family === 6 ? 128 : 32;
    if (!family || parts.length > 2 || (prefix !== undefined && (!/^\d+$/.test(prefix) || Number(prefix) > maxPrefix))) {
      errors.push(`${label}中的 IP 或 CIDR“${entry}”无效`);
    }
  }
}

export function transportSet(ruleOrProtocols) {
  const protocols = Array.isArray(ruleOrProtocols) ? ruleOrProtocols : ruleOrProtocols?.protocols ?? [ruleOrProtocols?.protocol].filter(Boolean);
  return new Set(sourceGroups(protocols).map((protocol) => protocol === 'udp' ? 'udp' : 'tcp'));
}

export function validateRule(rule, rules = [], { certificateIds = null, allowMissingCertificate = false } = {}) {
  const errors = [];
  if (!rule.name) errors.push('请输入规则名称');
  if (!rule.protocols.length || rule.protocols.some((protocol) => !SOURCE_PROTOCOLS.has(protocol))) errors.push('来源协议不受支持');
  if (!rule.targetProtocols.length || rule.targetProtocols.some((protocol) => !TARGET_PROTOCOLS.has(protocol))) errors.push('目标协议不受支持');
  if (!rule.listenHost) errors.push('请输入监听地址');
  if (!rule.targetHost) errors.push('请输入目标主机');
  const needsCertificate = rule.protocols.some((protocol) => protocol === 'https' || protocol === 'wss');
  if (needsCertificate && !rule.tls.certId && !(allowMissingCertificate && !rule.enabled)) errors.push('HTTPS / WSS 入口需要选择证书');
  if (needsCertificate && rule.tls.certId && certificateIds && !certificateIds.has(rule.tls.certId) && !(allowMissingCertificate && !rule.enabled)) errors.push('选择的 HTTPS 证书不存在或当前不可用');
  validateHeaders(rule, errors);
  validateIpEntries(rule.allowIps, '白名单', errors);
  validateIpEntries(rule.blockIps, '黑名单', errors);
  const tcpGroups = sourceGroups(rule.protocols).filter((protocol) => protocol !== 'udp');
  if (tcpGroups.length > 1) errors.push('同一组监听端口只能选择一组 TCP 类入口：HTTP/WS、HTTPS/WSS 或 TCP');
  const groups = sourceGroups(rule.protocols);
  const targetTcpModes = [rule.targetProtocols.some((protocol) => protocol === 'http' || protocol === 'ws'), rule.targetProtocols.some((protocol) => protocol === 'https' || protocol === 'wss'), rule.targetProtocols.includes('tcp')].filter(Boolean).length;
  if (targetTcpModes > 1) errors.push('同一入口只能选择一组 Web 或 TCP 目标协议');
  if (rule.targetProtocols.includes('tcp') && !groups.includes('tcp') || rule.targetProtocols.includes('udp') && !groups.includes('udp') || rule.targetProtocols.some((protocol) => ['http', 'ws', 'https', 'wss'].includes(protocol)) && !groups.some((protocol) => protocol === 'http' || protocol === 'https')) errors.push('目标协议需要与来源协议类型对应');
  for (const sourceProtocol of groups) {
    if (!targetProtocolFor(sourceProtocol, rule.targetProtocols)) errors.push(`${sourceProtocol.toUpperCase()} 入口缺少兼容的目标协议`);
  }
  const listenPorts = listenPortsFor(rule);
  const targetPorts = targetPortsFor(rule);
  const listenCount = listenPorts.length;
  const targetCount = targetPorts.length;
  if (listenCount > 256) errors.push('单条规则最多监听 256 个端口');
  if (targetCount !== 1 && targetCount !== listenCount) errors.push('目标端口需为单端口，或与来源端口数量一致');
  const transports = transportSet(rule);
  const listenSet = new Set(listenPorts);
  for (const current of rules) {
    if (current.id === rule.id || !current.enabled || !rule.enabled) continue;
    if (!listenHostsOverlap(current.listenHost, rule.listenHost)) continue;
    if (!listenPortsFor(current).some((port) => listenSet.has(port))) continue;
    const overlaps = [...transportSet(current)].some((item) => transports.has(item));
    if (overlaps) errors.push(`监听地址与规则“${current.name}”冲突`);
  }
  if (errors.length) {
    const error = new Error(errors.join('；'));
    error.status = 400;
    error.details = errors;
    throw error;
  }
  return rule;
}

function demoRules() {
  return [
    normalizeRule({ name: '家庭面板', protocol: 'http', listenPort: 8080, domains: ['home.lan'], targetProtocol: 'http', targetHost: '192.168.50.121', targetPort: 80, preserveHost: true }),
    normalizeRule({ name: '安全终端', protocol: 'tcp', listenPort: 8222, targetProtocol: 'tcp', targetHost: '192.168.50.121', targetPort: 22 }),
    normalizeRule({ name: '联机服务', protocol: 'tcp+udp', listenPort: 19191, targetProtocol: 'tcp', targetHost: '192.168.50.121', targetPort: 19191 }),
    normalizeRule({ name: '开发预览', protocol: 'http', listenPort: 4891, domains: ['preview.lan'], targetProtocol: 'http', targetHost: '192.168.50.121', targetPort: 48091, enabled: false }),
  ];
}

export class ConfigStore {
  constructor(dataDir, { demoMode = false, systemCertificates = null } = {}) {
    this.dataDir = dataDir;
    this.file = path.join(dataDir, 'config.json');
    this.certDir = path.join(dataDir, 'certificates');
    this.demoMode = demoMode;
    this.systemCertificates = systemCertificates;
    this.data = null;
  }

  load() {
    fs.mkdirSync(this.certDir, { recursive: true });
    if (fs.existsSync(this.file)) {
      this.data = JSON.parse(fs.readFileSync(this.file, 'utf8'));
    } else {
      this.data = {
        version: 1,
        settings: { healthCheckInterval: 30, logLevel: 'info', startOnBoot: true },
        rules: this.demoMode ? demoRules() : [],
        certificates: [],
      };
      this.save();
    }
    this.data.settings ||= { healthCheckInterval: 30, logLevel: 'info', startOnBoot: true };
    this.data.certificates ||= [];
    let repairedDuplicateIds = false;
    const usedIds = new Set();
    this.data.rules = (this.data.rules || []).map((source) => {
      const rule = normalizeRule(source, source);
      if (usedIds.has(rule.id)) {
        do { rule.id = randomUUID(); } while (usedIds.has(rule.id));
        repairedDuplicateIds = true;
      }
      usedIds.add(rule.id);
      return rule;
    });
    if (repairedDuplicateIds) this.save();
    return this.data;
  }

  save() {
    fs.mkdirSync(this.dataDir, { recursive: true });
    const temporary = `${this.file}.tmp`;
    fs.writeFileSync(temporary, `${JSON.stringify(this.data, null, 2)}\n`, { mode: 0o600 });
    fs.renameSync(temporary, this.file);
  }

  rules() { return this.data.rules.map((rule) => ({ ...rule })); }
  rule(id) { return this.data.rules.find((rule) => rule.id === id) || null; }

  createRule(input) {
    const usedIds = new Set(this.data.rules.map((rule) => rule.id));
    let id = randomUUID();
    while (usedIds.has(id)) id = randomUUID();
    const rule = validateRule(normalizeRule({ ...input, id }), this.data.rules, { certificateIds: this.certificateIds() });
    this.data.rules.unshift(rule);
    this.save();
    return rule;
  }

  updateRule(id, input) {
    const index = this.data.rules.findIndex((rule) => rule.id === id);
    if (index < 0) { const error = new Error('规则不存在'); error.status = 404; throw error; }
    const merged = { ...this.data.rules[index], ...input };
    if (input.listenPorts === undefined && input.listenPortSpec === undefined && ['listenPort', 'listenPortStart', 'listenPortEnd'].some((key) => Object.hasOwn(input, key))) delete merged.listenPorts;
    if (input.targetPorts === undefined && input.targetPortSpec === undefined && ['targetPort', 'targetPortStart', 'targetPortEnd'].some((key) => Object.hasOwn(input, key))) delete merged.targetPorts;
    const rule = normalizeRule(merged, this.data.rules[index]);
    validateRule(rule, this.data.rules, { certificateIds: this.certificateIds(), allowMissingCertificate: !rule.enabled });
    this.data.rules[index] = rule;
    this.save();
    return rule;
  }

  deleteRule(id) {
    const index = this.data.rules.findIndex((rule) => rule.id === id);
    if (index < 0) { const error = new Error('规则不存在'); error.status = 404; throw error; }
    const [removed] = this.data.rules.splice(index, 1);
    this.save();
    return removed;
  }

  duplicateRule(id) {
    const source = this.rule(id);
    if (!source) { const error = new Error('规则不存在'); error.status = 404; throw error; }
    const sourcePorts = listenPortsFor(source);
    const minimum = Math.min(...sourcePorts);
    const width = Math.max(...sourcePorts) - minimum;
    let port = Math.min(65535 - width, Math.max(...sourcePorts) + 1);
    const candidate = () => sourcePorts.map((item) => port + item - minimum);
    const overlaps = () => {
      const ports = new Set(candidate());
      return this.data.rules.some((rule) => listenHostsOverlap(rule.listenHost, source.listenHost) && listenPortsFor(rule).some((item) => ports.has(item)));
    };
    while (overlaps() && port < 65535 - width) port += Math.max(1, width + 1);
    return this.createRule({ ...source, id: undefined, name: `${source.name} 副本`, listenPorts: candidate(), enabled: false });
  }

  settings() { return { ...this.data.settings }; }
  updateSettings(input) {
    this.data.settings = {
      ...this.data.settings,
      healthCheckInterval: integer(input.healthCheckInterval, this.data.settings.healthCheckInterval || 30, 5, 3600),
      logLevel: ['debug', 'info', 'warn', 'error'].includes(input.logLevel) ? input.logLevel : this.data.settings.logLevel || 'info',
      startOnBoot: bool(input.startOnBoot, this.data.settings.startOnBoot),
    };
    this.save();
    return this.settings();
  }

  manualCertificates() { return this.data.certificates.map(sanitizeCertificate); }
  manualCertificateFingerprints() {
    return new Set(this.data.certificates.map((certificate) => certificate.fingerprint).filter(Boolean));
  }
  certificates() {
    // The order is intentional: if callers offer an automatic/default choice,
    // user-imported material wins over the experimental fnOS compatibility source.
    const manual = this.manualCertificates();
    const manualIds = new Set(manual.map((certificate) => certificate.id));
    const system = (this.systemCertificates?.certificates?.() || []).filter((certificate) => !manualIds.has(certificate.id));
    return [...manual, ...system];
  }
  certificateIds() { return new Set(this.certificates().filter((certificate) => certificate.available !== false).map((certificate) => certificate.id)); }
  certificateState(id) {
    const certificate = this.certificates().find((candidate) => candidate.id === id);
    if (!certificate) return { exists: false, available: false, status: 'missing', stale: false, lastError: null };
    return {
      exists: true,
      available: certificate.available !== false,
      status: certificate.status || 'valid',
      stale: Boolean(certificate.stale),
      lastError: certificate.lastError || null,
      source: certificate.source || 'manual',
    };
  }
  certificate(id) {
    return this.data.certificates.find((certificate) => certificate.id === id)
      || this.systemCertificates?.certificate?.(id)
      || null;
  }
  addCertificate(certificate) {
    const manual = { ...certificate, source: 'manual', managed: false };
    this.data.certificates.unshift(manual);
    this.save();
    return manual;
  }
  removeCertificate(id) {
    const index = this.data.certificates.findIndex((certificate) => certificate.id === id);
    if (index < 0) {
      const error = new Error(this.systemCertificates?.certificate?.(id) ? 'fnOS 系统证书由系统管理，不能在此删除' : '证书不存在');
      error.status = this.systemCertificates?.certificate?.(id) ? 409 : 404;
      throw error;
    }
    const [certificate] = this.data.certificates.splice(index, 1);
    this.save();
    return certificate;
  }

  exportConfig() {
    return { version: 1, exportedAt: now(), settings: this.settings(), rules: this.rules(), certificates: this.manualCertificates() };
  }

  importConfig(payload, { replace = false } = {}) {
    const incoming = Array.isArray(payload?.rules) ? payload.rules : [];
    const combined = replace ? [] : this.data.rules.slice();
    const normalized = [];
    const usedIds = new Set(combined.map((rule) => rule.id));
    const certificateIds = this.certificateIds();
    for (const input of incoming) {
      let id = text(input?.id) || randomUUID();
      while (usedIds.has(id)) id = randomUUID();
      const rule = normalizeRule({ ...input, id });
      rule.enabled = false;
      validateRule(rule, combined, { certificateIds, allowMissingCertificate: true });
      combined.push(rule);
      normalized.push(rule);
      usedIds.add(rule.id);
    }
    this.data.rules = combined;
    if (payload?.settings) this.updateSettings(payload.settings);
    this.save();
    return { imported: normalized.length, rules: this.rules() };
  }
}
