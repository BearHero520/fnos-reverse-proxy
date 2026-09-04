import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';

export const DEFAULT_FNOS_CERTIFICATE_CONFIG = '/usr/trim/etc/network_cert_all.conf';

const MAX_CONFIG_BYTES = 4 * 1024 * 1024;
const MAX_CERTIFICATE_BYTES = 4 * 1024 * 1024;
const MAX_PRIVATE_KEY_BYTES = 1024 * 1024;
const MAX_CERTIFICATES = 1024;
const MIN_REFRESH_INTERVAL_MS = 15_000;
const MAX_REFRESH_INTERVAL_MS = 3_600_000;

const isoNow = () => new Date().toISOString();
const cleanText = (value) => String(value ?? '').trim();
const normalizeDomain = (value) => cleanText(value).toLowerCase().replace(/^dns:/i, '').replace(/\.$/, '');
const unique = (values) => [...new Set(values.filter(Boolean))];

function parseBoolean(value) {
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  const normalized = cleanText(value).toLowerCase();
  if (['1', 'true', 'yes', 'on', 'used', 'enabled'].includes(normalized)) return true;
  if (['0', 'false', 'no', 'off', 'unused', 'disabled', ''].includes(normalized)) return false;
  return Boolean(value);
}

function normalizeStringList(value) {
  const source = Array.isArray(value) ? value : cleanText(value).split(/[,，;；\n]/);
  return unique(source.map(normalizeDomain));
}

function normalizeAppFlag(value) {
  if (value === null || value === undefined) return '';
  if (Array.isArray(value)) return value.map((item) => cleanText(item)).filter(Boolean).slice(0, 64);
  if (['string', 'number', 'boolean'].includes(typeof value)) return value;
  return '[unsupported]';
}

function safeDate(value) {
  if (value === null || value === undefined || value === '') return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString();
}

function commonName(x509) {
  const match = cleanText(x509.subject).match(/(?:^|\n)CN=([^\n,]+)/);
  return match?.[1]?.trim() || '';
}

function subjectAltNames(x509) {
  return unique(cleanText(x509.subjectAltName)
    .split(/,\s*/)
    .filter((entry) => /^DNS:/i.test(entry))
    .map(normalizeDomain));
}

function certificateBlocks(buffer) {
  const text = buffer.toString('utf8');
  const matches = [...text.matchAll(/-----BEGIN (?:TRUSTED )?CERTIFICATE-----[\s\S]*?-----END (?:TRUSTED )?CERTIFICATE-----/g)]
    .map((match) => `${match[0].trim()}\n`);
  if (matches.length) return matches;
  const x509 = new X509Certificate(buffer);
  return [`${x509.toString().trim()}\n`];
}

function privateKeyFromBuffer(buffer) {
  try { return createPrivateKey(buffer); } catch {}
  for (const type of ['pkcs8', 'pkcs1', 'sec1']) {
    try { return createPrivateKey({ key: buffer, format: 'der', type }); } catch {}
  }
  throw new Error('私钥格式无法识别');
}

function chainLength(pem) {
  return [...String(pem).matchAll(/-----BEGIN (?:TRUSTED )?CERTIFICATE-----/g)].length || 1;
}

function validityState(validFrom, validTo, timestamp = Date.now()) {
  const begins = Date.parse(validFrom);
  const expires = Date.parse(validTo);
  if (Number.isFinite(begins) && begins > timestamp) return 'not-yet-valid';
  if (Number.isFinite(expires) && expires <= timestamp) return 'expired';
  return 'valid';
}

function entryLabel(entry, index) {
  return normalizeDomain(entry?.domain) || normalizeStringList(entry?.san)[0] || `#${index + 1}`;
}

function normalizedSourcePath(value) {
  const source = cleanText(value);
  return source ? path.normalize(source) : '';
}

function stableId(entry) {
  const configuredDomain = normalizeDomain(entry?.domain);
  const configuredSan = normalizeStringList(entry?.san).sort();
  const certificatePath = normalizedSourcePath(entry?.fullchain || entry?.certificate);
  const privateKeyPath = normalizedSourcePath(entry?.privateKey);
  const identity = [configuredDomain, configuredSan.join('\0'), certificatePath, privateKeyPath].join('\0');
  return `system-${createHash('sha256').update(identity).digest('hex').slice(0, 24)}`;
}

function currentValidity(certificate) {
  const status = validityState(certificate.validFrom, certificate.validTo);
  return { status, available: status === 'valid' };
}

function publicCertificate(certificate) {
  const validity = currentValidity(certificate);
  return {
    id: certificate.id,
    name: certificate.name,
    format: certificate.format,
    source: 'system',
    managed: true,
    deletable: false,
    available: validity.available,
    stale: Boolean(certificate.stale),
    status: validity.status,
    subject: certificate.subject,
    issuer: certificate.issuer,
    validFrom: certificate.validFrom,
    validTo: certificate.validTo,
    fingerprint: certificate.fingerprint,
    serialNumber: certificate.serialNumber,
    subjectAltNames: [...certificate.subjectAltNames],
    domains: [...certificate.domains],
    keyType: certificate.keyType,
    chainLength: certificate.chainLength,
    used: certificate.used,
    appFlag: Array.isArray(certificate.appFlag) ? [...certificate.appFlag] : certificate.appFlag,
    configuredDomain: certificate.configuredDomain,
    configuredSan: [...certificate.configuredSan],
    configuredValidFrom: certificate.configuredValidFrom,
    configuredValidTo: certificate.configuredValidTo,
    lastLoadedAt: certificate.lastLoadedAt,
    lastError: certificate.lastError || null,
  };
}

function snapshotSignature(snapshot) {
  return JSON.stringify([...snapshot.values()]
    .map((certificate) => {
      const { lastLoadedAt, ...stable } = publicCertificate(certificate);
      return stable;
    })
    .sort((left, right) => left.id.localeCompare(right.id)));
}

function publicError(error) {
  return {
    certificate: error.certificate,
    code: error.code || 'INVALID_CERTIFICATE',
    message: error.message,
  };
}

function boundedRefreshInterval(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 60_000;
  return Math.max(MIN_REFRESH_INTERVAL_MS, Math.min(MAX_REFRESH_INTERVAL_MS, Math.round(parsed)));
}

function orderCertificateChain(leaf, remaining) {
  const chain = [];
  let current = leaf.x509;
  const candidates = [...remaining];
  while (candidates.length) {
    const issuerIndex = candidates.findIndex(({ x509 }) => {
      try { return current.checkIssued(x509) && current.verify(x509.publicKey); }
      catch { return false; }
    });
    if (issuerIndex < 0) {
      const error = new Error('证书链包含无关证书或签发关系已断开');
      error.code = 'INVALID_CHAIN';
      throw error;
    }
    const [issuer] = candidates.splice(issuerIndex, 1);
    if (validityState(issuer.x509.validFrom, issuer.x509.validTo) !== 'valid') {
      const error = new Error('证书链中包含已过期或尚未生效的签发证书');
      error.code = 'INVALID_CHAIN_VALIDITY';
      throw error;
    }
    chain.push(issuer);
    current = issuer.x509;
  }
  return chain;
}

/**
 * Compatibility reader for fnOS' undocumented certificate inventory.
 *
 * The source paths and key material deliberately only exist on the private
 * records returned by certificate(). certificates() is built from an explicit
 * allow-list so future config fields cannot accidentally leak through the API.
 */
export class SystemCertificateStore extends EventEmitter {
  constructor({
    configPath = process.env.FNOS_SYSTEM_CERT_CONFIG || DEFAULT_FNOS_CERTIFICATE_CONFIG,
    refreshIntervalMs = Number(process.env.FNOS_SYSTEM_CERT_REFRESH_SECONDS || 60) * 1000,
    logger = null,
  } = {}) {
    super();
    this.configPath = path.resolve(configPath);
    this.refreshIntervalMs = boundedRefreshInterval(refreshIntervalMs);
    this.logger = logger;
    this.snapshot = new Map();
    this.timer = null;
    this.watchedPaths = new Set();
    this.observedSignature = '';
    this.observedValiditySignature = '';
    this.lastLoggedIssueSignature = '';
    this.reloadPromise = null;
    this.currentStatus = {
      source: 'fnOS-internal',
      experimental: true,
      state: 'unavailable',
      available: false,
      usingLastKnownGood: false,
      certificateCount: 0,
      staleCount: 0,
      errorCount: 0,
      lastAttemptAt: null,
      lastSuccessAt: null,
      lastChangedAt: null,
      message: '尚未读取 fnOS 系统证书',
      errors: [],
    };
  }

  async start() {
    await this.reload({ reason: 'startup' });
    clearInterval(this.timer);
    this.timer = setInterval(() => void this.refreshIfChanged(), this.refreshIntervalMs);
    this.timer.unref?.();
    return this.status();
  }

  stop() {
    clearInterval(this.timer);
    this.timer = null;
  }

  status() {
    return {
      ...this.currentStatus,
      errors: this.currentStatus.errors.map((error) => ({ ...error })),
    };
  }

  certificates() {
    return [...this.snapshot.values()].map(publicCertificate);
  }

  certificate(id) {
    return this.snapshot.get(id) || null;
  }

  certificateAvailable(id) {
    const certificate = this.snapshot.get(id);
    return Boolean(certificate && currentValidity(certificate).available);
  }

  ids() {
    return new Set(this.snapshot.keys());
  }

  async fileSignature(files = null) {
    const paths = unique(files ? [...files] : [this.configPath, ...this.watchedPaths]);
    const parts = [];
    for (const file of paths) {
      try {
        const stat = await fs.promises.stat(file);
        parts.push(`${file}\0${stat.mtimeMs}\0${stat.size}`);
      } catch (error) {
        parts.push(`${file}\0${error.code || 'ERROR'}`);
      }
    }
    return createHash('sha256').update(parts.join('\n')).digest('hex');
  }

  validitySignature() {
    return [...this.snapshot.entries()]
      .map(([id, certificate]) => `${id}:${currentValidity(certificate).status}`)
      .sort()
      .join('|');
  }

  async refreshIfChanged() {
    const signature = await this.fileSignature();
    const needsRecovery = this.currentStatus.state === 'degraded' || this.currentStatus.state === 'unavailable';
    if (signature === this.observedSignature && !needsRecovery) {
      const validitySignature = this.validitySignature();
      if (validitySignature !== this.observedValiditySignature) {
        this.observedValiditySignature = validitySignature;
        const changedAt = isoNow();
        this.currentStatus = { ...this.currentStatus, lastChangedAt: changedAt };
        const certificateIds = [...this.snapshot.keys()];
        const result = { changed: true, status: this.status(), certificates: this.certificates(), certificateIds };
        this.emit('changed', { reason: 'validity', status: result.status, certificateIds });
        return result;
      }
      return { changed: false, status: this.status(), certificates: this.certificates() };
    }
    return this.reload({ reason: needsRecovery ? 'recovery' : 'mtime' });
  }

  reload(options = {}) {
    if (this.reloadPromise) return this.reloadPromise;
    this.reloadPromise = this.reloadNow(options).finally(() => { this.reloadPromise = null; });
    return this.reloadPromise;
  }

  async readBoundedFile(file, limit, label) {
    let stat;
    try { stat = await fs.promises.stat(file); }
    catch (error) {
      const wrapped = new Error(`${label}不可读取${error.code ? `（${error.code}）` : ''}`);
      wrapped.code = error.code || 'READ_FAILED';
      throw wrapped;
    }
    if (!stat.isFile()) {
      const error = new Error(`${label}不是普通文件`);
      error.code = 'NOT_A_FILE';
      throw error;
    }
    if (stat.size > limit) {
      const error = new Error(`${label}超过安全大小限制`);
      error.code = 'FILE_TOO_LARGE';
      throw error;
    }
    try { return await fs.promises.readFile(file); }
    catch (error) {
      const wrapped = new Error(`${label}不可读取${error.code ? `（${error.code}）` : ''}`);
      wrapped.code = error.code || 'READ_FAILED';
      throw wrapped;
    }
  }

  async loadEntry(entry, index, id) {
    const label = entryLabel(entry, index);
    const certPath = cleanText(entry.fullchain) || cleanText(entry.certificate);
    const keyPath = cleanText(entry.privateKey);
    if (!certPath || !keyPath) {
      const error = new Error('证书链或私钥字段缺失');
      error.code = 'MISSING_PATH';
      throw error;
    }
    if (!path.isAbsolute(certPath) || !path.isAbsolute(keyPath)) {
      const error = new Error('证书链和私钥必须使用绝对路径');
      error.code = 'INVALID_PATH';
      throw error;
    }
    const [certificateBuffer, privateKeyBuffer] = await Promise.all([
      this.readBoundedFile(certPath, MAX_CERTIFICATE_BYTES, '证书文件'),
      this.readBoundedFile(keyPath, MAX_PRIVATE_KEY_BYTES, '私钥文件'),
    ]);
    const key = privateKeyFromBuffer(privateKeyBuffer);
    const blocks = certificateBlocks(certificateBuffer);
    const parsed = blocks.map((pem) => ({ pem, x509: new X509Certificate(pem) }));
    const leafIndex = parsed.findIndex(({ x509 }) => x509.checkPrivateKey(key));
    if (leafIndex < 0) {
      const error = new Error('证书与私钥不匹配');
      error.code = 'KEY_MISMATCH';
      throw error;
    }
    const [leaf] = parsed.splice(leafIndex, 1);
    const chain = orderCertificateChain(leaf, parsed);
    const certificatePem = `${[leaf.pem, ...chain.map((item) => item.pem)].join('\n').trim()}\n`;
    const privateKeyPem = `${key.export({ format: 'pem', type: 'pkcs8' }).toString().trim()}\n`;
    tls.createSecureContext({ cert: certificatePem, key: privateKeyPem });
    const certificateDomains = unique([commonName(leaf.x509), ...subjectAltNames(leaf.x509)].map(normalizeDomain));
    const configuredDomain = normalizeDomain(entry.domain);
    const configuredSan = normalizeStringList(entry.san);
    const loadedAt = isoNow();
    return {
      id,
      name: certificateDomains[0] || configuredDomain || label,
      format: 'fnOS 系统证书',
      source: 'system',
      managed: true,
      certificatePem,
      privateKeyPem,
      subject: leaf.x509.subject,
      issuer: leaf.x509.issuer,
      validFrom: new Date(leaf.x509.validFrom).toISOString(),
      validTo: new Date(leaf.x509.validTo).toISOString(),
      fingerprint: leaf.x509.fingerprint256,
      serialNumber: leaf.x509.serialNumber,
      subjectAltNames: subjectAltNames(leaf.x509),
      domains: certificateDomains,
      keyType: key.asymmetricKeyType || 'unknown',
      chainLength: chainLength(certificatePem),
      status: validityState(leaf.x509.validFrom, leaf.x509.validTo),
      configuredDomain,
      configuredSan,
      configuredValidFrom: safeDate(entry.validFrom),
      configuredValidTo: safeDate(entry.validTo),
      used: parseBoolean(entry.used),
      appFlag: normalizeAppFlag(entry.appFlag),
      stale: false,
      lastError: null,
      lastLoadedAt: loadedAt,
      _sourcePaths: [certPath, keyPath],
    };
  }

  failLoad(error, attemptedAt, reason = 'error') {
    const before = snapshotSignature(this.snapshot);
    const hasSnapshot = this.snapshot.size > 0;
    if (hasSnapshot) {
      // Keep the working key material intact, but make the fallback explicit to
      // every API consumer instead of exposing it only through aggregate status.
      this.snapshot = new Map([...this.snapshot.entries()].map(([id, certificate]) => [id, {
        ...certificate,
        stale: true,
        lastError: error.message,
      }]));
    }
    this.currentStatus = {
      ...this.currentStatus,
      state: hasSnapshot ? 'degraded' : 'unavailable',
      available: hasSnapshot,
      usingLastKnownGood: hasSnapshot,
      certificateCount: this.snapshot.size,
      staleCount: hasSnapshot ? this.snapshot.size : 0,
      errorCount: 1,
      lastAttemptAt: attemptedAt,
      message: hasSnapshot ? `${error.message}；继续使用上一份可用证书` : error.message,
      errors: [publicError({ certificate: '系统配置', code: error.code, message: error.message })],
    };
    const validitySignature = this.validitySignature();
    const changed = before !== snapshotSignature(this.snapshot) || validitySignature !== this.observedValiditySignature;
    this.observedValiditySignature = validitySignature;
    const certificateIds = [...this.snapshot.keys()];
    if (changed) this.emit('changed', { reason, status: this.status(), certificateIds });
    const issueSignature = JSON.stringify({
      state: this.currentStatus.state,
      code: error.code || 'INVALID_CONFIG',
      message: error.message,
      usingLastKnownGood: hasSnapshot,
    });
    const shouldLog = reason === 'startup' || reason === 'manual' || issueSignature !== this.lastLoggedIssueSignature;
    this.lastLoggedIssueSignature = issueSignature;
    if (shouldLog) this.logger?.warn?.('fnOS 系统证书刷新失败', { code: error.code || 'INVALID_CONFIG', usingLastKnownGood: hasSnapshot });
    return { changed, status: this.status(), certificates: this.certificates(), certificateIds };
  }

  async reloadNow({ reason = 'manual', attempt = 0 } = {}) {
    const attemptedAt = isoNow();
    this.currentStatus = { ...this.currentStatus, lastAttemptAt: attemptedAt };
    const configSignatureBefore = await this.fileSignature([this.configPath]);
    let configBuffer;
    try {
      configBuffer = await this.readBoundedFile(this.configPath, MAX_CONFIG_BYTES, '系统证书配置');
    } catch (error) {
      this.observedSignature = await this.fileSignature();
      return this.failLoad(error, attemptedAt, reason);
    }

    let entries;
    try {
      entries = JSON.parse(configBuffer.toString('utf8'));
      if (!Array.isArray(entries)) throw new Error('顶层内容必须是数组');
      if (entries.length > MAX_CERTIFICATES) throw new Error(`证书条目超过 ${MAX_CERTIFICATES} 条限制`);
    } catch (cause) {
      const error = new Error(`系统证书配置无法解析：${cause.message}`);
      error.code = 'INVALID_JSON';
      this.observedSignature = await this.fileSignature();
      return this.failLoad(error, attemptedAt, reason);
    }

    const next = new Map();
    const errors = [];
    const watchedPaths = new Set();
    for (const entry of entries) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) continue;
      const certPath = cleanText(entry.fullchain) || cleanText(entry.certificate);
      const keyPath = cleanText(entry.privateKey);
      if (certPath) watchedPaths.add(certPath);
      if (keyPath) watchedPaths.add(keyPath);
    }
    const sourcePaths = [this.configPath, ...watchedPaths];
    const sourceSignatureBefore = await this.fileSignature(sourcePaths);
    const configSignatureAfter = await this.fileSignature([this.configPath]);
    if (configSignatureAfter !== configSignatureBefore) {
      if (attempt < 2) return this.reloadNow({ reason, attempt: attempt + 1 });
      const error = new Error('系统证书配置在读取过程中持续变化，请稍后重试');
      error.code = 'SOURCE_CHANGED_DURING_READ';
      this.watchedPaths = watchedPaths;
      this.observedSignature = sourceSignatureBefore;
      return this.failLoad(error, attemptedAt, reason);
    }

    for (const [index, entry] of entries.entries()) {
      if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
        errors.push({ certificate: `#${index + 1}`, code: 'INVALID_ENTRY', message: '证书条目格式无效' });
        continue;
      }
      const id = stableId(entry);
      if (next.has(id)) {
        errors.push({ certificate: entryLabel(entry, index), code: 'DUPLICATE_ENTRY', message: '系统证书配置包含重复条目' });
        continue;
      }
      try {
        next.set(id, await this.loadEntry(entry, index, id));
      } catch (cause) {
        const label = entryLabel(entry, index);
        const message = cleanText(cause.message) || '证书无法加载';
        errors.push({ certificate: label, code: cause.code || 'INVALID_CERTIFICATE', message });
        const previous = this.snapshot.get(id);
        if (previous) next.set(id, { ...previous, stale: true, lastError: message });
      }
    }

    const sourceSignatureAfter = await this.fileSignature(sourcePaths);
    if (sourceSignatureAfter !== sourceSignatureBefore) {
      if (attempt < 2) return this.reloadNow({ reason, attempt: attempt + 1 });
      const error = new Error('系统证书文件在读取过程中持续变化，请稍后重试');
      error.code = 'SOURCE_CHANGED_DURING_READ';
      this.watchedPaths = watchedPaths;
      this.observedSignature = sourceSignatureAfter;
      return this.failLoad(error, attemptedAt, reason);
    }

    this.watchedPaths = watchedPaths;
    const previousIds = [...this.snapshot.keys()];
    const before = snapshotSignature(this.snapshot);
    const nextPublic = snapshotSignature(next);
    const changed = before !== nextPublic;
    this.snapshot = next;
    const succeededAt = isoNow();
    const staleCount = [...next.values()].filter((certificate) => certificate.stale).length;
    const state = errors.length ? 'degraded' : 'ready';
    this.currentStatus = {
      ...this.currentStatus,
      state,
      available: next.size > 0 || entries.length === 0,
      usingLastKnownGood: staleCount > 0,
      certificateCount: next.size,
      staleCount,
      errorCount: errors.length,
      lastAttemptAt: attemptedAt,
      lastSuccessAt: errors.length ? this.currentStatus.lastSuccessAt : succeededAt,
      lastChangedAt: changed ? succeededAt : this.currentStatus.lastChangedAt,
      message: errors.length
        ? `已读取 ${next.size} 张系统证书，${errors.length} 张异常${staleCount ? `，其中 ${staleCount} 张继续使用上一版本` : ''}`
        : `已读取 ${next.size} 张 fnOS 系统证书`,
      errors: errors.map(publicError),
    };
    this.observedSignature = sourceSignatureAfter;
    this.observedValiditySignature = this.validitySignature();
    const certificateIds = [...new Set([...previousIds, ...next.keys()])];
    if (changed) this.emit('changed', { reason, status: this.status(), certificateIds });
    if (errors.length) {
      const publicErrors = errors.map(publicError);
      const issueSignature = JSON.stringify({ state, loaded: next.size, stale: staleCount, errors: publicErrors });
      const shouldLog = reason === 'startup' || reason === 'manual' || issueSignature !== this.lastLoggedIssueSignature;
      this.lastLoggedIssueSignature = issueSignature;
      if (shouldLog) this.logger?.warn?.('fnOS 系统证书部分加载失败', {
        loaded: next.size,
        errors: publicErrors,
        stale: staleCount,
      });
    } else {
      this.lastLoggedIssueSignature = '';
      this.logger?.info?.('fnOS 系统证书已刷新', { loaded: next.size, reason });
    }
    return { changed, status: this.status(), certificates: this.certificates(), certificateIds };
  }
}

export function sanitizeCertificate(certificate) {
  if (!certificate) return null;
  if (certificate.source === 'system' || certificate.managed) return publicCertificate(certificate);
  const {
    certificatePem,
    privateKeyPem,
    privateKey,
    certPath,
    keyPath,
    _sourcePaths,
    ...publicData
  } = certificate;
  const validity = certificate.validFrom && certificate.validTo ? currentValidity(certificate) : { status: certificate.status || 'valid', available: certificate.available !== false };
  return { ...publicData, status: validity.status, available: validity.available, source: 'manual', managed: false, deletable: true };
}
