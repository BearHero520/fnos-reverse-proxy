// Privileged, dependency-free adapter. The restricted deployment worker imports this module.
// fnOS's certificate storage is an internal interface: every operation fails closed
// when database, index, PEM, gateway mapping, or live TLS disagree.
import fs from 'node:fs';
import path from 'node:path';
import tls from 'node:tls';
import { spawn } from 'node:child_process';
import { createHash, createPrivateKey, randomUUID, X509Certificate } from 'node:crypto';

export const DEPLOY_ERRORS = {
  UNAVAILABLE: '内置部署服务未连接，请重启主应用后重试',
  INCOMPATIBLE: '系统证书结构或权限不兼容，未执行部署',
  PROTECTED: '仅支持已手动导入的证书，不修改 fnOS 自带证书',
  INVALID: '证书、私钥、证书链或有效期校验未通过',
  UNTRUSTED: '新证书链不受公共 CA 信任，请使用正式签发的完整证书链',
  DOMAIN: '新旧证书域名必须完全一致，验证域名必须包含在证书中',
  CONFLICT: '系统证书或配置已变化，请重新预检',
  TLS: '本机 HTTPS 验证未通过，请核对系统 HTTPS 端口和绑定域名',
  BUSY: '已有部署任务正在运行，请稍后重试',
  ROLLED_BACK: '部署未成功，已恢复原证书并验证 HTTPS',
  RECOVERY: '部署恢复未完成，已停止后续写入；请在 fnOS 检查证书与 HTTPS 服务',
};
export function deployError(code) { return Object.assign(new Error(DEPLOY_ERRORS[code] || DEPLOY_ERRORS.INCOMPATIBLE), { code, status: code === 'BUSY' || code === 'CONFLICT' ? 409 : 400 }); }
export const DEPLOY_STAGES = { metadata: '更新证书记录', files: '写入证书文件', restart: '重载系统 HTTPS', verify: '验证新证书 HTTPS', consistency: '核对部署结果' };
export function verifyFnosWebUser(config) {
  const users = [...config.matchAll(/^\s*user\s+([^;]+);/gm)].map((match) => match[1].trim().split(/\s+/));
  if (users.length !== 1 || users[0][0] !== 'www-data' || users[0].length > 2 || users[0][1] && users[0][1] !== 'www-data') throw deployError('INCOMPATIBLE');
}
const hash = (data) => createHash('sha256').update(data).digest('hex');
const canonical = (value) => Array.isArray(value) ? value.map(canonical) : value && typeof value === 'object' ? Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonical(value[key])])) : value;
const equal = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));
const cleanDomains = (values) => [...new Set(values.map((v) => String(v).trim().toLowerCase().replace(/\.$/, '')))].sort();
const domainPattern = /^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
export function inspectDeploymentCertificate(certificatePem, privateKeyPem, { allowExpired = false } = {}) {
  try {
    if (typeof certificatePem !== 'string' || certificatePem.length > 512 * 1024 || typeof privateKeyPem !== 'string' || privateKeyPem.length > 32 * 1024) throw 0;
    const blocks = certificatePem.match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) || [];
    if (!blocks.length || blocks.length > 12 || certificatePem.replace(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g, '').trim()) throw 0;
    const chain = blocks.map((pem) => new X509Certificate(pem));
    const leaf = chain[0];
    if (leaf.ca || !leaf.checkPrivateKey(createPrivateKey(privateKeyPem))) throw 0;
    for (let i = 0; i < chain.length; i++) {
      if (!allowExpired && (Date.parse(chain[i].validFrom) > Date.now() || Date.parse(chain[i].validTo) <= Date.now())) throw 0;
      if (i && (!chain[i].ca || !chain[i - 1].checkIssued(chain[i]) || !chain[i - 1].verify(chain[i].publicKey))) throw 0;
    }
    // Quoted/escaped SANs and non-DNS SANs are deliberately unsupported here.
    const names = (leaf.subjectAltName || '').split(/,\s*/);
    if (!names.length || names.some((n) => !n.startsWith('DNS:') || !domainPattern.test(n.slice(4).toLowerCase()))) throw 0;
    const domains = cleanDomains(names.map((n) => n.slice(4)));
    const keyType = leaf.publicKey.asymmetricKeyType;
    if (!['rsa', 'ec'].includes(keyType)) throw 0;
    return { leaf, chain, domains, fingerprint: leaf.fingerprint256, validFrom: Date.parse(leaf.validFrom), validTo: Date.parse(leaf.validTo), encryptType: keyType === 'rsa' ? 'RSA' : 'ECDSA', issuedBy: leaf.issuer.match(/(?:^|\n)CN=([^\n]+)/)?.[1] || leaf.issuer, chainPem: `${blocks.join('\n')}\n`, issuerPem: blocks.length > 1 ? `${blocks.slice(1).join('\n')}\n` : '' };
  } catch { throw deployError('INVALID'); }
}
let publicTrustAnchors;
export function assertPublicTrust(parsed) {
  publicTrustAnchors ||= tls.rootCertificates.map((pem) => new X509Certificate(pem));
  const last = parsed.chain.at(-1);
  if (!publicTrustAnchors.some((root) => last.raw.equals(root.raw) || last.checkIssued(root) && last.verify(root.publicKey))) throw deployError('UNTRUSTED');
}

function command(file, args, input = '', timeoutMs = 20000) {
  return new Promise((resolve, reject) => {
    const child = spawn(file, args, { env: { PATH: '/usr/sbin:/usr/bin:/sbin:/bin', LANG: 'C', PGCONNECT_TIMEOUT: '5' }, stdio: ['pipe', 'pipe', 'ignore'] });
    const chunks = []; let size = 0;
    const timer = setTimeout(() => { child.kill('SIGKILL'); reject(deployError('INCOMPATIBLE')); }, timeoutMs);
    child.on('error', () => { clearTimeout(timer); reject(deployError('INCOMPATIBLE')); });
    child.stdout.on('data', (chunk) => { size += chunk.length; if (size > 4 * 1024 * 1024) child.kill('SIGKILL'); else chunks.push(chunk); });
    child.on('close', (code) => { clearTimeout(timer); code === 0 && size <= 4 * 1024 * 1024 ? resolve(Buffer.concat(chunks).toString('utf8').trim()) : reject(deployError('INCOMPATIBLE')); });
    child.stdin.on('error', () => {}); child.stdin.end(input);
  });
}
const sqlJson = (value) => `convert_from(decode('${Buffer.from(JSON.stringify(value)).toString('base64')}','base64'),'UTF8')::jsonb`;
const psql = (sql) => command('/usr/sbin/runuser', ['-u', 'postgres', '--', '/usr/bin/psql', '-d', 'trim_connect', '-XqAt', '-v', 'ON_ERROR_STOP=1'], sql);
export async function compareAndSwapRow(before, after) {
  if (!Number.isSafeInteger(before.id) || before.id <= 0 || before.id !== after.id) throw deployError('INCOMPATIBLE');
  const fields = ['valid_from', 'valid_to', 'encrypt_type', 'issued_by', 'status', 'updated_time'];
  const assignments = fields.map((field) => `${field}=v.${field}`).join(',');
  const result = await psql(`BEGIN; SET LOCAL lock_timeout='3s'; SET LOCAL statement_timeout='8s'; WITH v AS (SELECT * FROM jsonb_populate_record(NULL::public.cert,${sqlJson(after)})), changed AS (UPDATE public.cert c SET ${assignments} FROM v WHERE c.id=${before.id} AND to_jsonb(c)=${sqlJson(before)} RETURNING 1) SELECT CASE WHEN count(*)=1 THEN 1 ELSE (count(*)::text || ' conflict')::integer END FROM changed; COMMIT;`);
  if (result !== '1') throw deployError('CONFLICT');
}
export function probeTls(host, port, fingerprint, requireTrust = false) {
  return new Promise((resolve, reject) => {
    // Certificate pinning is intentional; the peer must be the exact selected cert.
    const socket = tls.connect({ host: '127.0.0.1', port, servername: host, rejectUnauthorized: requireTrust });
    socket.setTimeout(7000, () => socket.destroy(deployError('TLS')));
    socket.once('error', () => reject(deployError('TLS')));
    socket.once('secureConnect', () => {
      const actual = socket.getPeerCertificate().fingerprint256;
      socket.destroy(); actual === fingerprint ? resolve() : reject(deployError('TLS'));
    });
  });
}
const defaultAdapter = {
  keyPermissions: async () => {
    // The vendor nginx binary has initialization side effects even with -T.
    // Preflight must never invoke it: inspect the root-owned config directly.
    const configPath = '/usr/trim/nginx/conf/nginx.conf';
    const metadata = fs.lstatSync(configPath);
    if (!metadata.isFile() || metadata.uid !== 0 || metadata.mode & 0o022 || metadata.size > 2 * 1024 * 1024) throw deployError('INCOMPATIBLE');
    verifyFnosWebUser(fs.readFileSync(configPath, 'utf8'));
    const gid = Number(await command('/usr/bin/id', ['-g', 'www-data']));
    if (!Number.isSafeInteger(gid) || gid <= 0) throw deployError('INCOMPATIBLE');
    return { mode: 0o640, gid };
  },
  detectPorts: async () => {
    const listeners = await command('/usr/bin/ss', ['-H', '-ltnp']);
    return [...new Set(listeners.split('\n').filter((line) => line.includes('"nginx"')).map((line) => Number(line.trim().split(/\s+/)[3]?.match(/:(\d+)$/)?.[1])).filter((port) => port > 0 && port <= 65535))].slice(0, 16);
  },
  rows: async () => JSON.parse(await psql("SELECT coalesce(json_agg(row_to_json(c) ORDER BY c.id),'[]'::json)::text FROM public.cert c;")),
  cas: compareAndSwapRow, probe: probeTls,
  validateTrust: assertPublicTrust,
  restart: async () => { for (const service of ['network_service.service', 'trim_nginx.service']) { await command('/usr/bin/systemctl', ['restart', service], '', 30000); await command('/usr/bin/systemctl', ['is-active', '--quiet', service]); } },
};

export class FnosDeploymentEngine {
  constructor({ adapter = defaultAdapter, certRoot = '/usr/trim/var/trim_connect/ssls', indexPath = '/usr/trim/etc/network_cert_all.conf', gatewayPath = '/usr/trim/etc/network_gateway_cert.conf', stateDir = '/var/lib/reverse-proxy-cert-deployer', secure = true } = {}) {
    Object.assign(this, { adapter, certRoot, indexPath, gatewayPath, stateDir, secure });
    this.busy = false; this.recoveryFailed = false;
  }
  regular(file, isCert = false) {
    const stat = fs.lstatSync(file);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4 * 1024 * 1024) throw deployError('INCOMPATIBLE');
    if (isCert) {
      const relative = path.relative(this.certRoot, file);
      if (!relative || relative.startsWith('..') || path.isAbsolute(relative) || fs.realpathSync(file) !== path.join(fs.realpathSync(this.certRoot), relative)) throw deployError('INCOMPATIBLE');
    }
    if (this.secure) {
      for (let current = fs.realpathSync(file); ; current = path.dirname(current)) {
        const metadata = fs.statSync(current);
        if (metadata.uid !== 0 || metadata.mode & 0o022) throw deployError('INCOMPATIBLE');
        if (current === path.dirname(current)) break;
      }
    }
    return stat;
  }
  snapshot(file, isCert = false) {
    const stat = this.regular(file, isCert);
    return { file, content: fs.readFileSync(file).toString('base64'), mode: stat.mode & 0o777, uid: stat.uid, gid: stat.gid, isCert };
  }
  replace(snapshot, content) {
    this.regular(snapshot.file, snapshot.isCert);
    this.atomic(snapshot.file, content, snapshot);
  }
  sameContent(file, a, b) {
    if (![this.indexPath, this.gatewayPath].includes(file)) return a === b;
    try { return equal(JSON.parse(Buffer.from(a, 'base64')), JSON.parse(Buffer.from(b, 'base64'))); } catch { return false; }
  }
  atomic(file, content, { mode = 0o600, uid, gid } = {}) {
    const temp = `${file}.${randomUUID()}.tmp`;
    const fd = fs.openSync(temp, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
    try {
      fs.writeFileSync(fd, content);
      if (this.secure && uid !== undefined) fs.fchownSync(fd, uid, gid);
      fs.fchmodSync(fd, mode); fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    try { fs.renameSync(temp, file); } finally { try { fs.unlinkSync(temp); } catch {} }
    if (this.secure) { const dir = fs.openSync(path.dirname(file), fs.constants.O_RDONLY); try { fs.fsyncSync(dir); } finally { fs.closeSync(dir); } }
  }
  async read() {
    const index = this.snapshot(this.indexPath); const gateway = this.snapshot(this.gatewayPath);
    const entries = JSON.parse(Buffer.from(index.content, 'base64')); const mappings = JSON.parse(Buffer.from(gateway.content, 'base64'));
    const rows = await this.adapter.rows();
    if (![entries, mappings, rows].every((v) => Array.isArray(v) && v.length <= 1024)) throw deployError('INCOMPATIBLE');
    return { rows, entries, mappings, index, gateway };
  }
  target(row, state) {
    if (!row || row.source !== 'upload') throw deployError('PROTECTED');
    if (!Number.isSafeInteger(row.id) || row.id <= 0 || !row.certificate || !row.private_key) throw deployError('INCOMPATIBLE');
    const cert = this.snapshot(row.certificate, true); const key = this.snapshot(row.private_key, true);
    // fnOS imports may use 0755. Existing read/execute bits do not permit
    // modification; regular() still rejects non-root ownership and writable
    // files/parents. The new key is readable only by root and fnOS's web group.
    const parsed = inspectDeploymentCertificate(Buffer.from(cert.content, 'base64').toString(), Buffer.from(key.content, 'base64').toString(), { allowExpired: true });
    const names = cleanDomains(String(row.san || row.domain).split(/[,;\s]+/).filter(Boolean));
    if (!equal(names, parsed.domains) || row.valid_from !== parsed.validFrom || row.valid_to !== parsed.validTo) throw deployError('INCOMPATIBLE');
    const matches = state.entries.filter((e) => e.certificate === row.certificate && e.privateKey === row.private_key);
    if (matches.length !== 1 || matches[0].validFrom !== row.valid_from || matches[0].validTo !== row.valid_to) throw deployError('INCOMPATIBLE');
    return { row, cert, key, parsed, entry: matches[0] };
  }
  publicTarget(target) {
    return { id: String(target.row.id), domains: target.parsed.domains, validTo: new Date(target.parsed.validTo).toISOString(), fingerprint: target.parsed.fingerprint };
  }
  async status() {
    if (this.recoveryFailed) throw deployError('RECOVERY');
    const state = await this.read(); const targets = []; const unavailableTargets = [];
    let ports = [];
    try { ports = await this.adapter.detectPorts?.() || []; } catch {}
    for (const row of state.rows) {
      try {
        const target = this.target(row, state); const entry = this.publicTarget(target);
        const host = entry.domains.find((domain) => !domain.startsWith('*.'));
        const bound = state.mappings.some((m) => m.cert === row.certificate && m.key === row.private_key);
        const matches = host && bound ? await Promise.all(ports.map(async (port) => { try { await this.adapter.probe(host, port, entry.fingerprint); return port; } catch { return null; } })) : [];
        targets.push({ ...entry, bound, probeHost: host || '', verifiedPorts: matches.filter(Boolean) });
      } catch (error) {
        const domains = cleanDomains(String(row.san || row.domain || '').split(/[,;\s]+/)).filter((name) => domainPattern.test(name));
        unavailableTargets.push({ id: String(row.id), domains, reason: DEPLOY_ERRORS[error.code] || DEPLOY_ERRORS.INCOMPATIBLE });
      }
    }
    return { available: true, experimental: true, targets, unavailableTargets, skipped: unavailableTargets.length, running: this.busy };
  }
  async plan(input) {
    if (this.recoveryFailed) throw deployError('RECOVERY');
    if (!/^[1-9]\d{0,14}$/.test(String(input.targetId)) || !domainPattern.test(input.probeHost || '') || input.probeHost.startsWith('*.') || !Number.isInteger(input.probePort) || input.probePort < 1 || input.probePort > 65535) throw deployError('INVALID');
    const state = await this.read(); const target = this.target(state.rows.find((row) => String(row.id) === input.targetId), state);
    const next = inspectDeploymentCertificate(input.certificatePem, input.privateKeyPem);
    await this.adapter.validateTrust?.(next);
    if (!equal(next.domains, target.parsed.domains) || !next.leaf.checkHost(input.probeHost, { subject: 'never' })) throw deployError('DOMAIN');
    if (input.expectedFingerprint && input.expectedFingerprint !== target.parsed.fingerprint) throw deployError('CONFLICT');
    const mapping = state.mappings.some((m) => m.cert === target.row.certificate && m.key === target.row.private_key && (m.host === 'fallback' || m.host === input.probeHost || target.parsed.domains.includes(m.host)));
    if (!mapping) throw deployError('INCOMPATIBLE');
    await this.adapter.probe(input.probeHost, input.probePort, target.parsed.fingerprint);
    const keyPermissions = await this.adapter.keyPermissions();
    if (keyPermissions.mode !== 0o640 || !Number.isSafeInteger(keyPermissions.gid) || keyPermissions.gid <= 0) throw deployError('INCOMPATIBLE');
    const files = [{ ...target.cert, next: Buffer.from(next.chainPem).toString('base64') }, { ...target.key, nextMode: keyPermissions.mode, nextGid: keyPermissions.gid, next: Buffer.from(input.privateKeyPem).toString('base64') }];
    const extra = [[target.row.issuer_certificate, next.issuerPem, false], [target.entry.fullchain, next.chainPem, true], [path.join(path.dirname(target.row.certificate), 'fullchain.crt'), next.chainPem, true]];
    for (const [file, pem, fullchain] of extra) {
      if (!file || files.some((f) => f.file === file)) continue;
      if (!fs.existsSync(file)) { if (file === target.row.issuer_certificate || file === target.entry.fullchain) throw deployError('INCOMPATIBLE'); continue; }
      if (!pem) throw deployError('INVALID');
      const snapshot = this.snapshot(file, true);
      if (fullchain && new X509Certificate(Buffer.from(snapshot.content, 'base64')).fingerprint256 !== target.parsed.fingerprint) throw deployError('INCOMPATIBLE');
      files.push({ ...snapshot, next: Buffer.from(pem).toString('base64') });
    }
    const paths = new Set(files.map((file) => file.file));
    if (state.rows.some((row) => row.id !== target.row.id && [row.certificate, row.private_key, row.issuer_certificate].some((file) => paths.has(file))) || state.entries.some((entry) => entry !== target.entry && [entry.certificate, entry.privateKey, entry.fullchain].some((file) => paths.has(file)))) throw deployError('INCOMPATIBLE');
    const newEntries = state.entries.map((entry) => entry === target.entry ? { ...entry, validFrom: next.validFrom, validTo: next.validTo } : entry);
    files.push({ ...state.index, next: Buffer.from(JSON.stringify(newEntries)).toString('base64') });
    const rowAfter = { ...target.row, valid_from: next.validFrom, valid_to: next.validTo, encrypt_type: next.encryptType, issued_by: next.issuedBy, status: 'suc', updated_time: Date.now() };
    const planId = hash(JSON.stringify({ files, row: target.row, gateway: state.gateway.content, host: input.probeHost, port: input.probePort }));
    return { files, rowBefore: target.row, rowAfter, gateway: state.gateway, probeHost: input.probeHost, probePort: input.probePort, oldFingerprint: target.parsed.fingerprint, newFingerprint: next.fingerprint, planId, target: this.publicTarget(target), validTo: new Date(next.validTo).toISOString() };
  }
  async prepare(input) {
    if (this.busy) throw deployError('BUSY');
    const plan = await this.plan(input);
    return { planId: plan.planId, target: plan.target, fingerprint: plan.newFingerprint, validTo: plan.validTo, probeHost: plan.probeHost, probePort: plan.probePort };
  }
  async rollback(journal) {
    const rows = await this.adapter.rows(); const row = rows.find((r) => r.id === journal.rowBefore.id);
    if (!equal(row, journal.rowBefore) && !equal(row, journal.rowAfter)) throw deployError('RECOVERY');
    for (const file of journal.files) {
      const current = this.snapshot(file.file, file.isCert);
      if (!this.sameContent(file.file, current.content, file.content) && !this.sameContent(file.file, current.content, file.next)) throw deployError('RECOVERY');
    }
    if (!this.sameContent(this.gatewayPath, this.snapshot(this.gatewayPath).content, journal.gateway.content)) throw deployError('RECOVERY');
    if (!equal(row, journal.rowBefore)) await this.adapter.cas(journal.rowAfter, journal.rowBefore);
    for (const file of journal.files) this.replace(file, Buffer.from(file.content, 'base64'));
    await this.adapter.restart();
    await this.adapter.probe(journal.probeHost, journal.probePort, journal.oldFingerprint);
  }
  pruneBackups() {
    // Only completed helper-owned journals, never the active recovery journal.
    const files = fs.readdirSync(this.stateDir).filter((name) => /^(?:backup|rolled-back|recovered)-[a-f0-9-]{36}\.json$/.test(name))
      .map((name) => ({ file: path.join(this.stateDir, name), stat: fs.lstatSync(path.join(this.stateDir, name)) }))
      .filter(({ stat }) => stat.isFile() && !stat.isSymbolicLink()).sort((a, b) => b.stat.mtimeMs - a.stat.mtimeMs);
    for (const { file } of files.slice(10)) fs.unlinkSync(file);
  }
  async recover() {
    const file = path.join(this.stateDir, 'active.json');
    if (!fs.existsSync(file)) return;
    try {
      const journal = JSON.parse(fs.readFileSync(file, 'utf8'));
      if (!journal.committed) await this.rollback(journal);
      fs.renameSync(file, path.join(this.stateDir, `recovered-${randomUUID()}.json`));
      try { this.pruneBackups(); } catch {}
    } catch { this.recoveryFailed = true; }
  }
  async deploy(input) {
    if (this.busy) throw deployError('BUSY');
    this.busy = true; let journal; let durable = false; let stage = 'metadata';
    const active = path.join(this.stateDir, 'active.json');
    try {
      journal = await this.plan(input);
      if (!input.planId || input.planId !== journal.planId) throw deployError('CONFLICT');
      fs.mkdirSync(this.stateDir, { recursive: true, mode: 0o700 });
      if (fs.existsSync(active)) throw deployError('RECOVERY');
      this.atomic(active, Buffer.from(JSON.stringify(journal))); durable = true;
      // Re-read everything after the durable backup, before the first mutation.
      for (const file of journal.files) if (!this.sameContent(file.file, this.snapshot(file.file, file.isCert).content, file.content)) throw deployError('CONFLICT');
      if (!this.sameContent(this.gatewayPath, this.snapshot(this.gatewayPath).content, journal.gateway.content)) throw deployError('CONFLICT');
      await this.adapter.cas(journal.rowBefore, journal.rowAfter);
      stage = 'files';
      for (const file of journal.files) this.replace({ ...file, mode: file.nextMode ?? file.mode, gid: file.nextGid ?? file.gid }, Buffer.from(file.next, 'base64'));
      stage = 'restart';
      await this.adapter.restart();
      stage = 'verify';
      await this.adapter.probe(journal.probeHost, journal.probePort, journal.newFingerprint, true);
      stage = 'consistency';
      for (const file of journal.files) if (!this.sameContent(file.file, this.snapshot(file.file, file.isCert).content, file.next)) throw deployError('CONFLICT');
      if (!equal((await this.adapter.rows()).find((row) => row.id === journal.rowAfter.id), journal.rowAfter)) throw deployError('CONFLICT');
      if (!this.sameContent(this.gatewayPath, this.snapshot(this.gatewayPath).content, journal.gateway.content)) throw deployError('CONFLICT');
      journal.committed = true; this.atomic(active, Buffer.from(JSON.stringify(journal)));
      fs.renameSync(active, path.join(this.stateDir, `backup-${randomUUID()}.json`));
      try { this.pruneBackups(); } catch {}
      return { ok: true, fingerprint: journal.newFingerprint, validTo: journal.validTo, verifiedAt: new Date().toISOString() };
    } catch (error) {
      if (!durable) throw error;
      journal.failure = { stage, code: DEPLOY_ERRORS[error.code] ? error.code : 'INCOMPATIBLE', at: new Date().toISOString() };
      try { this.atomic(active, Buffer.from(JSON.stringify(journal))); } catch {}
      try { await this.rollback(journal); fs.renameSync(active, path.join(this.stateDir, `rolled-back-${randomUUID()}.json`)); }
      catch { this.recoveryFailed = true; throw deployError('RECOVERY'); }
      throw Object.assign(deployError('ROLLED_BACK'), { stage });
    } finally { this.busy = false; }
  }
}
