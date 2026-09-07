import { randomUUID, X509Certificate } from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { inspectCertificateFiles, publicCertificateCandidate } from './certificate-parser.js';
import { sanitizeCertificate } from './system-certificate-store.js';

export function createCertificateRotator({ store, manager, notifier }) {
  let queue = Promise.resolve();
  const rotate = async ({ name, certificatePem, privateKeyPem, environment = 'production', provider = 'acme', domains = [], targetCertificateId, orderId, strictTarget = false }) => {
    const parsed = inspectCertificateFiles([
      { name: 'issued.pem', data: Buffer.from(certificatePem).toString('base64') },
      { name: 'issued.key', data: Buffer.from(privateKeyPem).toString('base64') },
    ], { name });
    const candidate = parsed.candidates[0];
    const x509 = new X509Certificate(candidate.certificatePem);
    if (Date.parse(x509.validFrom) > Date.now() || Date.parse(x509.validTo) <= Date.now()) throw new Error('签发证书尚未生效或已过期，旧证书保持不变');
    if (!domains.length || domains.some((domain) => domain.startsWith('*.') ? !candidate.subjectAltNames.includes(domain) : !x509.checkHost(domain, { subject: 'never' }))) throw new Error('签发证书不包含全部申请域名，旧证书保持不变');
    const isStaging = (cert) => cert.automation?.environment === 'staging';
    const inEnvironment = (cert) => isStaging(cert) === (environment === 'staging');
    const names = (cert) => (cert.subjectAltNames || []).map((value) => value.toLowerCase()).sort().join(',');
    const duplicate = store.data.certificates.find((cert) => cert.fingerprint === candidate.fingerprint && inEnvironment(cert));
    const linked = store.data.certificates.find((cert) => cert.id === targetCertificateId && inEnvironment(cert) && names(cert) === names(candidate));
    const previous = strictTarget ? store.data.certificates.find((cert) => cert.id === targetCertificateId && cert.source !== 'system') : linked || store.data.certificates.find((cert) => inEnvironment(cert) && names(cert) === names(candidate));
    if (strictTarget && !previous) throw Object.assign(new Error('待替换证书不存在或为只读系统证书'), { status: 404 });
    if (strictTarget) {
      const requiredDomains = [...(previous.subjectAltNames || []), ...store.data.rules.filter((rule) => rule.tls?.certId === previous.id).flatMap((rule) => rule.domains || [])];
      if (!requiredDomains.length || requiredDomains.some((domain) => domain.startsWith('*.') ? !candidate.subjectAltNames.includes(domain) : !x509.checkHost(domain, { subject: 'never' }))) throw Object.assign(new Error('新证书未覆盖原证书及已绑定规则的全部域名，旧证书保持不变'), { status: 400 });
    }
    if (duplicate && (!strictTarget || duplicate.id === targetCertificateId)) return { certificate: { ...sanitizeCertificate(duplicate), action: 'unchanged' }, tlsReload: { ok: true, updated: 0, failures: [] } };
    const id = previous?.id || randomUUID();
    const revision = randomUUID();
    const certPath = path.join(store.certDir, `${id}-${revision}.crt`);
    const keyPath = path.join(store.certDir, `${id}-${revision}.key`);
    const removeNew = () => { for (const file of [certPath, keyPath]) { try { fs.unlinkSync(file); } catch {} } };
    let saved;
    try {
      fs.writeFileSync(certPath, candidate.certificatePem, { mode: 0o600 });
      fs.writeFileSync(keyPath, candidate.privateKeyPem, { mode: 0o600 });
      const record = { ...publicCertificateCandidate(candidate), id, name: previous?.name || name, certPath, keyPath, createdAt: previous?.createdAt || new Date().toISOString(), automation: strictTarget ? previous.automation : { provider, environment, ...(orderId ? { orderId } : {}) } };
      saved = previous ? store.replaceManualCertificate(id, record) : store.addCertificate(record);
    } catch (error) {
      if (previous) store.data.certificates = store.data.certificates.map((cert) => cert.id === id ? previous : cert);
      else store.data.certificates = store.data.certificates.filter((cert) => cert.id !== id);
      // Best-effort restoration after a disk error; keep old PEM files intact.
      try { store.save(); removeNew(); } catch {}
      throw error;
    }
    let tlsReload;
    try {
      tlsReload = await manager.reloadTlsCertificates([id]);
      if (!tlsReload.ok) throw new Error('证书热更新未全部成功');
    } catch {
      if (store.data.certificates.find((cert) => cert.id === id)?.fingerprint === saved.fingerprint) {
        if (previous) store.replaceManualCertificate(id, previous); else store.removeCertificate(id);
        if (previous) { try { await manager.reloadTlsCertificates([id]); } catch {} }
        removeNew();
      }
      throw new Error('新证书热更新失败，已保留原证书与规则绑定；稍后会重试同一订单');
    }
    if (previous) for (const file of [previous.certPath, previous.keyPath].filter(Boolean)) { try { fs.unlinkSync(file); } catch {} }
    const action = previous ? 'replaced' : 'created';
    void notifier?.send('certificate.updated', { source: provider, certificateId: id, name: saved.name, action, environment, tlsUpdated: tlsReload.updated, ok: true });
    return { certificate: { ...sanitizeCertificate(saved), action }, tlsReload, warnings: parsed.warnings };
  };
  return (input) => { const result = queue.then(() => rotate(input)); queue = result.catch(() => {}); return result; };
}
