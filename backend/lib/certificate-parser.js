import { createPrivateKey, randomUUID, X509Certificate } from 'node:crypto';
import tls from 'node:tls';
import forge from 'node-forge';

const CERTIFICATE_TYPES = new Set(['CERTIFICATE', 'TRUSTED CERTIFICATE']);
const PRIVATE_KEY_TYPES = new Set(['PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'ENCRYPTED PRIVATE KEY']);

function safeFileName(value = '') {
  return String(value).replace(/[\\/\0]/g, '_').slice(0, 160) || 'certificate';
}

function stem(fileName = '') {
  return safeFileName(fileName)
    .replace(/\.(pem|crt|cer|key|der|pfx|p12)$/i, '')
    .replace(/[-_.]?(fullchain|chain|certificate|cert|privkey|private|key)$/i, '') || 'certificate';
}

function pemBlocks(text = '', sourceFile = '') {
  const blocks = [];
  const pattern = /-----BEGIN ([A-Z0-9 ]+)-----[\s\S]*?-----END \1-----/g;
  for (const match of String(text).matchAll(pattern)) {
    blocks.push({ type: match[1], pem: `${match[0].trim()}\n`, sourceFile });
  }
  return blocks;
}

function privateKeyFromDer(buffer, passphrase = '') {
  for (const type of ['pkcs8', 'pkcs1', 'sec1']) {
    try {
      const key = createPrivateKey({ key: buffer, format: 'der', type, passphrase });
      return `${key.export({ format: 'pem', type: 'pkcs8' }).toString().trim()}\n`;
    } catch {}
  }
  return null;
}

function commonName(x509) {
  const match = String(x509.subject || '').match(/(?:^|\n)CN=([^\n,]+)/);
  return match?.[1]?.trim() || '';
}

function subjectAltNames(x509) {
  return String(x509.subjectAltName || '')
    .split(/,\s*/)
    .map((entry) => entry.replace(/^DNS:/i, '').trim())
    .filter(Boolean);
}

function matchCertificate(keyPem, certificates, passphrase = '') {
  const key = createPrivateKey({ key: keyPem, format: 'pem', passphrase });
  const certificate = certificates.find((item) => {
    try { return new X509Certificate(item.pem).checkPrivateKey(key); } catch { return false; }
  });
  return { key, certificate };
}

function certificateChainFor(leaf, certificates = []) {
  const remaining = [...certificates];
  const chain = [];
  let current = new X509Certificate(leaf.pem);
  while (remaining.length) {
    const issuerIndex = remaining.findIndex((item) => {
      try {
        const issuer = new X509Certificate(item.pem);
        return current.checkIssued(issuer) && current.verify(issuer.publicKey);
      } catch {
        return false;
      }
    });
    if (issuerIndex < 0) break;
    const [issuerItem] = remaining.splice(issuerIndex, 1);
    const issuer = new X509Certificate(issuerItem.pem);
    chain.push(issuerItem);
    if (issuer.subject === issuer.issuer) break;
    current = issuer;
  }
  return chain;
}

function candidateFromPair({ name, format, keyPem, leaf, chain = [], sourceFiles = [], passphrase = '' }) {
  const key = createPrivateKey({ key: keyPem, format: 'pem', passphrase });
  const x509 = new X509Certificate(leaf.pem);
  if (!x509.checkPrivateKey(key)) throw new Error('证书与私钥不匹配');
  const certificatePem = `${[leaf.pem, ...chain.map((item) => item.pem)].join('\n').trim()}\n`;
  const normalizedKeyPem = `${key.export({ format: 'pem', type: 'pkcs8' }).toString().trim()}\n`;
  tls.createSecureContext({ cert: certificatePem, key: normalizedKeyPem });
  return {
    id: randomUUID(),
    name: String(name || commonName(x509) || stem(leaf.sourceFile)).trim(),
    format,
    subject: x509.subject,
    issuer: x509.issuer,
    validFrom: x509.validFrom,
    validTo: x509.validTo,
    fingerprint: x509.fingerprint256,
    serialNumber: x509.serialNumber,
    subjectAltNames: subjectAltNames(x509),
    keyType: key.asymmetricKeyType || 'unknown',
    chainLength: chain.length + 1,
    sourceFiles: [...new Set(sourceFiles.map(safeFileName))],
    certificatePem,
    privateKeyPem: normalizedKeyPem,
  };
}

function pfxCandidates(buffer, fileName, passphrase = '') {
  const binary = forge.util.createBuffer(buffer.toString('binary'));
  const asn1 = forge.asn1.fromDer(binary);
  const p12 = forge.pkcs12.pkcs12FromAsn1(asn1, false, passphrase);
  const certBagType = forge.pki.oids.certBag;
  const keyBagTypes = [forge.pki.oids.pkcs8ShroudedKeyBag, forge.pki.oids.keyBag];
  const certificates = (p12.getBags({ bagType: certBagType })[certBagType] || []).map((bag) => ({ pem: forge.pki.certificateToPem(bag.cert), sourceFile: fileName }));
  const keys = keyBagTypes.flatMap((bagType) => p12.getBags({ bagType })[bagType] || []).filter((bag) => bag.key).map((bag) => forge.pki.privateKeyToPem(bag.key));
  if (!certificates.length || !keys.length) throw new Error('PFX/P12 中未找到可用的证书和私钥');
  const used = new Set();
  return keys.map((keyPem, index) => {
    const { certificate } = matchCertificate(keyPem, certificates.filter((item) => !used.has(item)));
    if (!certificate) throw new Error('PFX/P12 中的证书与私钥无法配对');
    used.add(certificate);
    return candidateFromPair({
      name: keys.length > 1 ? `${stem(fileName)} ${index + 1}` : stem(fileName),
      format: 'PKCS#12',
      keyPem,
      leaf: certificate,
      chain: certificateChainFor(certificate, certificates.filter((item) => item !== certificate)),
      sourceFiles: [fileName],
    });
  });
}

export function inspectCertificateFiles(files = [], { passphrase = '', name = '' } = {}) {
  if (!Array.isArray(files) || !files.length) throw new Error('请选择要导入的证书文件');
  if (files.length > 20) throw new Error('单次最多导入 20 个文件');
  const candidates = [];
  const warnings = [];
  const certificates = [];
  const keys = [];

  for (const file of files) {
    const fileName = safeFileName(file.name);
    const buffer = Buffer.from(String(file.data || ''), 'base64');
    if (!buffer.length) { warnings.push(`${fileName} 是空文件`); continue; }
    if (buffer.length > 2 * 1024 * 1024) { warnings.push(`${fileName} 超过 2 MB，已跳过`); continue; }
    if (/\.(pfx|p12)$/i.test(fileName)) {
      try { candidates.push(...pfxCandidates(buffer, fileName, passphrase)); }
      catch (error) { warnings.push(`${fileName}：${error.message}`); }
      continue;
    }

    const blocks = pemBlocks(buffer.toString('utf8'), fileName);
    let recognized = false;
    for (const block of blocks) {
      if (CERTIFICATE_TYPES.has(block.type)) { certificates.push(block); recognized = true; }
      if (PRIVATE_KEY_TYPES.has(block.type)) { keys.push(block); recognized = true; }
    }
    if (recognized) continue;
    try {
      const x509 = new X509Certificate(buffer);
      certificates.push({ pem: `${x509.toString().trim()}\n`, sourceFile: fileName });
      continue;
    } catch {}
    const keyPem = privateKeyFromDer(buffer, passphrase);
    if (keyPem) keys.push({ pem: keyPem, sourceFile: fileName });
    else warnings.push(`${fileName}：未识别到证书或私钥`);
  }

  const usedCertificates = new Set();
  for (const [index, key] of keys.entries()) {
    let matched;
    try { matched = matchCertificate(key.pem, certificates.filter((item) => !usedCertificates.has(item)), passphrase).certificate; }
    catch (error) { warnings.push(`${key.sourceFile}：${error.message}`); continue; }
    if (!matched) { warnings.push(`${key.sourceFile}：未找到匹配的证书`); continue; }
    usedCertificates.add(matched);
    const chainCandidates = certificates.filter((item) => item !== matched && !keys.some((otherKey) => {
      try { return new X509Certificate(item.pem).checkPrivateKey(createPrivateKey({ key: otherKey.pem, format: 'pem', passphrase })); } catch { return false; }
    }));
    const chain = certificateChainFor(matched, chainCandidates);
    try {
      candidates.push(candidateFromPair({
        name: name && keys.length === 1 && candidates.length === 0 ? name : commonName(new X509Certificate(matched.pem)) || stem(key.sourceFile) || `证书 ${index + 1}`,
        format: 'PEM / DER',
        keyPem: key.pem,
        leaf: matched,
        chain,
        sourceFiles: [matched.sourceFile, key.sourceFile, ...chain.map((item) => item.sourceFile)],
        passphrase,
      }));
    } catch (error) { warnings.push(`${key.sourceFile}：${error.message}`); }
  }

  if (!candidates.length) {
    const error = new Error(warnings[0] || '没有解析到可用的证书与私钥组合');
    error.details = warnings;
    throw error;
  }
  return { candidates, warnings };
}

export function publicCertificateCandidate(candidate) {
  const { certificatePem, privateKeyPem, certPath, keyPath, ...publicData } = candidate;
  return publicData;
}
