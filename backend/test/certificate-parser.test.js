import assert from 'node:assert/strict';
import test from 'node:test';
import forge from 'node-forge';
import { inspectCertificateFiles } from '../lib/certificate-parser.js';

function fixture() {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const certificate = forge.pki.createCertificate();
  certificate.publicKey = keys.publicKey;
  certificate.serialNumber = '01';
  certificate.validity.notBefore = new Date(Date.now() - 60000);
  certificate.validity.notAfter = new Date(Date.now() + 86400000 * 365);
  const attributes = [{ name: 'commonName', value: 'proxy.example.test' }];
  certificate.setSubject(attributes);
  certificate.setIssuer(attributes);
  certificate.setExtensions([{ name: 'subjectAltName', altNames: [{ type: 2, value: 'proxy.example.test' }] }]);
  certificate.sign(keys.privateKey, forge.md.sha256.create());
  return { keys, certificate, certPem: forge.pki.certificateToPem(certificate), keyPem: forge.pki.privateKeyToPem(keys.privateKey) };
}

function issuedFixture() {
  const issuerKeys = forge.pki.rsa.generateKeyPair(2048);
  const issuer = forge.pki.createCertificate();
  issuer.publicKey = issuerKeys.publicKey;
  issuer.serialNumber = '10';
  issuer.validity.notBefore = new Date(Date.now() - 60000);
  issuer.validity.notAfter = new Date(Date.now() + 86400000 * 730);
  const issuerAttributes = [{ name: 'commonName', value: 'Example Test CA' }];
  issuer.setSubject(issuerAttributes);
  issuer.setIssuer(issuerAttributes);
  issuer.setExtensions([{ name: 'basicConstraints', cA: true }, { name: 'keyUsage', keyCertSign: true }]);
  issuer.sign(issuerKeys.privateKey, forge.md.sha256.create());

  const leafKeys = forge.pki.rsa.generateKeyPair(2048);
  const leaf = forge.pki.createCertificate();
  leaf.publicKey = leafKeys.publicKey;
  leaf.serialNumber = '11';
  leaf.validity.notBefore = new Date(Date.now() - 60000);
  leaf.validity.notAfter = new Date(Date.now() + 86400000 * 365);
  leaf.setSubject([{ name: 'commonName', value: 'issued.example.test' }]);
  leaf.setIssuer(issuerAttributes);
  leaf.setExtensions([{ name: 'subjectAltName', altNames: [{ type: 2, value: 'issued.example.test' }] }]);
  leaf.sign(issuerKeys.privateKey, forge.md.sha256.create());
  return {
    leafPem: forge.pki.certificateToPem(leaf),
    keyPem: forge.pki.privateKeyToPem(leafKeys.privateKey),
    issuerPem: forge.pki.certificateToPem(issuer),
  };
}

const upload = (name, buffer) => ({ name, data: Buffer.from(buffer).toString('base64') });

test('parses and matches separate PEM certificate and private key files', () => {
  const generated = fixture();
  const result = inspectCertificateFiles([upload('proxy.crt', generated.certPem), upload('proxy.key', generated.keyPem)]);
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].name, 'proxy.example.test');
  assert.deepEqual(result.candidates[0].subjectAltNames, ['proxy.example.test']);
  assert.match(result.candidates[0].certificatePem, /BEGIN CERTIFICATE/);
  assert.match(result.candidates[0].privateKeyPem, /BEGIN PRIVATE KEY/);
});

test('parses password-protected PKCS#12 files', () => {
  const generated = fixture();
  const p12 = forge.pkcs12.toPkcs12Asn1(generated.keys.privateKey, [generated.certificate], 'secret', { algorithm: '3des' });
  const buffer = Buffer.from(forge.asn1.toDer(p12).getBytes(), 'binary');
  const result = inspectCertificateFiles([upload('proxy.p12', buffer)], { passphrase: 'secret' });
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].format, 'PKCS#12');
  assert.equal(result.candidates[0].name, 'proxy');
});

test('does not append unrelated certificates to an imported chain', () => {
  const leaf = fixture();
  const unrelated = fixture();
  const result = inspectCertificateFiles([
    upload('leaf.crt', leaf.certPem),
    upload('leaf.key', leaf.keyPem),
    upload('unrelated-ca.crt', unrelated.certPem),
  ]);
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].chainLength, 1);
  assert.deepEqual(result.candidates[0].sourceFiles, ['leaf.crt', 'leaf.key']);
});

test('orders and includes a verified issuer chain', () => {
  const generated = issuedFixture();
  const result = inspectCertificateFiles([
    upload('issuer.crt', generated.issuerPem),
    upload('leaf.key', generated.keyPem),
    upload('leaf.crt', generated.leafPem),
  ]);
  assert.equal(result.candidates.length, 1);
  assert.equal(result.candidates[0].chainLength, 2);
  assert.deepEqual(result.candidates[0].sourceFiles, ['leaf.crt', 'leaf.key', 'issuer.crt']);
});
