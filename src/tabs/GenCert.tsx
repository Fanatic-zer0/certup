import { useState } from 'react';
import { Loader2, CheckCircle, XCircle, Download, Copy, Terminal, Pin, Clock } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input, Textarea, Label } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle, FieldRow } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { CopyBtn, MatchBanner, CliBlock, PemOutput } from '@/components/ui/cert-ui';
import { Section, Field, MatchBadge, TrustEntryCard } from '@/components/cert-components';
import { KeyAlgoSelector } from '@/components/KeyAlgoSelector';
import {
  attrMap, certFingerprint, splitPemCerts, getRsaModulus, generateRsaKeyPair,
  isNonRsaError, friendlySigAlg, parseRawCertFromPem, extractSpkiDer,
  publicKeyBitsFromCertOrCsr, publicKeyBitsFromPrivateKey,
  verifyEcCertSignature, spkiSha256FromPem, safeIso,
  parseJksBinary, parsePkcs12Binary, parseTrustEntry, pemDownload, binaryDownload,
  extractForgeExtensions, toNativeKeySpec, keyAlgoLabel, EC_CURVE_OPTIONS,
  type TrustEntry, type KeyAlgoState, type KeyAlgo, type ChainLink, type CertType,
} from '@/lib/cert-crypto';
import { isNativeCrypto, nativeCert, type NativeSubject, type NativeKeySpec } from '@/lib/nativeCrypto';
import * as forge from 'node-forge';


export function GenCertTab() {
  const [certType, setCertType] = useState<CertType>('self-signed');
  const [cn, setCn] = useState('');
  const [org, setOrg] = useState('');
  const [ou, setOu] = useState('');
  const [country, setCountry] = useState('US');
  const [state, setState] = useState('');
  const [locality, setLocality] = useState('');
  const [san, setSan] = useState('');
  const native = isNativeCrypto();
  const [keyAlgo, setKeyAlgo] = useState<KeyAlgoState>({ algo: 'rsa', rsaBits: '2048', curve: 'P-256' });
  const [validDays, setValidDays] = useState('365');
  const [caPem, setCaPem] = useState('');
  const [caKeyPem, setCaKeyPem] = useState('');
  const [csrPem, setCsrPem] = useState('');
  const [certOut, setCertOut] = useState('');
  const [keyOut, setKeyOut] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const CERT_TYPES: { id: CertType; label: string; desc: string }[] = [
    { id: 'self-signed', label: 'Self-Signed', desc: 'Generate key + cert, signed by itself' },
    { id: 'ca-signed', label: 'CA-Signed', desc: 'Sign an existing CSR with a CA cert + key' },
    { id: 'root-ca', label: 'Root CA', desc: 'Create a self-signed Root CA certificate' },
    { id: 'intermediate-ca', label: 'Intermediate CA', desc: 'CA cert signed by a Root CA' },
  ];

  const buildSubject = (): forge.pki.CertificateField[] => {
    const attrs: forge.pki.CertificateField[] = [{ name: 'commonName', value: cn.trim() }];
    if (org.trim()) attrs.push({ name: 'organizationName', value: org.trim() });
    if (ou.trim()) attrs.push({ name: 'organizationalUnitName', value: ou.trim() });
    if (country.trim()) attrs.push({ name: 'countryName', value: country.trim() });
    if (state.trim()) attrs.push({ name: 'stateOrProvinceName', value: state.trim() });
    if (locality.trim()) attrs.push({ name: 'localityName', value: locality.trim() });
    return attrs;
  };

  const sanExtension = (): Record<string, unknown> | null => {
    const sanList = san.split(',').map((s) => s.trim()).filter(Boolean);
    if (sanList.length === 0) return null;
    return { name: 'subjectAltName', altNames: sanList.map((s) => {
      const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(s);
      return isIp ? { type: 7, ip: s } : { type: 2, value: s };
    }) };
  };

  const days = parseInt(validDays) || 365;

  const generate = async () => {
    if (!cn.trim() && certType !== 'ca-signed') { setError('Common Name is required.'); return; }
    setError(''); setLoading(true); setCertOut(''); setKeyOut('');
    try {
      // Native (desktop) path: generate certs with any algorithm (RSA / EC / Ed).
      if (native) {
        const sanList = san.split(',').map((s) => s.trim()).filter(Boolean);
        const subject: NativeSubject = {
          common_name: cn.trim(), organization: org.trim(), org_unit: ou.trim(),
          country: country.trim(), state: state.trim(), locality: locality.trim(), san: sanList,
        };
        const out = await nativeCert.generate({
          cert_type: certType,
          subject: certType === 'ca-signed' ? undefined : subject,
          key: toNativeKeySpec(keyAlgo),
          valid_days: days,
          ca_cert_pem: caPem,
          ca_key_pem: caKeyPem,
          csr_pem: csrPem,
        });
        setCertOut(out.cert_pem); setKeyOut(out.key_pem);
        setLoading(false);
        return;
      }

      if (certType === 'self-signed') {
        const kp = await generateRsaKeyPair(parseInt(keyAlgo.rsaBits));
        const cert = forge.pki.createCertificate();
        cert.publicKey = kp.publicKey;
        cert.serialNumber = '01' + forge.util.bytesToHex(forge.random.getBytesSync(8));
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date(Date.now() + days * 86400000);
        const attrs = buildSubject();
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        const exts: any[] = [
          { name: 'basicConstraints', cA: false },
          { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
          { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
          { name: 'subjectKeyIdentifier' },
        ];
        const sanExt = sanExtension();
        if (sanExt) exts.push(sanExt);
        cert.setExtensions(exts);
        cert.sign(kp.privateKey, forge.md.sha256.create());
        setCertOut(forge.pki.certificateToPem(cert));
        setKeyOut(forge.pki.privateKeyToPem(kp.privateKey));

      } else if (certType === 'root-ca') {
        const kp = await generateRsaKeyPair(parseInt(keyAlgo.rsaBits));
        const cert = forge.pki.createCertificate();
        cert.publicKey = kp.publicKey;
        cert.serialNumber = '01';
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date(Date.now() + days * 86400000);
        const attrs = buildSubject();
        cert.setSubject(attrs);
        cert.setIssuer(attrs);
        cert.setExtensions([
          { name: 'basicConstraints', cA: true, critical: true } as any,
          { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true } as any,
          { name: 'subjectKeyIdentifier' } as any,
        ]);
        cert.sign(kp.privateKey, forge.md.sha256.create());
        setCertOut(forge.pki.certificateToPem(cert));
        setKeyOut(forge.pki.privateKeyToPem(kp.privateKey));

      } else if (certType === 'intermediate-ca') {
        if (!caPem.trim() || !caKeyPem.trim()) { setError('Root CA certificate and key are required for Intermediate CA.'); setLoading(false); return; }
        const caCert = forge.pki.certificateFromPem(caPem);
        const caKey = forge.pki.privateKeyFromPem(caKeyPem);
        const kp = await generateRsaKeyPair(parseInt(keyAlgo.rsaBits));
        const cert = forge.pki.createCertificate();
        cert.publicKey = kp.publicKey;
        cert.serialNumber = '02' + forge.util.bytesToHex(forge.random.getBytesSync(8));
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date(Date.now() + days * 86400000);
        const attrs = buildSubject();
        cert.setSubject(attrs);
        cert.setIssuer(caCert.subject.attributes);
        cert.setExtensions([
          { name: 'basicConstraints', cA: true, pathlenConstraint: 0, critical: true } as any,
          { name: 'keyUsage', keyCertSign: true, cRLSign: true, critical: true } as any,
          { name: 'subjectKeyIdentifier' } as any,
          { name: 'authorityKeyIdentifier', keyIdentifier: true } as any,
        ]);
        cert.sign(caKey, forge.md.sha256.create());
        setCertOut(forge.pki.certificateToPem(cert));
        setKeyOut(forge.pki.privateKeyToPem(kp.privateKey));

      } else if (certType === 'ca-signed') {
        if (!caPem.trim() || !caKeyPem.trim()) { setError('CA certificate and key are required.'); setLoading(false); return; }
        if (!csrPem.trim()) { setError('CSR is required.'); setLoading(false); return; }
        const caCert = forge.pki.certificateFromPem(caPem);
        const caKey = forge.pki.privateKeyFromPem(caKeyPem);
        const csr = forge.pki.certificationRequestFromPem(csrPem);
        if (!csr.verify()) throw new Error('CSR signature is invalid');
        const cert = forge.pki.createCertificate();
        cert.publicKey = csr.publicKey as forge.pki.PublicKey;
        cert.serialNumber = '03' + forge.util.bytesToHex(forge.random.getBytesSync(8));
        cert.validity.notBefore = new Date();
        cert.validity.notAfter = new Date(Date.now() + days * 86400000);
        cert.setSubject(csr.subject.attributes);
        cert.setIssuer(caCert.subject.attributes);
        const exts: any[] = [
          { name: 'basicConstraints', cA: false },
          { name: 'keyUsage', digitalSignature: true, keyEncipherment: true },
          { name: 'extKeyUsage', serverAuth: true, clientAuth: true },
          { name: 'subjectKeyIdentifier' },
          { name: 'authorityKeyIdentifier', keyIdentifier: true },
        ];
        const sanExt = sanExtension();
        if (sanExt) exts.push(sanExt);
        cert.setExtensions(exts);
        cert.sign(caKey, forge.md.sha256.create());
        setCertOut(forge.pki.certificateToPem(cert));
        setKeyOut(''); // CA-signed: no new key generated (CSR already has the key)
      }
    } catch (e) { setError(String(e)); }
    setLoading(false);
  };

  const needsSubject = certType !== 'ca-signed';
  const needsCa = certType === 'ca-signed' || certType === 'intermediate-ca';
  const needsCsr = certType === 'ca-signed';

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium mb-2" style={{ color: 'var(--text-secondary)' }}>Certificate Type</label>
        <div className="grid grid-cols-2 gap-2">
          {CERT_TYPES.map(({ id, label, desc }) => (
            <button key={id} className="text-left p-2.5 rounded-lg border transition-colors"
              style={{
                borderColor: certType === id ? 'var(--accent)' : 'var(--border)',
                background: certType === id ? 'rgba(99,102,241,0.08)' : 'var(--bg-secondary)',
              }}
              onClick={() => setCertType(id)}>
              <div className="text-xs font-semibold" style={{ color: certType === id ? 'var(--accent)' : 'var(--text-primary)' }}>{label}</div>
              <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{desc}</div>
            </button>
          ))}
        </div>
      </div>

      {needsSubject && (
        <div className="grid grid-cols-2 gap-3">
          <div className="col-span-2">
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Common Name (CN) *</label>
            <input className="input-base" value={cn} onChange={(e) => setCn(e.target.value)} placeholder={certType === 'root-ca' ? 'My Root CA' : 'example.com'} />
          </div>
          <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Organization (O)</label>
            <input className="input-base" value={org} onChange={(e) => setOrg(e.target.value)} placeholder="My Company" /></div>
          <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Org Unit (OU)</label>
            <input className="input-base" value={ou} onChange={(e) => setOu(e.target.value)} placeholder="Engineering" /></div>
          <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Country (2-letter)</label>
            <input className="input-base" value={country} onChange={(e) => setCountry(e.target.value)} maxLength={2} /></div>
          <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>State</label>
            <input className="input-base" value={state} onChange={(e) => setState(e.target.value)} /></div>
          {!['root-ca', 'intermediate-ca'].includes(certType) && (
            <div className="col-span-2">
              <label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>SANs (comma-separated DNS/IP)</label>
              <input className="input-base font-mono text-xs" value={san} onChange={(e) => setSan(e.target.value)} placeholder="www.example.com, api.example.com" />
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 gap-3">
        {!needsCsr && (
          <div className="col-span-2">
            <KeyAlgoSelector value={keyAlgo} onChange={setKeyAlgo} native={native} />
          </div>
        )}
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Validity (days)</label>
          <input className="input-base" type="number" value={validDays} onChange={(e) => setValidDays(e.target.value)} />
        </div>
      </div>

      {needsCsr && (
        <div>
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>CSR (PEM)</label>
          <textarea className="input-base font-mono text-xs resize-none" rows={5}
            placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
            value={csrPem} onChange={(e) => setCsrPem(e.target.value)} />
        </div>
      )}

      {needsCa && (
        <div className="grid grid-cols-1 gap-3">
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              {certType === 'intermediate-ca' ? 'Root CA Certificate (PEM)' : 'CA Certificate (PEM)'}
            </label>
            <textarea className="input-base font-mono text-xs resize-none" rows={5}
              placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
              value={caPem} onChange={(e) => setCaPem(e.target.value)} />
          </div>
          <div>
            <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
              {certType === 'intermediate-ca' ? 'Root CA Private Key (PEM)' : 'CA Private Key (PEM)'}
            </label>
            <textarea className="input-base font-mono text-xs resize-none" rows={5}
              placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
              value={caKeyPem} onChange={(e) => setCaKeyPem(e.target.value)} />
          </div>
        </div>
      )}

      {error && <p className="text-xs" style={{ color: 'var(--danger)' }}>{error}</p>}
      <button className="btn btn-accent btn-sm flex items-center gap-2" onClick={generate} disabled={loading}>
        {loading && <Loader2 size={12} className="animate-spin" />}{loading ? 'Generating…' : 'Generate Certificate'}
      </button>

      <div className="space-y-3">
        <PemOutput label="Certificate" pem={certOut} filename="certificate.crt" />
        {keyOut && <PemOutput label="Private Key (keep secret!)" pem={keyOut} filename="private.key" />}
        <CliBlock commands={(() => {
          const cnVal = cn.trim() || (certType === 'root-ca' ? 'My Root CA' : certType === 'intermediate-ca' ? 'Intermediate CA' : 'example.com');
          const subj: string[] = [`/CN=${cnVal}`];
          if (org.trim()) subj.push(`O=${org.trim()}`);
          if (ou.trim()) subj.push(`OU=${ou.trim()}`);
          if (country.trim()) subj.push(`C=${country.trim()}`);
          if (state.trim()) subj.push(`ST=${state.trim()}`);
          const subjStr = subj.join('/');
          const sanList = san.split(',').map((s) => s.trim()).filter(Boolean);
          const sanStr = sanList.map((s) => (/^\d+\.\d+\.\d+\.\d+$/.test(s) ? `IP:${s}` : `DNS:${s}`)).join(',');
          const addSan = sanStr ? `\n  -addext "subjectAltName=${sanStr}" \\` : '';
          const d = validDays || '365';
          const newkey = keyAlgo.algo === 'rsa'
            ? `rsa:${keyAlgo.rsaBits}`
            : keyAlgo.algo === 'ec'
              ? `ec -pkeyopt ec_paramgen_curve:${keyAlgo.curve}`
              : keyAlgo.algo;
          if (certType === 'self-signed') {
            return `openssl req -x509 \\\n  -newkey ${newkey} \\\n  -keyout private.key \\\n  -out certificate.crt \\\n  -days ${d} \\\n  -nodes \\${addSan}\n  -subj "${subjStr}"\n\n# Verify:\nopenssl x509 -in certificate.crt -noout -text`;
          }
          if (certType === 'root-ca') {
            return `openssl req -x509 \\\n  -newkey ${newkey} \\\n  -keyout ca.key \\\n  -out ca.crt \\\n  -days ${d} \\\n  -nodes \\\n  -subj "${subjStr}" \\\n  -addext "basicConstraints=critical,CA:TRUE" \\\n  -addext "keyUsage=critical,keyCertSign,cRLSign"\n\n# Verify:\nopenssl x509 -in ca.crt -noout -text`;
          }
          if (certType === 'intermediate-ca') {
            return `# Step 1: Generate intermediate key and CSR\nopenssl req -newkey ${newkey} \\\n  -keyout intermediate.key \\\n  -out intermediate.csr \\\n  -nodes \\\n  -subj "${subjStr}"\n\n# Step 2: Sign with Root CA\nopenssl x509 -req \\\n  -in intermediate.csr \\\n  -CA root-ca.crt \\\n  -CAkey root-ca.key \\\n  -CAcreateserial \\\n  -out intermediate.crt \\\n  -days ${d} \\\n  -sha256 \\\n  -extfile <(printf "basicConstraints=critical,CA:TRUE,pathlen:0\\nkeyUsage=critical,keyCertSign,cRLSign")`;
          }
          if (certType === 'ca-signed') {
            return `openssl x509 -req \\\n  -in request.csr \\\n  -CA ca.crt \\\n  -CAkey ca.key \\\n  -CAcreateserial \\\n  -out certificate.crt \\\n  -days ${d} \\\n  -sha256\n\n# Verify:\nopenssl x509 -in certificate.crt -noout -text`;
          }
          return '';
        })()} />
      </div>
    </div>
  );
}
