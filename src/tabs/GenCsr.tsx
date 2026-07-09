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
  type TrustEntry, type KeyAlgoState, type KeyAlgo,
} from '@/lib/cert-crypto';
import { isNativeCrypto, nativeCert, type NativeSubject, type NativeKeySpec } from '@/lib/nativeCrypto';
import * as forge from 'node-forge';


export function GenCsrTab() {
  const [cn, setCn] = useState('');
  const [org, setOrg] = useState('');
  const [ou, setOu] = useState('');
  const [country, setCountry] = useState('US');
  const [state, setState] = useState('');
  const [locality, setLocality] = useState('');
  const [san, setSan] = useState('');
  const native = isNativeCrypto();
  const [keyAlgo, setKeyAlgo] = useState<KeyAlgoState>({ algo: 'rsa', rsaBits: '2048', curve: 'P-256' });
  const [csrPem, setCsrPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const generate = async () => {
    if (!cn.trim()) { setError('Common Name is required.'); return; }
    setError(''); setLoading(true); setCsrPem(''); setKeyPem('');
    try {
      const sanList = san.split(',').map((s) => s.trim()).filter(Boolean);

      // Native (desktop) path: generate CSR with any algorithm (RSA / EC / Ed).
      if (native) {
        const subject: NativeSubject = {
          common_name: cn.trim(), organization: org.trim(), org_unit: ou.trim(),
          country: country.trim(), state: state.trim(), locality: locality.trim(), san: sanList,
        };
        const out = await nativeCert.generateCsr(subject, toNativeKeySpec(keyAlgo));
        setCsrPem(out.csr_pem); setKeyPem(out.key_pem);
        setLoading(false);
        return;
      }

      const kp = await generateRsaKeyPair(parseInt(keyAlgo.rsaBits));
      const csr = forge.pki.createCertificationRequest();
      csr.publicKey = kp.publicKey;
      const attrs: forge.pki.CertificateField[] = [{ name: 'commonName', value: cn.trim() }];
      if (org.trim()) attrs.push({ name: 'organizationName', value: org.trim() });
      if (ou.trim()) attrs.push({ name: 'organizationalUnitName', value: ou.trim() });
      if (country.trim()) attrs.push({ name: 'countryName', value: country.trim() });
      if (state.trim()) attrs.push({ name: 'stateOrProvinceName', value: state.trim() });
      if (locality.trim()) attrs.push({ name: 'localityName', value: locality.trim() });
      csr.setSubject(attrs);
      // SANs in a CSR require a challengePassword extensions attribute; the CA usually sets them from the cert template.
      // We add them as a CSR extensions request (extensionRequest / OID 1.2.840.113549.1.9.14) if provided.
      if (sanList.length > 0) {
        csr.setAttributes([{
          name: 'extensionRequest',
          extensions: [{ name: 'subjectAltName', altNames: sanList.map((s) => {
            const isIp = /^\d+\.\d+\.\d+\.\d+$/.test(s) || s.startsWith('[');
            return isIp ? { type: 7, ip: s } : { type: 2, value: s };
          }) }],
        }]);
      }
      csr.sign(kp.privateKey, forge.md.sha256.create());
      setCsrPem(forge.pki.certificationRequestToPem(csr));
      setKeyPem(forge.pki.privateKeyToPem(kp.privateKey));
    } catch (e) { setError(String(e)); }
    setLoading(false);
  };

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Generate a Certificate Signing Request and private key. Send the CSR to a CA to obtain a signed certificate.</p>
      <div className="grid grid-cols-2 gap-3">
        <div className="col-span-2">
          <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Common Name (CN) *</label>
          <input className="input-base" value={cn} onChange={(e) => setCn(e.target.value)} placeholder="example.com" />
        </div>
        <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Organization (O)</label>
          <input className="input-base" value={org} onChange={(e) => setOrg(e.target.value)} placeholder="My Company Ltd" /></div>
        <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Org Unit (OU)</label>
          <input className="input-base" value={ou} onChange={(e) => setOu(e.target.value)} placeholder="Engineering" /></div>
        <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Country (2-letter)</label>
          <input className="input-base" value={country} onChange={(e) => setCountry(e.target.value)} placeholder="US" maxLength={2} /></div>
        <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>State / Province</label>
          <input className="input-base" value={state} onChange={(e) => setState(e.target.value)} placeholder="California" /></div>
        <div><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Locality / City</label>
          <input className="input-base" value={locality} onChange={(e) => setLocality(e.target.value)} placeholder="San Francisco" /></div>
        <div className="col-span-2">
          <KeyAlgoSelector value={keyAlgo} onChange={setKeyAlgo} native={native} />
        </div>
        <div className="col-span-2"><label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Subject Alternative Names (comma-separated: DNS or IP)</label>
          <input className="input-base font-mono text-xs" value={san} onChange={(e) => setSan(e.target.value)} placeholder="www.example.com, api.example.com, 192.168.1.1" /></div>
      </div>
      {error && <p className="text-xs" style={{ color: 'var(--danger)' }}>{error}</p>}
      <button className="btn btn-accent btn-sm flex items-center gap-2" onClick={generate} disabled={loading}>
        {loading && <Loader2 size={12} className="animate-spin" />}{loading ? 'Generating…' : 'Generate CSR + Key'}
      </button>
      <div className="space-y-3">
        <PemOutput label="Certificate Signing Request (CSR)" pem={csrPem} filename="request.csr" />
        <PemOutput label="Private Key (keep secret!)" pem={keyPem} filename="private.key" />
        <CliBlock commands={(() => {
          const cnVal = cn.trim() || 'example.com';
          const subj: string[] = [`/CN=${cnVal}`];
          if (org.trim()) subj.push(`O=${org.trim()}`);
          if (ou.trim()) subj.push(`OU=${ou.trim()}`);
          if (country.trim()) subj.push(`C=${country.trim()}`);
          if (state.trim()) subj.push(`ST=${state.trim()}`);
          if (locality.trim()) subj.push(`L=${locality.trim()}`);
          const subjStr = subj.join('/');
          const sanList = san.split(',').map((s) => s.trim()).filter(Boolean);
          const sanStr = sanList.map((s) => (/^\d+\.\d+\.\d+\.\d+$/.test(s) ? `IP:${s}` : `DNS:${s}`)).join(',');
          const addExt = sanStr ? ` \\\n  -addext "subjectAltName=${sanStr}"` : '';
          const keyGen = keyAlgo.algo === 'rsa'
            ? `openssl genrsa -out private.key ${keyAlgo.rsaBits}`
            : keyAlgo.algo === 'ec'
              ? `openssl ecparam -name ${keyAlgo.curve} -genkey -noout -out private.key`
              : `openssl genpkey -algorithm ${keyAlgo.algo} -out private.key`;
          return `# Generate private key (${keyAlgoLabel(keyAlgo)})\n${keyGen}\n\n# Create CSR\nopenssl req -new \\\n  -key private.key \\\n  -subj "${subjStr}"${addExt} \\\n  -out request.csr\n\n# Verify CSR\nopenssl req -in request.csr -noout -text`;
        })()} />
      </div>
    </div>
  );
}
