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


export function CsrDecodeTab() {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState<{
    subject: Record<string, string>;
    publicKey: { type: string; bits: number };
    signatureAlg: string;
    sigValid: boolean | null;
    sans: string[];
    extensions: { name: string; value: string }[];
    fingerprints: { md5: string; sha1: string; sha256: string };
    raw: string;
  } | null>(null);

  const parse = () => {
    setError(''); setInfo(null);
    try {
      const pem = input.trim();
      // Fingerprints from raw DER
      const b64 = pem.replace(/-----[^-]+-----/g, '').replace(/\s/g, '');
      const der = forge.util.decode64(b64);
      const md5   = forge.md.md5.create().update(der).digest().toHex().replace(/../g, h => h.toUpperCase() + ':').slice(0, -1);
      const sha1  = forge.md.sha1.create().update(der).digest().toHex().replace(/../g, h => h.toUpperCase() + ':').slice(0, -1);
      const sha256 = forge.md.sha256.create().update(der).digest().toHex().replace(/../g, h => h.toUpperCase() + ':').slice(0, -1);

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let csr: any;
      try {
        csr = forge.pki.certificationRequestFromPem(pem);
      } catch (e) {
        if (!isNonRsaError(e)) throw e;
        throw new Error('EC / non-RSA CSRs are supported via the desktop app only.');
      }

      const subject = attrMap(csr.subject.attributes);

      // Signature validity
      let sigValid: boolean | null = null;
      try { sigValid = (csr as any).verify((csr as any).publicKey); } catch { sigValid = null; }

      // Signature algorithm OID
      const signatureAlg = (csr as any).siginfo?.algorithmOid ?? '';

      // Public key
      const rsaPub = csr.publicKey as forge.pki.rsa.PublicKey;
      const pubKeyBits = rsaPub?.n?.bitLength() ?? 0;
      const pubKeyType = pubKeyBits ? 'RSA' : 'Unknown';

      // SANs and extensions from extensionRequest attribute
      const sans: string[] = [];
      const extensions: { name: string; value: string }[] = [];
      const extReqAttr = (csr as any).getAttribute({ name: 'extensionRequest' });
      for (const ext of extReqAttr?.extensions ?? []) {
        if (ext.name === 'subjectAltName') {
          for (const n of ext.altNames ?? []) {
            if (n.type === 2 && n.value) sans.push(`DNS: ${n.value}`);
            else if (n.type === 7 && n.ip) sans.push(`IP: ${n.ip}`);
            else if (n.type === 1 && n.value) sans.push(`Email: ${n.value}`);
          }
          extensions.push({ name: 'Subject Alt Name', value: sans.join(', ') || '(none)' });
        } else if (ext.name === 'keyUsage') {
          const KU_LABEL: Record<string, string> = {
            digitalSignature: 'Digital Signature', nonRepudiation: 'Non Repudiation',
            keyEncipherment: 'Key Encipherment', dataEncipherment: 'Data Encipherment',
            keyAgreement: 'Key Agreement', keyCertSign: 'Certificate Sign',
            cRLSign: 'CRL Sign',
          };
          const used = Object.keys(KU_LABEL).filter((k) => (ext as any)[k]).map((k) => KU_LABEL[k]);
          extensions.push({ name: 'Key Usage', value: used.join(', ') || '(none)' });
        } else if (ext.name === 'extKeyUsage') {
          const EKU: Record<string, string> = {
            serverAuth: 'TLS Server Auth', clientAuth: 'TLS Client Auth',
            codeSigning: 'Code Signing', emailProtection: 'Email Protection',
          };
          const used = Object.keys(EKU).filter((k) => (ext as any)[k]).map((k) => EKU[k]);
          extensions.push({ name: 'Extended Key Usage', value: used.join(', ') || '(none)' });
        } else if (ext.name === 'basicConstraints') {
          extensions.push({ name: 'Basic Constraints', value: `CA: ${(ext as any).cA ? 'TRUE' : 'FALSE'}` });
        } else {
          extensions.push({ name: ext.name ?? ext.id, value: '(present)' });
        }
      }

      // Detailed text block
      const dnStr = Object.entries(subject).map(([k, v]) => `${k}=${v}`).join(', ');
      const raw = [
        '── Subject ──',
        dnStr || '(empty)',
        '',
        '── Public Key ──',
        `${pubKeyType}${pubKeyBits ? ` (${pubKeyBits} bits)` : ''}`,
        '',
        '── Signature Algorithm ──',
        friendlySigAlg(signatureAlg),
        `Self-signature: ${sigValid === null ? '(could not verify)' : sigValid ? 'Valid ✓' : 'Invalid ✗'}`,
        '',
        ...(sans.length ? ['── Subject Alternative Names ──', ...sans, ''] : []),
        ...(extensions.length ? ['── Requested Extensions ──', ...extensions.map((e) => `${e.name}: ${e.value}`), ''] : []),
        '── Fingerprints ──',
        `MD5:    ${md5}`,
        `SHA-1:  ${sha1}`,
        `SHA-256: ${sha256}`,
      ].join('\n');

      setInfo({ subject, publicKey: { type: pubKeyType, bits: pubKeyBits }, signatureAlg, sigValid, sans, extensions, fingerprints: { md5, sha1, sha256 }, raw });
    } catch (e) { setError(String(e)); }
  };

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>PEM Certificate Signing Request (CSR)</label>
        <textarea
          className="input-base font-mono text-xs resize-none" rows={8}
          placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
          value={input} onChange={(e) => setInput(e.target.value)}
        />
        {error && <p className="text-xs mt-1" style={{ color: 'var(--danger)' }}>{error}</p>}
        <div className="flex items-center gap-2 mt-2">
          <button className="btn btn-accent btn-sm" onClick={parse} disabled={!input.trim()}>Parse CSR</button>
          {info && (
            <span className={`badge ${info.sigValid === false ? 'badge-danger' : 'badge-success'}`}>
              {info.sigValid === false ? 'Signature Invalid' : info.sigValid ? 'Signature Valid' : 'Signature Unverified'}
            </span>
          )}
        </div>
      </div>

      {info && (
        <div className="space-y-3">
          <Section title="Subject">
            {Object.keys(info.subject).length
              ? Object.entries(info.subject).map(([k, v]) => <Field key={k} label={k} value={v} />)
              : <Field label="—" value="(no subject fields)" />}
          </Section>

          <Section title="Public Key">
            <Field label="Type" value={info.publicKey.type} />
            <Field label="Size" value={info.publicKey.bits ? `${info.publicKey.bits} bits` : '(unknown)'} />
            <Field label="Signature Alg" value={friendlySigAlg(info.signatureAlg)} />
            <Field
              label="Self-Signature"
              value={
                info.sigValid === null ? '(could not verify)' :
                info.sigValid ? '✓ Valid — CSR was self-signed with the matching private key' :
                '✗ Invalid — signature does not match the embedded public key'
              }
            />
          </Section>

          {info.sans.length > 0 && (
            <Section title="Subject Alternative Names">
              {info.sans.map((s, i) => <Field key={i} label={i === 0 ? 'SAN' : ''} value={s} />)}
            </Section>
          )}

          {info.extensions.length > 0 && (
            <Section title="Requested Extensions">
              {info.extensions.map((e, i) => <Field key={i} label={e.name} value={e.value} />)}
            </Section>
          )}

          <Section title="CSR Fingerprints">
            <Field label="MD5"    value={info.fingerprints.md5} />
            <Field label="SHA-1"  value={info.fingerprints.sha1} />
            <Field label="SHA-256" value={info.fingerprints.sha256} />
          </Section>

          <Section title="Full Details">
            <div className="py-2 flex justify-end"><CopyBtn text={info.raw} /></div>
            <pre className="text-xs font-mono whitespace-pre-wrap break-all pb-3" style={{ color: 'var(--text-primary)' }}>{info.raw}</pre>
          </Section>

          <CliBlock commands={`# View CSR details\nopenssl req -in request.csr -noout -text\n\n# Verify CSR self-signature\nopenssl req -in request.csr -verify -noout\n\n# Show just the subject\nopenssl req -in request.csr -noout -subject\n\n# Show fingerprint (SHA-256)\nopenssl req -in request.csr -noout -fingerprint -sha256`} />
        </div>
      )}
    </div>
  );
}
