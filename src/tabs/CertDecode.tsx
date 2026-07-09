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


export function CertDecodeTab() {
  const [input, setInput] = useState('');
  const [error, setError] = useState('');
  const [info, setInfo] = useState<{
    subject: Record<string, string>; issuer: Record<string, string>;
    serial: string; notBefore: string; notAfter: string; san: string[];
    fingerprints: { md5: string; sha1: string; sha256: string; spkiSha256Hex: string; spkiSha256B64: string };
    publicKey: { type: string; bits: number };
    signatureAlg: string; version: number;
    extensions: { name: string; critical: boolean; value: string }[];
  } | null>(null);

  const parse = () => {
    if (!input.trim()) return;
    try {
      try {
        // RSA path — forge handles everything natively
        const cert = forge.pki.certificateFromPem(input);
        const san: string[] = [];
        const ext = cert.getExtension('subjectAltName') as { altNames?: { type: number; value?: string; ip?: string }[] } | null;
        for (const n of ext?.altNames ?? []) {
          if (n.type === 2 && n.value) san.push(`DNS: ${n.value}`);
          else if (n.type === 7 && n.ip) san.push(`IP: ${n.ip}`);
        }
        const rsaPub = cert.publicKey as forge.pki.rsa.PublicKey;
        const spki = spkiSha256FromPem(input);
        setInfo({
          subject: attrMap(cert.subject.attributes), issuer: attrMap(cert.issuer.attributes),
          serial: cert.serialNumber, notBefore: cert.validity.notBefore.toISOString(),
          notAfter: cert.validity.notAfter.toISOString(), san,
          fingerprints: {
            md5: certFingerprint(cert, 'md5'), sha1: certFingerprint(cert, 'sha1'), sha256: certFingerprint(cert, 'sha256'),
            spkiSha256Hex: spki.hex, spkiSha256B64: spki.b64,
          },
          publicKey: { type: 'RSA', bits: rsaPub.n?.bitLength() ?? 0 },
          signatureAlg: cert.siginfo.algorithmOid, version: cert.version + 1,
          extensions: extractForgeExtensions(cert, san),
        });
      } catch (e) {
        if (!isNonRsaError(e)) throw e;
        // Non-RSA cert (EC, Ed25519, etc.) — parse from raw ASN.1
        const raw = parseRawCertFromPem(input);
        const spki = spkiSha256FromPem(input);
        setInfo({
          subject: raw.subject, issuer: raw.issuer,
          serial: raw.serial, notBefore: safeIso(raw.notBefore),
          notAfter: safeIso(raw.notAfter), san: raw.san,
          fingerprints: {
            md5: raw.md5, sha1: raw.sha1, sha256: raw.sha256,
            spkiSha256Hex: spki.hex, spkiSha256B64: spki.b64,
          },
          publicKey: { type: raw.keyType, bits: raw.keyBits },
          signatureAlg: raw.sigAlgOid, version: raw.version,
          extensions: raw.extensions,
        });
      }
      setError('');
    } catch (e) { setError(String(e)); setInfo(null); }
  };

  const now = new Date();
  const expired = info ? new Date(info.notAfter) < now : false;

  const expiryText = (() => {
    if (!info || !info.notAfter) return '(unparsed)';
    const exp = new Date(info.notAfter);
    if (Number.isNaN(exp.getTime())) return '(unparsed)';
    const days = Math.round((exp.getTime() - now.getTime()) / 86400000);
    const rel = expired ? `expired ${Math.abs(days)} day(s) ago` : `expires in ${days} day(s)`;
    return `${exp.toLocaleString()} (${rel})`;
  })();

  const dnToString = (dn: Record<string, string>) =>
    Object.entries(dn).map(([k, v]) => `${k}=${v}`).join(', ') || '(empty)';

  const detailedText = info
    ? [
        '── Subject ──',
        dnToString(info.subject),
        '',
        '── Issuer ──',
        dnToString(info.issuer),
        '',
        '── Properties ──',
        `Version:            v${info.version}`,
        `Serial Number:      ${info.serial}`,
        `Signature Algorithm:${friendlySigAlg(info.signatureAlg)}`,
        `Public Key:         ${info.publicKey.type}${info.publicKey.bits ? ` (${info.publicKey.bits} bits)` : ''}`,
        `Not Before:         ${info.notBefore ? new Date(info.notBefore).toUTCString() : '(unparsed)'}`,
        `Not After:          ${info.notAfter ? new Date(info.notAfter).toUTCString() : '(unparsed)'}${expired ? '  ⚠ EXPIRED' : ''}`,
        `Expiry:             ${expiryText}`,
        '',
        '── Certificate Extensions ──',
        ...(info.extensions.length
          ? info.extensions.map((e) => `${e.name}${e.critical ? ' (critical)' : ''}: ${e.value}`)
          : ['(none)']),
        ...(info.san.length ? ['', '── Subject Alternative Names ──', ...info.san] : []),
        '',
        '── Certificate Fingerprints ──',
        `MD5:              ${info.fingerprints.md5}`,
        `SHA-1:            ${info.fingerprints.sha1}`,
        `SHA-256:          ${info.fingerprints.sha256}`,
        `SPKI SHA256 Hex:  ${info.fingerprints.spkiSha256Hex}`,
        `SPKI SHA256 B64:  ${info.fingerprints.spkiSha256B64}`,
      ].join('\n')
    : '';

  return (
    <div className="space-y-4">
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>PEM Certificate</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={8}
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          value={input} onChange={(e) => setInput(e.target.value)} />
        {error && <p className="text-xs mt-1" style={{ color: 'var(--danger)' }}>{error}</p>}
        <div className="flex items-center gap-2 mt-2">
          <button className="btn btn-accent btn-sm" onClick={parse}>Parse Certificate</button>
          {info && <span className={`badge ${expired ? 'badge-danger' : 'badge-success'}`}>{expired ? 'Expired' : 'Valid'}</span>}
        </div>
      </div>
      {info && (
        <div className="space-y-3">
          <Section title="Subject">
            {Object.keys(info.subject).length
              ? Object.entries(info.subject).map(([k, v]) => <Field key={k} label={k} value={v} />)
              : <Field label="—" value="(no subject fields)" />}
          </Section>
          <Section title="Issuer">
            {Object.keys(info.issuer).length
              ? Object.entries(info.issuer).map(([k, v]) => <Field key={k} label={k} value={v} />)
              : <Field label="—" value="(no issuer fields)" />}
          </Section>
          <Section title="Properties">
            <Field label="Version" value={`v${info.version}`} />
            <Field label="Serial" value={info.serial} />
            <Field label="Signature Alg" value={friendlySigAlg(info.signatureAlg)} />
            <Field label="Public Key" value={`${info.publicKey.type}${info.publicKey.bits ? ` (${info.publicKey.bits} bits)` : ''}`} />
            <Field label="Not Before" value={info.notBefore ? new Date(info.notBefore).toLocaleString() : '(unparsed)'} />
            <Field label="Not After" value={`${info.notAfter ? new Date(info.notAfter).toLocaleString() : '(unparsed)'}${expired ? '  ⚠ EXPIRED' : ''}`} />
            <Field label="Expiry" value={expiryText} />
          </Section>
          <Section title="Certificate Extensions">
            {info.extensions.length
              ? info.extensions.map((e, i) => <Field key={i} label={`${e.name}${e.critical ? ' *' : ''}`} value={e.value} />)
              : <Field label="—" value="(none)" />}
            {info.san.map((s, i) => <Field key={`san-${i}`} label={i === 0 ? 'Subject Alt Name' : ''} value={s} />)}
          </Section>
          <Section title="Certificate Fingerprints">
            <Field label="MD5" value={info.fingerprints.md5} />
            <Field label="SHA-1" value={info.fingerprints.sha1} />
            <Field label="SHA-256" value={info.fingerprints.sha256} />
            <Field label="SPKI SHA256 Hex" value={info.fingerprints.spkiSha256Hex || '(unavailable)'} />
            <Field label="SPKI SHA256 Base64" value={info.fingerprints.spkiSha256B64 || '(unavailable)'} />
          </Section>
          <Section title="Certificate Detailed Information">
            <div className="py-2 flex justify-end"><CopyBtn text={detailedText} /></div>
            <pre className="text-xs font-mono whitespace-pre-wrap break-all pb-3" style={{ color: 'var(--text-primary)' }}>{detailedText}</pre>
          </Section>
        </div>
      )}
    </div>
  );
}
