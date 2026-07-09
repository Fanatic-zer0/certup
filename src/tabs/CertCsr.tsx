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


export function CertCsrTab() {
  const [certPem, setCertPem] = useState('');
  const [csrPem, setCsrPem] = useState('');
  const [result, setResult] = useState<{
    modulusMatch: boolean; subjectMatch: boolean;
    certSubject: string; csrSubject: string;
  } | null>(null);
  const [error, setError] = useState('');

  const check = () => {
    setError(''); setResult(null);
    (async () => {
    try {
      // Native (desktop) path: OpenSSL compares public keys for ANY algorithm.
      if (isNativeCrypto()) {
        let nativeCertSub: Record<string, string>;
        try { nativeCertSub = attrMap(forge.pki.certificateFromPem(certPem).subject.attributes); }
        catch (e) { if (!isNonRsaError(e)) throw e; nativeCertSub = parseRawCertFromPem(certPem).subject; }
        const nativeCsr = forge.pki.certificationRequestFromPem(csrPem);
        const nativeCsrSub = attrMap(nativeCsr.subject.attributes);
        const m = await nativeCert.matchCsr(certPem, csrPem);
        const cStr = Object.entries(nativeCertSub).map(([k, v]) => `${k}=${v}`).join(', ');
        const rStr = Object.entries(nativeCsrSub).map(([k, v]) => `${k}=${v}`).join(', ');
        setResult({ modulusMatch: m.matched, subjectMatch: cStr === rStr, certSubject: cStr, csrSubject: rStr });
        return;
      }

      // Parse cert — fallback to raw ASN.1 for EC/non-RSA
      let certSub: Record<string, string>;
      let certSpkiBitStr = '';
      let isEc = false;
      let forgeCert: forge.pki.Certificate | null = null;
      try {
        forgeCert = forge.pki.certificateFromPem(certPem);
        certSub = attrMap(forgeCert.subject.attributes);
      } catch (e) {
        if (!isNonRsaError(e)) throw e;
        isEc = true;
        const raw = parseRawCertFromPem(certPem);
        certSub = raw.subject;
        certSpkiBitStr = publicKeyBitsFromCertOrCsr(certPem);
      }

      const csr = forge.pki.certificationRequestFromPem(csrPem);
      let modulusMatch: boolean;

      if (isEc) {
        // Compare raw EC public key bit strings from cert and CSR
        const csrSpkiBitStr = publicKeyBitsFromCertOrCsr(csrPem);
        modulusMatch = certSpkiBitStr.length > 0 && certSpkiBitStr === csrSpkiBitStr;
      } else {
        try { if (!csr.verify()) throw new Error('CSR signature is invalid'); } catch (e) { if (!isNonRsaError(e)) throw e; }
        const certMod = getRsaModulus(forgeCert!.publicKey);
        const csrMod = getRsaModulus(csr.publicKey as forge.pki.PublicKey);
        modulusMatch = certMod.length > 0 && certMod === csrMod;
      }

      const csrSub = attrMap(csr.subject.attributes);
      const certSubStr = Object.entries(certSub).map(([k, v]) => `${k}=${v}`).join(', ');
      const csrSubStr = Object.entries(csrSub).map(([k, v]) => `${k}=${v}`).join(', ');
      setResult({ modulusMatch, subjectMatch: certSubStr === csrSubStr, certSubject: certSubStr, csrSubject: csrSubStr });
    } catch (e) { setError(String(e)); }
    })();
  };

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Verifies that a certificate was issued from a given CSR — checks public key and subject match.
      </p>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Certificate (PEM)</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={5}
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          value={certPem} onChange={(e) => setCertPem(e.target.value)} />
      </div>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>CSR / Certificate Signing Request (PEM)</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={5}
          placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
          value={csrPem} onChange={(e) => setCsrPem(e.target.value)} />
      </div>
      <button className="btn btn-accent btn-sm" onClick={check} disabled={!certPem.trim() || !csrPem.trim()}>
        Check Match
      </button>
      {error && <p className="text-xs" style={{ color: 'var(--danger)' }}>{error}</p>}
      {result && (
        <div className="space-y-3">
          <MatchBadge match={result.modulusMatch && result.subjectMatch}
            yes="Certificate was issued from this CSR" no="Certificate does NOT match this CSR" />
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-xs">
              {result.modulusMatch ? <CheckCircle size={13} style={{ color: 'var(--success)' }} /> : <XCircle size={13} style={{ color: 'var(--danger)' }} />}
              <span style={{ color: 'var(--text-primary)' }}>Public key modulus {result.modulusMatch ? 'matches' : 'does NOT match'}</span>
            </div>
            <div className="flex items-center gap-2 text-xs">
              {result.subjectMatch ? <CheckCircle size={13} style={{ color: 'var(--success)' }} /> : <XCircle size={13} style={{ color: 'var(--danger)' }} />}
              <span style={{ color: 'var(--text-primary)' }}>Subject DN {result.subjectMatch ? 'matches' : 'does NOT match'}</span>
            </div>
          </div>
          {!result.subjectMatch && (
            <div className="space-y-1 text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>
              <p><span style={{ color: 'var(--text-muted)' }}>Cert subject: </span>{result.certSubject}</p>
              <p><span style={{ color: 'var(--text-muted)' }}>CSR subject:  </span>{result.csrSubject}</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
