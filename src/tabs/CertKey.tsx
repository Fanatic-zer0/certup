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


export function CertKeyTab() {
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [result, setResult] = useState<{ match: boolean; certBits: number; keyBits: number; detail: string } | null>(null);
  const [error, setError] = useState('');

  const check = async () => {
    setError(''); setResult(null);
    try {
      // Native (desktop) path: OpenSSL compares public keys for ANY algorithm.
      if (isNativeCrypto()) {
        const m = await nativeCert.matchKey(certPem, keyPem);
        // bit size is informational; derive it where the JS parsers can.
        let bits = 0;
        try { bits = (forge.pki.certificateFromPem(certPem).publicKey as forge.pki.rsa.PublicKey).n?.bitLength() ?? 0; }
        catch { try { bits = parseRawCertFromPem(certPem).keyBits; } catch { /* ignore */ } }
        setResult({ match: m.matched, certBits: bits, keyBits: bits, detail: m.detail });
        return;
      }

      let forgeCert: forge.pki.Certificate | null = null;
      let isEc = false;
      let ecBits = 0;
      try {
        forgeCert = forge.pki.certificateFromPem(certPem);
      } catch (e) {
        if (!isNonRsaError(e)) throw e;
        const raw = parseRawCertFromPem(certPem);
        isEc = true;
        ecBits = raw.keyBits;
      }

      if (isEc) {
        // Compare the public key embedded in the cert (SPKI) with the one embedded
        // in the private key. Works for both SEC1 (-----BEGIN EC PRIVATE KEY-----)
        // and PKCS#8 (-----BEGIN PRIVATE KEY-----) without curve guessing.
        const certBits = publicKeyBitsFromCertOrCsr(certPem);
        const keyBits = publicKeyBitsFromPrivateKey(keyPem);
        if (!certBits) throw new Error('Could not extract the public key from the certificate.');
        if (!keyBits) throw new Error('Could not extract a public key from the private key. Ensure it is an EC key in SEC1 (-----BEGIN EC PRIVATE KEY-----) or PKCS#8 (-----BEGIN PRIVATE KEY-----) format.');
        const match = certBits === keyBits;
        setResult({
          match, certBits: ecBits, keyBits: ecBits,
          detail: match ? 'EC public key in the certificate matches the private key.' : 'EC public keys do NOT match — this key did not generate this certificate.',
        });
      } else {
        const privKey = forge.pki.privateKeyFromPem(keyPem);
        const certMod = getRsaModulus(forgeCert!.publicKey);
        const keyMod = getRsaModulus(privKey as unknown as forge.pki.PublicKey);
        const match = certMod.length > 0 && certMod === keyMod;
        const certPub = forgeCert!.publicKey as forge.pki.rsa.PublicKey;
        const keyPriv = privKey as forge.pki.rsa.PrivateKey;
        setResult({
          match,
          certBits: certPub.n?.bitLength() ?? 0,
          keyBits: keyPriv.n?.bitLength() ?? 0,
          detail: match ? 'Public key modulus in certificate matches the private key.' : 'Moduli do NOT match — this key did not generate this certificate.',
        });
      }
    } catch (e) { setError(String(e)); }
  };

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Verifies that a certificate's public key modulus matches the corresponding private key.
      </p>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Certificate (PEM)</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={6}
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          value={certPem} onChange={(e) => setCertPem(e.target.value)} />
      </div>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Private Key (PEM)</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={6}
          placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...or...&#10;-----BEGIN PRIVATE KEY-----"
          value={keyPem} onChange={(e) => setKeyPem(e.target.value)} />
      </div>
      <button className="btn btn-accent btn-sm" onClick={check} disabled={!certPem.trim() || !keyPem.trim()}>
        Check Match
      </button>
      {error && <p className="text-xs" style={{ color: 'var(--danger)' }}>{error}</p>}
      {result && (
        <div className="space-y-3">
          <MatchBadge match={result.match} yes="Certificate and Private Key MATCH" no="Certificate and Private Key do NOT match" />
          <div className="grid grid-cols-2 gap-3">
            {[{ label: 'Certificate key size', value: `${result.certBits} bits` }, { label: 'Private key size', value: `${result.keyBits} bits` }].map(({ label, value }) => (
              <div key={label} className="rounded-lg p-3 text-center" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                <div className="text-base font-bold" style={{ color: 'var(--accent)' }}>{value}</div>
                <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{label}</div>
              </div>
            ))}
          </div>
          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{result.detail}</p>
        </div>
      )}
    </div>
  );
}
