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


export function CsrKeyTab() {
  const [csrPem, setCsrPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [result, setResult] = useState<{
    match: boolean; detail: string; csrBits: number; keyBits: number;
  } | null>(null);
  const [error, setError] = useState('');

  const check = async () => {
    setError(''); setResult(null);
    try {
      // Determine if EC or RSA by trying forge.
      // NOTE: nativeCert.matchKey expects a certificate PEM, not a CSR — so we
      // always use the JS path here regardless of isNativeCrypto().
      let isEc = false;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let forgeCsr: any = null;
      try {
        forgeCsr = forge.pki.certificationRequestFromPem(csrPem);
      } catch (e) {
        if (!isNonRsaError(e)) throw e;
        isEc = true;
      }

      if (isEc) {
        const csrBits = publicKeyBitsFromCertOrCsr(csrPem);
        const privBits = publicKeyBitsFromPrivateKey(keyPem);
        if (!csrBits) throw new Error('Could not extract the public key from the CSR.');
        if (!privBits) throw new Error('Could not extract a public key from the private key.');
        const match = csrBits === privBits;
        setResult({
          match,
          csrBits: 0,
          keyBits: 0,
          detail: match
            ? 'EC public key embedded in the CSR matches the private key.'
            : 'EC public keys do NOT match — this key did not generate this CSR.',
        });
      } else {
        const privKey = forge.pki.privateKeyFromPem(keyPem);
        const csrMod = getRsaModulus(forgeCsr!.publicKey as forge.pki.PublicKey);
        const keyMod = getRsaModulus(privKey as unknown as forge.pki.PublicKey);
        const match = csrMod.length > 0 && csrMod === keyMod;
        const csrBits = (forgeCsr!.publicKey as forge.pki.rsa.PublicKey).n?.bitLength() ?? 0;
        const keyBits = (privKey as forge.pki.rsa.PrivateKey).n?.bitLength() ?? 0;
        setResult({
          match,
          csrBits,
          keyBits,
          detail: match
            ? 'RSA modulus in CSR matches the private key — the CSR was generated from this key.'
            : 'Moduli do NOT match — this private key did not generate this CSR.',
        });
      }
    } catch (e) { setError(String(e)); }
  };

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Verify that a CSR was created with a specific private key by comparing their embedded public key.
      </p>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
          Certificate Signing Request (PEM)
        </label>
        <textarea
          className="input-base font-mono text-xs resize-none" rows={6}
          placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
          value={csrPem} onChange={(e) => setCsrPem(e.target.value)}
        />
      </div>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
          Private Key (PEM)
        </label>
        <textarea
          className="input-base font-mono text-xs resize-none" rows={6}
          placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...or...&#10;-----BEGIN PRIVATE KEY-----"
          value={keyPem} onChange={(e) => setKeyPem(e.target.value)}
        />
      </div>
      <button className="btn btn-accent btn-sm" onClick={check} disabled={!csrPem.trim() || !keyPem.trim()}>
        Check Match
      </button>
      {error && <p className="text-xs" style={{ color: 'var(--danger)' }}>{error}</p>}
      {result && (
        <div className="space-y-3">
          <MatchBadge
            match={result.match}
            yes="CSR and Private Key MATCH"
            no="CSR and Private Key do NOT match"
          />
          {(result.csrBits > 0 || result.keyBits > 0) && (
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: 'CSR key size', value: `${result.csrBits} bits` },
                { label: 'Private key size', value: `${result.keyBits} bits` },
              ].map(({ label, value }) => (
                <div key={label} className="rounded-lg p-3 text-center" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                  <div className="text-base font-bold" style={{ color: 'var(--accent)' }}>{value}</div>
                  <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{label}</div>
                </div>
              ))}
            </div>
          )}
          <p className="text-xs" style={{ color: 'var(--text-secondary)' }}>{result.detail}</p>
          <CliBlock commands={`# Verify CSR matches private key (compare public keys)\nopenssl req -in request.csr -noout -pubkey > csr_pub.pem\nopenssl pkey -in private.key -pubout > key_pub.pem\ndiff csr_pub.pem key_pub.pem && echo "MATCH" || echo "NO MATCH"\n\n# One-liner (modulus comparison)\necho "CSR:"; openssl req -in request.csr -noout -modulus | md5\necho "KEY:"; openssl rsa -in private.key -noout -modulus | md5`} />
        </div>
      )}
    </div>
  );
}
