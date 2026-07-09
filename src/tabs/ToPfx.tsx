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


export function ToPfxTab() {
  const [certPem, setCertPem] = useState('');
  const [keyPem, setKeyPem] = useState('');
  const [chainPem, setChainPem] = useState('');
  const [password, setPassword] = useState('');
  const [friendlyName, setFriendlyName] = useState('');
  const [error, setError] = useState('');
  const [ready, setReady] = useState(false);
  const [pfxBytes, setPfxBytes] = useState<Uint8Array | null>(null);

  const build = () => {
    setError(''); setReady(false); setPfxBytes(null);
    (async () => {
    try {
      if (!certPem.trim()) { setError('Certificate is required.'); return; }
      if (!keyPem.trim()) { setError('Private key is required.'); return; }

      // Native (desktop) path: OpenSSL bundles cert + key of ANY algorithm (EC/Ed).
      if (isNativeCrypto()) {
        const b64 = await nativeCert.toPkcs12(certPem, keyPem, chainPem, password, friendlyName.trim());
        const bin = atob(b64);
        const bytes = Uint8Array.from(bin, (c) => c.charCodeAt(0));
        setPfxBytes(bytes);
        setReady(true);
        return;
      }

      const cert = forge.pki.certificateFromPem(certPem);
      const key = forge.pki.privateKeyFromPem(keyPem);
      const chain: forge.pki.Certificate[] = [];
      if (chainPem.trim()) {
        const pems = splitPemCerts(chainPem);
        for (const p of pems) chain.push(forge.pki.certificateFromPem(p));
      }
      const p12Asn1 = forge.pkcs12.toPkcs12Asn1(
        key, [cert, ...chain], password,
        { algorithm: '3des', friendlyName: friendlyName.trim() || undefined }
      );
      const p12Der = forge.asn1.toDer(p12Asn1).bytes();
      const bytes = Uint8Array.from(p12Der, (c) => c.charCodeAt(0));
      setPfxBytes(bytes);
      setReady(true);
    } catch (e) { setError(String(e)); }
    })();
  };

  const download = () => {
    if (!pfxBytes) return;
    binaryDownload(pfxBytes, `${friendlyName.trim() || 'certificate'}.pfx`, 'application/x-pkcs12');
  };

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Bundle a certificate, private key, and optional chain into a PKCS#12 (.pfx / .p12) file. Used by IIS, Windows, Java keystores, and many other systems.
      </p>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Certificate (PEM) *</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={5}
          placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
          value={certPem} onChange={(e) => setCertPem(e.target.value)} />
      </div>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Private Key (PEM) *</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={5}
          placeholder="-----BEGIN RSA PRIVATE KEY-----&#10;...&#10;-----END PRIVATE KEY-----"
          value={keyPem} onChange={(e) => setKeyPem(e.target.value)} />
      </div>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Certificate Chain — intermediates + root (PEM, optional)</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={5}
          placeholder={"-----BEGIN CERTIFICATE-----\n(intermediate)\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\n(root CA)\n-----END CERTIFICATE-----"}
          value={chainPem} onChange={(e) => setChainPem(e.target.value)} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Friendly Name (alias)</label>
          <input className="input-base" value={friendlyName} onChange={(e) => setFriendlyName(e.target.value)} placeholder="my-cert" />
        </div>
        <div>
          <label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>Password (leave blank for no password)</label>
          <input className="input-base" type="password" autoComplete="new-password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="optional" />
        </div>
      </div>
      {error && <p className="text-xs" style={{ color: 'var(--danger)' }}>{error}</p>}
      <div className="flex gap-2 items-center flex-wrap">
        <button className="btn btn-accent btn-sm" onClick={build}>Build PFX</button>
        {ready && (
          <button className="btn btn-ghost btn-sm flex items-center gap-1" onClick={download}>
            <Download size={12} />Download .pfx
          </button>
        )}
        {ready && <span className="text-xs" style={{ color: 'var(--success)' }}>✓ PFX ready — {pfxBytes?.length} bytes</span>}
      </div>
      <CliBlock commands={(() => {
        const outName = (friendlyName.trim() || 'certificate') + '.pfx';
        const hasChain = chainPem.trim() !== '';
        const chainPart = hasChain ? `\n  -certfile chain.pem \\` : '';
        const namePart = friendlyName.trim() ? `\n  -name "${friendlyName.trim()}" \\` : '';
        const passPart = password ? `\n  -passout pass:yourpassword` : `\n  -passout pass:`;
        return `# Bundle cert + key into PFX\nopenssl pkcs12 -export \\\n  -in certificate.crt \\\n  -inkey private.key \\${chainPart}\n  -out ${outName} \\${namePart}${passPart}\n\n# Verify PFX contents:\nopenssl pkcs12 -in ${outName} -noout -info`;
      })()} />
    </div>
  );
}
