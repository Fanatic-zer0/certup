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


export function ChainVerifyTab() {
  const [chainPem, setChainPem] = useState('');
  const [links, setLinks] = useState<ChainLink[]>([]);
  const [error, setError] = useState('');
  const [overallOk, setOverallOk] = useState<boolean | null>(null);

  const verify = async () => {
    setError(''); setLinks([]); setOverallOk(null);
    try {
      const pems = splitPemCerts(chainPem);
      if (pems.length === 0) throw new Error('No certificates found. Paste one or more PEM certificates.');

      const now = new Date();

      // Native (desktop) path: OpenSSL verifies ANY curve incl. secp256k1 / brainpool / EdDSA.
      if (isNativeCrypto()) {
        const native = await nativeCert.verifyChain(chainPem);
        const result: ChainLink[] = native.map((l) => ({
          index: l.index, subject: l.subject, issuer: l.issuer,
          notAfter: l.not_after, selfSigned: l.self_signed,
          issuerChainOk: l.issuer_chain_ok, signatureOk: l.signature_ok,
        }));
        setLinks(result);
        setOverallOk(result.every((l) => l.issuerChainOk && l.signatureOk !== false && new Date(l.notAfter) >= now));
        return;
      }

      // Parse each cert — use raw ASN.1 fallback for non-RSA (EC, Ed25519)
      type FlexCert = { subject: Record<string, string>; issuer: Record<string, string>; notAfter: Date; forge: forge.pki.Certificate | null; pem: string };
      const flexCerts: FlexCert[] = pems.map((p) => {
        try {
          const cert = forge.pki.certificateFromPem(p);
          return { subject: attrMap(cert.subject.attributes), issuer: attrMap(cert.issuer.attributes), notAfter: cert.validity.notAfter, forge: cert, pem: p };
        } catch (e) {
          if (!isNonRsaError(e)) throw e;
          const raw = parseRawCertFromPem(p);
          return { subject: raw.subject, issuer: raw.issuer, notAfter: raw.notAfter ?? new Date(NaN), forge: null, pem: p };
        }
      });

      const toStr = (m: Record<string, string>) => Object.entries(m).map(([k, v]) => `${k}=${v}`).join(', ');
      const result: ChainLink[] = await Promise.all(flexCerts.map(async (fc, i) => {
        const selfSigned = toStr(fc.subject) === toStr(fc.issuer);
        let issuerChainOk = selfSigned;
        if (!selfSigned && i + 1 < flexCerts.length) {
          issuerChainOk = toStr(fc.issuer) === toStr(flexCerts[i + 1].subject);
        }
        // Determine the issuing certificate (self for roots, next in chain otherwise)
        const issuer = selfSigned ? fc : (i + 1 < flexCerts.length ? flexCerts[i + 1] : null);
        let signatureOk: boolean | null = null;
        if (issuer) {
          if (fc.forge && issuer.forge) {
            // RSA path via forge
            try { signatureOk = issuer.forge.verify(fc.forge); } catch { signatureOk = null; }
          } else {
            // EC / non-RSA path via WebCrypto
            signatureOk = await verifyEcCertSignature(fc.pem, issuer.pem);
          }
        }
        return {
          index: i, subject: toStr(fc.subject), issuer: toStr(fc.issuer),
          notAfter: safeIso(fc.notAfter), selfSigned,
          issuerChainOk, signatureOk,
        };
      }));
      setLinks(result);
      const allOk = result.every((l) => l.issuerChainOk && l.signatureOk !== false && new Date(l.notAfter) >= now);
      setOverallOk(allOk);
    } catch (e) { setError(String(e)); }
  };

  const now = new Date();

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Paste the full certificate chain (leaf first, then intermediates, then root CA). Each cert must be PEM encoded.
      </p>
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>Certificate Chain (PEM — one or more certs)</label>
        <textarea className="input-base font-mono text-xs resize-none" rows={10}
          placeholder={"-----BEGIN CERTIFICATE-----\n(leaf cert)\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\n(intermediate)\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\n(root CA)\n-----END CERTIFICATE-----"}
          value={chainPem} onChange={(e) => setChainPem(e.target.value)} />
      </div>
      <button className="btn btn-accent btn-sm" onClick={verify} disabled={!chainPem.trim()}>Verify Chain</button>
      {error && <p className="text-xs" style={{ color: 'var(--danger)' }}>{error}</p>}
      {links.length > 0 && (
        <div className="space-y-3">
          <MatchBadge match={overallOk!}
            yes={`Chain is valid (${links.length} certificate${links.length > 1 ? 's' : ''})`}
            no="Chain has issues — see details below" />
          {links.map((link) => {
            const expired = new Date(link.notAfter) < now;
            return (
              <div key={link.index} className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
                <div className="flex items-center gap-2 px-3 py-2" style={{ background: 'var(--bg-secondary)' }}>
                  <span className="text-xs font-bold px-1.5 py-0.5 rounded" style={{ background: 'var(--accent)', color: 'white' }}>
                    {link.index === 0 ? 'Leaf' : link.selfSigned ? 'Root CA' : `Intermediate ${link.index}`}
                  </span>
                  {expired && <span className="badge badge-danger text-xs">Expired</span>}
                  {link.selfSigned && <span className="badge badge-info text-xs">Self-signed</span>}
                </div>
                <div className="px-3">
                  <Field label="Subject" value={link.subject} />
                  <Field label="Issuer" value={link.issuer} />
                  <Field label="Not After" value={`${new Date(link.notAfter).toLocaleString()}${expired ? ' ⚠' : ''}`} />
                  <div className="flex gap-4 py-2 text-xs">
                    <span className="flex items-center gap-1">
                      {link.issuerChainOk ? <CheckCircle size={11} style={{ color: 'var(--success)' }} /> : <XCircle size={11} style={{ color: 'var(--danger)' }} />}
                      <span style={{ color: 'var(--text-secondary)' }}>Issuer chain</span>
                    </span>
                    {link.signatureOk !== null && (
                      <span className="flex items-center gap-1">
                        {link.signatureOk ? <CheckCircle size={11} style={{ color: 'var(--success)' }} /> : <XCircle size={11} style={{ color: 'var(--danger)' }} />}
                        <span style={{ color: 'var(--text-secondary)' }}>Signature</span>
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
