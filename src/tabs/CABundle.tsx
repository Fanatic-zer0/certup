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


export function CABundleTab() {
  const [input, setInput] = useState('');
  const [entries, setEntries] = useState<TrustEntry[]>([]);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('');
  const [sortBy, setSortBy] = useState<'index' | 'subject' | 'expiry-asc' | 'expiry-desc' | 'ca-first'>('index');
  const [showOnlyCA, setShowOnlyCA] = useState(false);
  const [expiryWindow, setExpiryWindow] = useState<number | null>(null);
  const now = new Date();

  const parse = () => {
    setError(''); setEntries([]);
    const pems = splitPemCerts(input);
    if (pems.length === 0) { setError('No PEM certificates found. Paste one or more PEM-encoded certificates.'); return; }
    const parsed = pems.map((pem, i) => parseTrustEntry(pem, i));
    setEntries(parsed);
  };

  const dnStr = (m: Record<string, string>) =>
    Object.entries(m).map(([k, v]) => `${k}=${v}`).join(', ');

  const filtered = entries
    .filter((e) => {
      if (showOnlyCA && !e.isCA) return false;
      if (expiryWindow !== null) {
        // show certs expiring within expiryWindow days (including already-expired)
        if (!e.notAfter) return false;
        const diffDays = (e.notAfter.getTime() - now.getTime()) / 86400000;
        if (diffDays > expiryWindow) return false;
      }
      if (filter.trim()) {
        const q = filter.toLowerCase();
        const sub = dnStr(e.subject).toLowerCase();
        const iss = dnStr(e.issuer).toLowerCase();
        const sanStr = e.san.join(' ').toLowerCase();
        if (!sub.includes(q) && !iss.includes(q) && !e.serial.toLowerCase().includes(q) && !sanStr.includes(q) && !e.fingerprints.md5.toLowerCase().replace(/:/g, '').includes(q.replace(/:/g, ''))) return false;
      }
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'subject') return dnStr(a.subject).localeCompare(dnStr(b.subject));
      if (sortBy === 'expiry-asc' || sortBy === 'expiry-desc') {
        const at = a.notAfter?.getTime() ?? 0;
        const bt = b.notAfter?.getTime() ?? 0;
        return sortBy === 'expiry-asc' ? at - bt : bt - at;
      }
      if (sortBy === 'ca-first') {
        if (a.isCA && !b.isCA) return -1;
        if (!a.isCA && b.isCA) return 1;
        return a.index - b.index;
      }
      return a.index - b.index;
    });

  const stats = {
    total: entries.length,
    ca: entries.filter((e) => e.isCA).length,
    selfSigned: entries.filter((e) => e.selfSigned).length,
    expired: entries.filter((e) => e.notAfter && e.notAfter < now).length,
    expiringSoon: entries.filter((e) => {
      if (!e.notAfter || e.notAfter < now) return false;
      return (e.notAfter.getTime() - now.getTime()) < 90 * 86400000;
    }).length,
    parseErrors: entries.filter((e) => !!e.error).length,
  };

  const summaryText = entries.length === 0 ? '' : [
    `Truststore / CA Bundle — ${stats.total} certificate(s)`,
    `CA Certificates: ${stats.ca}`,
    `Self-Signed: ${stats.selfSigned}`,
    `Expired: ${stats.expired}`,
    `Expiring within 90 days: ${stats.expiringSoon}`,
    '',
    ...entries.map((e, i) => {
      const lines: string[] = [`[${i + 1}]${e.alias ? ` [${e.alias}]` : ''} ${dnStr(e.subject) || '(no subject)'}`];
      lines.push(`  Issuer:   ${dnStr(e.issuer) || '(no issuer)'}`);
      lines.push(`  Serial:   ${e.serial}`);
      lines.push(`  Key:      ${e.keyType}${e.keyBits ? ` (${e.keyBits} bits)` : ''}`);
      lines.push(`  Sig Alg:  ${friendlySigAlg(e.sigAlgOid)}`);
      lines.push(`  CA:       ${e.isCA ? 'YES' : 'No'}${e.selfSigned ? '  (Self-Signed)' : ''}`);
      lines.push(`  Not Before: ${e.notBefore?.toUTCString() ?? '(unparsed)'}`);
      lines.push(`  Not After:  ${e.notAfter?.toUTCString() ?? '(unparsed)'}${e.notAfter && e.notAfter < now ? '  ⚠ EXPIRED' : ''}`);
      lines.push(`  SHA-256:  ${e.fingerprints.sha256 || '(unavailable)'}`);
      return lines.join('\n');
    }),
  ].join('\n');

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Paste a PEM CA bundle or truststore to inspect all certificates. For JKS / JCEKS / PKCS#12 keystores, use the <strong>Keystore</strong> tab.
      </p>

      {/* PEM paste */}
      <div>
        <label className="block text-xs font-medium mb-1" style={{ color: 'var(--text-secondary)' }}>
          PEM CA Bundle / Truststore
        </label>
        <textarea
          className="input-base font-mono text-xs resize-none" rows={8}
          placeholder={"-----BEGIN CERTIFICATE-----\n(CA cert 1)\n-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----\n(CA cert 2)\n-----END CERTIFICATE-----"}
          value={input} onChange={(e) => setInput(e.target.value)}
        />
        {error && <p className="text-xs mt-1" style={{ color: 'var(--danger)' }}>{error}</p>}
        <div className="flex items-center gap-2 mt-2">
          <button className="btn btn-accent btn-sm" onClick={parse}>Parse Bundle</button>
          {entries.length > 0 && (
            <button className="btn btn-ghost btn-sm" onClick={() => { setEntries([]); setFilter(''); setShowOnlyCA(false); setExpiryWindow(null); }}>
              Clear
            </button>
          )}
        </div>
      </div>

      {entries.length > 0 && (
        <div className="space-y-4">
          {/* Summary stats */}
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-6">
            {[
              { label: 'Total', value: stats.total, color: 'var(--accent)' },
              { label: 'CA Certs', value: stats.ca, color: 'var(--info, #60a5fa)' },
              { label: 'Self-Signed', value: stats.selfSigned, color: '#a78bfa' },
              { label: 'Expired', value: stats.expired, color: stats.expired > 0 ? 'var(--danger)' : 'var(--text-muted)' },
              { label: 'Exp. ≤90d', value: stats.expiringSoon, color: stats.expiringSoon > 0 ? '#fbbf24' : 'var(--text-muted)' },
              { label: 'Parse Errors', value: stats.parseErrors, color: stats.parseErrors > 0 ? 'var(--danger)' : 'var(--text-muted)' },
            ].map(({ label, value, color }) => (
              <div key={label} className="rounded-lg p-2.5 text-center" style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)' }}>
                <div className="text-base font-bold" style={{ color }}>{value}</div>
                <div className="text-xs mt-0.5" style={{ color: 'var(--text-muted)' }}>{label}</div>
              </div>
            ))}
          </div>

          {/* Toolbar */}
          <div className="flex flex-wrap items-center gap-2">
            <input
              className="input-base text-xs flex-1 min-w-[160px]"
              placeholder="Filter by subject, issuer, SAN, serial, MD5…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <select
              className="input-base text-xs"
              style={{ width: 156 }}
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as typeof sortBy)}
            >
              <option value="index">Sort: Original order</option>
              <option value="subject">Sort: Subject A→Z</option>
              <option value="expiry-asc">Sort: Expiry ↑ soonest</option>
              <option value="expiry-desc">Sort: Expiry ↓ latest</option>
              <option value="ca-first">Sort: CA first</option>
            </select>
            <select
              className="input-base text-xs"
              style={{ width: 148 }}
              value={expiryWindow === null ? '' : String(expiryWindow)}
              onChange={(e) => setExpiryWindow(e.target.value === '' ? null : Number(e.target.value))}
            >
              <option value="">Expiry: all dates</option>
              <option value="-1">Expiry: already expired</option>
              <option value="30">Expiring ≤ 30 days</option>
              <option value="60">Expiring ≤ 60 days</option>
              <option value="90">Expiring ≤ 90 days</option>
              <option value="180">Expiring ≤ 180 days</option>
              <option value="365">Expiring ≤ 1 year</option>
            </select>
            <label className="flex items-center gap-1 text-xs cursor-pointer select-none" style={{ color: 'var(--text-secondary)' }}>
              <input type="checkbox" checked={showOnlyCA} onChange={(e) => setShowOnlyCA(e.target.checked)} />
              CA only
            </label>
            <CopyBtn text={summaryText} label="Copy All" />
          </div>

          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
            Showing {filtered.length} of {entries.length} certificate(s)
          </p>

          {/* Column header */}
          <div
            className="flex items-center gap-0 rounded text-[10px] font-semibold uppercase tracking-wider select-none"
            style={{ background: 'var(--bg-tertiary)', color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}
          >
            <span className="px-2 py-1.5" style={{ width: 36 }}>#</span>
            <span className="flex-1 px-2 py-1.5" style={{ maxWidth: '22%' }}>Name / CN</span>
            <span className="hidden sm:block px-2 py-1.5" style={{ width: '20%' }}>Issuer CN</span>
            <span className="hidden md:block px-2 py-1.5" style={{ width: '17%' }}>SAN</span>
            <span className="px-2 py-1.5" style={{ width: 96 }}>Expiry</span>
            <span className="hidden lg:block px-2 py-1.5" style={{ width: 130 }}>MD5</span>
            <span className="px-2 py-1.5 flex-shrink-0" style={{ minWidth: 80 }}>Status</span>
          </div>

          {/* Certificate rows */}
          <div className="space-y-1">
            {filtered.map((entry) => (
              <TrustEntryCard key={entry.index} entry={entry} now={now} />
            ))}
            {filtered.length === 0 && (
              <p className="text-xs text-center py-6" style={{ color: 'var(--text-muted)' }}>No certificates match the current filter.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
