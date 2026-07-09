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


export function KeystoreTab() {
  const [entries, setEntries] = useState<TrustEntry[]>([]);
  const [error, setError] = useState('');
  const [ksFileName, setKsFileName] = useState('');
  const [ksPassword, setKsPassword] = useState('');
  const [filter, setFilter] = useState('');
  const [sortBy, setSortBy] = useState<'index' | 'subject' | 'expiry-asc' | 'expiry-desc' | 'ca-first'>('index');
  const [expiryWindow, setExpiryWindow] = useState<number | null>(null);
  const now = new Date();

  const handleKeystoreFile = (file: File) => {
    setError(''); setEntries([]); setKsFileName(file.name);
    const reader = new FileReader();
    reader.onload = (e) => {
      try {
        const buf = e.target!.result as ArrayBuffer;
        const firstByte = new Uint8Array(buf)[0];
        const certs = firstByte === 0x30
          ? parsePkcs12Binary(buf, ksPassword)
          : parseJksBinary(buf);
        if (certs.length === 0) { setError('No X.509 certificates found in the keystore.'); return; }
        setEntries(certs.map(({ alias, pem }, i) => parseTrustEntry(pem, i, alias)));
      } catch (err) { setError(String(err)); }
    };
    reader.onerror = () => setError('Failed to read the file.');
    reader.readAsArrayBuffer(file);
  };

  const dnStr = (m: Record<string, string>) =>
    Object.entries(m).map(([k, v]) => `${k}=${v}`).join(', ') || '(empty)';

  const filtered = entries
    .filter((e) => {
      if (expiryWindow !== null) {
        if (!e.notAfter) return false;
        const diffDays = (e.notAfter.getTime() - now.getTime()) / 86400000;
        if (diffDays > expiryWindow) return false;
      }
      if (filter.trim()) {
        const q = filter.toLowerCase();
        const sub = dnStr(e.subject).toLowerCase();
        const iss = dnStr(e.issuer).toLowerCase();
        const sanStr = e.san.join(' ').toLowerCase();
        if (!sub.includes(q) && !iss.includes(q) && !e.serial.toLowerCase().includes(q) && !sanStr.includes(q) && !(e.alias ?? '').toLowerCase().includes(q)) return false;
      }
      return true;
    })
    .sort((a, b) => {
      if (sortBy === 'subject') return dnStr(a.subject).localeCompare(dnStr(b.subject));
      if (sortBy === 'expiry-asc' || sortBy === 'expiry-desc') {
        const at = a.notAfter?.getTime() ?? 0, bt = b.notAfter?.getTime() ?? 0;
        return sortBy === 'expiry-asc' ? at - bt : bt - at;
      }
      if (sortBy === 'ca-first') { if (a.isCA && !b.isCA) return -1; if (!a.isCA && b.isCA) return 1; }
      return a.index - b.index;
    });

  return (
    <div className="space-y-4">
      <p className="text-xs" style={{ color: 'var(--text-muted)' }}>
        Upload a <strong>JKS / JCEKS</strong> Java KeyStore (magic <code>FEEDFEED</code>) or a <strong>PKCS#12 / PFX</strong> file
        (Java 9+ default — <code>.jks</code>, <code>.p12</code>, <code>.pfx</code>).
        Certificates are stored unencrypted in JKS; PKCS#12 needs a password only for MAC verification (Java default: <code>changeit</code>).
      </p>

      <div className="rounded-lg overflow-hidden" style={{ border: '1px solid var(--border)' }}>
        <div className="px-3 py-2 text-xs font-semibold" style={{ background: 'var(--bg-secondary)', color: 'var(--accent)' }}>
          Upload Keystore File
        </div>
        <div className="px-3 py-3 space-y-3">
          <div className="grid gap-2" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div>
              <label className="block text-xs mb-1" style={{ color: 'var(--text-secondary)' }}>
                Keystore Password <span style={{ color: 'var(--text-muted)' }}>(PKCS#12 — leave blank to auto-try)</span>
              </label>
              <input
                className="input-base text-xs"
                type="password"
                autoComplete="off"
                placeholder="e.g. changeit"
                value={ksPassword}
                onChange={(e) => setKsPassword(e.target.value)}
              />
            </div>
            <div className="flex items-end">
              <label className="btn btn-ghost btn-sm cursor-pointer w-full justify-center">
                Choose file (.jks / .p12 / .pfx / .jceks)
                <input
                  type="file"
                  accept=".jks,.jceks,.p12,.pfx,application/octet-stream,application/x-pkcs12"
                  className="hidden"
                  onChange={(e) => { const f = e.target.files?.[0]; if (f) handleKeystoreFile(f); e.target.value = ''; }}
                />
              </label>
            </div>
          </div>
          {ksFileName && <p className="text-xs font-mono" style={{ color: 'var(--text-secondary)' }}>Loaded: {ksFileName}</p>}
          {error && <p className="text-xs" style={{ color: 'var(--danger)' }}>{error}</p>}
        </div>
      </div>

      {entries.length > 0 && (
        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-2 sm:grid-cols-4">
            {[
              { label: 'Total', value: entries.length, color: 'var(--accent)' },
              { label: 'CA', value: entries.filter((e) => e.isCA).length, color: 'var(--info, #60a5fa)' },
              { label: 'Expired', value: entries.filter((e) => e.notAfter && e.notAfter < now).length, color: 'var(--danger)' },
              { label: 'Exp. ≤90d', value: entries.filter((e) => { if (!e.notAfter || e.notAfter < now) return false; return (e.notAfter.getTime() - now.getTime()) < 90 * 86400000; }).length, color: '#fbbf24' },
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
              placeholder="Filter by alias, subject, issuer, SAN…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
            />
            <select className="input-base text-xs" style={{ width: 156 }} value={sortBy}
              onChange={(e) => setSortBy(e.target.value as typeof sortBy)}>
              <option value="index">Sort: Original order</option>
              <option value="subject">Sort: Subject A→Z</option>
              <option value="expiry-asc">Sort: Expiry ↑ soonest</option>
              <option value="expiry-desc">Sort: Expiry ↓ latest</option>
              <option value="ca-first">Sort: CA first</option>
            </select>
            <select className="input-base text-xs" style={{ width: 148 }}
              value={expiryWindow === null ? '' : String(expiryWindow)}
              onChange={(e) => setExpiryWindow(e.target.value === '' ? null : Number(e.target.value))}>
              <option value="">Expiry: all dates</option>
              <option value="-1">Already expired</option>
              <option value="30">Expiring ≤ 30d</option>
              <option value="90">Expiring ≤ 90d</option>
              <option value="180">Expiring ≤ 180d</option>
              <option value="365">Expiring ≤ 1yr</option>
            </select>
          </div>

          <p className="text-xs" style={{ color: 'var(--text-muted)' }}>Showing {filtered.length} of {entries.length} certificate(s)</p>

          {/* Column header */}
          <div className="flex items-center gap-0 rounded text-[10px] font-semibold uppercase tracking-wider select-none"
            style={{ background: 'var(--bg-tertiary)', color: 'var(--text-muted)', borderBottom: '1px solid var(--border)' }}>
            <span className="px-2 py-1.5" style={{ width: 36 }}>#</span>
            <span className="flex-1 px-2 py-1.5" style={{ maxWidth: '22%' }}>Name / Alias</span>
            <span className="hidden sm:block px-2 py-1.5" style={{ width: '20%' }}>Issuer CN</span>
            <span className="hidden md:block px-2 py-1.5" style={{ width: '17%' }}>SAN</span>
            <span className="px-2 py-1.5" style={{ width: 96 }}>Expiry</span>
            <span className="hidden lg:block px-2 py-1.5" style={{ width: 130 }}>MD5</span>
            <span className="px-2 py-1.5 flex-shrink-0" style={{ minWidth: 80 }}>Status</span>
          </div>

          <div className="space-y-1">
            {filtered.map((entry) => <TrustEntryCard key={entry.index} entry={entry} now={now} />)}
            {filtered.length === 0 && (
              <p className="text-xs text-center py-6" style={{ color: 'var(--text-muted)' }}>No certificates match the current filter.</p>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
