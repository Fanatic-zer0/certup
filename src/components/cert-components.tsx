/**
 * cert-components.tsx — rich layout primitives for cert display
 */
import { useState } from 'react';
import { CheckCircle, XCircle, Download, ChevronDown, ChevronRight } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Badge } from '@/components/ui/badge';
import { CopyBtn } from '@/components/ui/cert-ui';
import { friendlySigAlg, pemDownload, type TrustEntry } from '@/lib/cert-crypto';

// ─── Section ─────────────────────────────────────────────────────────────────

export function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div
      className="rounded-lg overflow-hidden"
      style={{
        border: '1px solid hsl(var(--border))',
        boxShadow: 'var(--shadow-xs)',
      }}
    >
      <div
        className="px-3.5 py-2 text-[11px] font-semibold tracking-wide uppercase"
        style={{
          background: 'hsl(var(--muted)/0.6)',
          borderBottom: '1px solid hsl(var(--border))',
          color: 'hsl(var(--primary))',
          letterSpacing: '0.06em',
        }}
      >
        {title}
      </div>
      <div className="px-3.5" style={{ background: 'hsl(var(--card))' }}>
        {children}
      </div>
    </div>
  );
}

// ─── Field ───────────────────────────────────────────────────────────────────

export function Field({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div
      className="flex gap-3 py-[7px] items-start"
      style={{ borderBottom: '1px solid hsl(var(--border)/0.5)' }}
    >
      <span
        className="text-[11px] font-medium flex-shrink-0 pt-px"
        style={{ color: 'hsl(var(--muted-foreground))', width: 136 }}
      >
        {label}
      </span>
      <span className="text-[11.5px] font-mono break-all flex-1" style={{ color: 'hsl(var(--foreground))' }}>
        {value}
      </span>
    </div>
  );
}

// ─── MatchBadge ──────────────────────────────────────────────────────────────

export function MatchBadge({ match, yes, no }: { match: boolean | null; yes: string; no: string }) {
  if (match === null) return null;
  return (
    <div
      className="flex items-center gap-2.5 rounded-lg px-4 py-3 text-[12.5px] font-semibold"
      style={
        match
          ? { background: 'hsl(var(--success-subtle))', color: 'hsl(var(--success))', border: '1px solid hsl(var(--success)/0.25)' }
          : { background: 'hsl(var(--destructive)/0.08)', color: 'hsl(var(--destructive))', border: '1px solid hsl(var(--destructive)/0.2)' }
      }
    >
      {match ? <CheckCircle size={15} /> : <XCircle size={15} />}
      {match ? yes : no}
    </div>
  );
}

// ─── TrustEntryCard ──────────────────────────────────────────────────────────

export function TrustEntryCard({ entry, now }: { entry: TrustEntry; now: Date }) {
  const [open, setOpen] = useState(false);

  const expired     = entry.notAfter ? entry.notAfter < now : false;
  const expiringSoon = !expired && entry.notAfter
    ? (entry.notAfter.getTime() - now.getTime()) < 90 * 86400000
    : false;

  const displayName = entry.alias || entry.subject['CN'] || entry.subject['O'] ||
    Object.values(entry.subject)[0] || `Cert #${entry.index + 1}`;
  const issuerCN = entry.issuer['CN'] || entry.issuer['O'] || '—';

  const dnsSans   = entry.san.filter((s) => s.startsWith('DNS: '));
  const sanLabel  = dnsSans.length === 0 ? (entry.san.length ? `${entry.san.length} SANs` : '—')
    : dnsSans.length === 1 ? dnsSans[0].replace('DNS: ', '')
    : `${dnsSans[0].replace('DNS: ', '')} +${dnsSans.length - 1}`;

  const days        = entry.notAfter ? Math.round((entry.notAfter.getTime() - now.getTime()) / 86400000) : null;
  const expiryLabel = !entry.notAfter ? '—'
    : expired ? `${Math.abs(days!)}d ago`
    : expiringSoon ? `${days}d`
    : entry.notAfter.toLocaleDateString(undefined, { year: '2-digit', month: 'short', day: 'numeric' });

  const md5Short = entry.fingerprints.md5
    ? entry.fingerprints.md5.split(':').slice(0, 5).join(':') + '…'
    : '—';

  const dnStr = (m: Record<string, string>) => Object.entries(m).map(([k, v]) => `${k}=${v}`).join(', ') || '(empty)';

  const borderColor = expired ? 'hsl(var(--destructive)/0.35)'
    : expiringSoon ? 'hsl(var(--warning)/0.35)'
    : 'hsl(var(--border))';

  return (
    <div
      className="rounded-lg overflow-hidden"
      style={{ border: `1px solid ${borderColor}`, boxShadow: 'var(--shadow-xs)' }}
    >
      {/* Row */}
      <button
        className={cn('w-full flex items-center gap-0 text-left transition-all min-h-[38px] cursor-pointer')}
        style={{ background: open ? 'hsl(var(--muted)/0.5)' : 'hsl(var(--card))' }}
        onMouseEnter={(e) => { if (!open) (e.currentTarget as HTMLButtonElement).style.background = 'hsl(var(--muted)/0.35)'; }}
        onMouseLeave={(e) => { if (!open) (e.currentTarget as HTMLButtonElement).style.background = 'hsl(var(--card))'; }}
        onClick={() => setOpen(!open)}
      >
        <span className="flex-shrink-0 font-mono text-[10px] px-2.5 text-center tabular-nums" style={{ color: 'hsl(var(--muted-foreground))', width: 36 }}>
          {entry.index + 1}
        </span>
        <span className="flex-1 min-w-0 px-2 py-2 truncate text-[12px] font-semibold" style={{ color: 'hsl(var(--foreground))', maxWidth: '22%' }} title={displayName}>
          {displayName}
        </span>
        <span className="hidden sm:block flex-shrink-0 px-2 py-2 truncate text-[11.5px]" style={{ color: 'hsl(var(--muted-foreground))', width: '20%' }} title={dnStr(entry.issuer)}>
          {issuerCN}
        </span>
        <span className="hidden md:block flex-shrink-0 px-2 py-2 truncate text-[11px] font-mono" style={{ color: 'hsl(var(--muted-foreground))', width: '17%' }} title={entry.san.join(', ')}>
          {sanLabel}
        </span>
        <span
          className="flex-shrink-0 px-2 py-2 text-[11px] font-mono text-right tabular-nums"
          style={{ width: 94, color: expired ? 'hsl(var(--destructive))' : expiringSoon ? 'hsl(var(--warning))' : 'hsl(var(--muted-foreground))' }}
        >
          {expiryLabel}
        </span>
        <span className="hidden lg:block flex-shrink-0 px-2 py-2 truncate text-[10.5px] font-mono" style={{ color: 'hsl(var(--muted-foreground))', width: 132 }} title={`MD5: ${entry.fingerprints.md5}`}>
          {md5Short}
        </span>
        <div className="flex items-center gap-1 px-2 flex-shrink-0">
          {entry.isCA && <Badge variant="info" className="text-[9px] px-1.5 py-0">CA</Badge>}
          {entry.selfSigned && <Badge variant="purple" className="text-[9px] px-1.5 py-0">Self</Badge>}
          {expired && <Badge variant="danger" className="text-[9px] px-1.5 py-0">Exp</Badge>}
          {expiringSoon && !expired && <Badge variant="warning" className="text-[9px] px-1.5 py-0">Soon</Badge>}
          <span className="ml-1" style={{ color: 'hsl(var(--muted-foreground))' }}>
            {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </span>
        </div>
      </button>

      {/* Expanded */}
      {open && (
        <div
          className="px-4 pb-4 pt-3 space-y-3"
          style={{ borderTop: '1px solid hsl(var(--border))', background: 'hsl(var(--background-subtle))' }}
        >
          {entry.error && (
            <p className="text-[11.5px] px-3 py-2 rounded-md" style={{ background: 'hsl(var(--destructive)/0.08)', color: 'hsl(var(--destructive))', border: '1px solid hsl(var(--destructive)/0.2)' }}>
              Parse error: {entry.error}
            </p>
          )}
          <Section title="Subject">
            {Object.keys(entry.subject).length
              ? Object.entries(entry.subject).map(([k, v]) => <Field key={k} label={k} value={v} />)
              : <Field label="—" value="(no subject fields)" />}
          </Section>
          <Section title="Issuer">
            {Object.keys(entry.issuer).length
              ? Object.entries(entry.issuer).map(([k, v]) => <Field key={k} label={k} value={v} />)
              : <Field label="—" value="(no issuer fields)" />}
          </Section>
          <Section title="Properties">
            <Field label="Version" value={`v${entry.version}`} />
            <Field label="Serial" value={entry.serial || '(unknown)'} />
            <Field label="Key" value={`${entry.keyType}${entry.keyBits ? ` (${entry.keyBits} bits)` : ''}`} />
            <Field label="Signature Alg" value={friendlySigAlg(entry.sigAlgOid)} />
            <Field label="CA / Self-Signed" value={`${entry.isCA ? 'CA' : 'End-entity'} · ${entry.selfSigned ? 'Self-signed' : 'Issued by CA'}`} />
            <Field label="Not Before" value={entry.notBefore ? entry.notBefore.toLocaleString() : '(unparsed)'} />
            <Field label="Not After" value={`${entry.notAfter ? entry.notAfter.toLocaleString() : '(unparsed)'}${expired ? '  ⚠ EXPIRED' : expiringSoon ? '  ⚠ Expiring soon' : ''}`} />
          </Section>
          {entry.extensions.length > 0 && (
            <Section title="Extensions">
              {entry.extensions.map((e, i) => <Field key={i} label={`${e.name}${e.critical ? ' *' : ''}`} value={e.value} />)}
              {entry.san.map((s, i) => <Field key={`san-${i}`} label={i === 0 ? 'Subject Alt Names' : ''} value={s} />)}
            </Section>
          )}
          <Section title="Fingerprints">
            <Field label="MD5"    value={entry.fingerprints.md5 || '—'} />
            <Field label="SHA-1"  value={entry.fingerprints.sha1 || '—'} />
            <Field label="SHA-256" value={entry.fingerprints.sha256 || '—'} />
          </Section>
          <div className="flex gap-2 pt-1">
            <CopyBtn text={entry.pem} label="Copy PEM" />
            <button
              className="inline-flex items-center gap-1.5 text-[11.5px] transition-colors cursor-pointer"
              style={{ color: 'hsl(var(--muted-foreground))' }}
              onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.color = 'hsl(var(--foreground))'; }}
              onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.color = 'hsl(var(--muted-foreground))'; }}
              onClick={() => pemDownload(entry.pem, `cert-${entry.index + 1}.pem`)}
            >
              <Download size={11} />Download PEM
            </button>
            <CopyBtn text={dnStr(entry.subject)} label="Copy DN" />
          </div>
        </div>
      )}
    </div>
  );
}

