/**
 * cert-ui.tsx — rich, minimal UI atoms for the cert tool
 */
import { useState } from 'react';
import { CheckCircle, XCircle, Copy, Terminal as TerminalIcon, Download, Check } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { cn } from '@/lib/utils';

// ─── CopyBtn ─────────────────────────────────────────────────────────────────

export function CopyBtn({ text, label = 'Copy' }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);
  const go = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };
  return (
    <Button variant="ghost" size="sm" onClick={go} className="gap-1">
      {copied ? <Check size={11} style={{ color: 'hsl(var(--success))' }} /> : <Copy size={11} />}
      <span style={copied ? { color: 'hsl(var(--success))' } : {}}>
        {copied ? 'Copied' : label}
      </span>
    </Button>
  );
}

// ─── MatchBanner ─────────────────────────────────────────────────────────────

export function MatchBanner({ match, yes, no }: { match: boolean | null; yes: string; no: string }) {
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

// ─── CliBlock ────────────────────────────────────────────────────────────────

export function CliBlock({ commands }: { commands: string }) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const copy = async () => { await navigator.clipboard.writeText(commands); setCopied(true); setTimeout(() => setCopied(false), 1500); };
  return (
    <div
      className="rounded-lg overflow-hidden"
      style={{ border: '1px solid hsl(var(--border))' }}
    >
      <button
        className="w-full flex items-center justify-between px-3 py-2 text-[11.5px] font-medium transition-colors cursor-pointer"
        style={{ background: 'hsl(var(--muted)/0.5)', color: 'hsl(var(--muted-foreground))' }}
        onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = 'hsl(var(--muted))'; }}
        onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = 'hsl(var(--muted)/0.5)'; }}
        onClick={() => setOpen(!open)}
      >
        <span className="flex items-center gap-2">
          <TerminalIcon size={12} style={{ color: 'hsl(var(--primary))' }} />
          CLI equivalent (openssl)
        </span>
        <span className="text-[10px] opacity-60">{open ? '▲' : '▼'}</span>
      </button>
      {open && (
        <div className="relative" style={{ background: 'hsl(222 25% 6%)' }}>
          <button
            className="absolute top-2 right-2 flex items-center gap-1 px-2 py-1 rounded text-[10px] cursor-pointer transition-colors"
            style={{ background: 'rgba(255,255,255,0.07)', color: 'rgba(255,255,255,0.55)' }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.12)'; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = 'rgba(255,255,255,0.07)'; }}
            onClick={copy}
          >
            {copied ? <Check size={10} /> : <Copy size={10} />}
            {copied ? 'Copied' : 'Copy'}
          </button>
          <pre className="p-4 pr-16 text-[11.5px] font-mono overflow-x-auto leading-relaxed m-0" style={{ color: 'hsl(220 15% 80%)' }}>
            {commands}
          </pre>
        </div>
      )}
    </div>
  );
}

// ─── PemOutput ───────────────────────────────────────────────────────────────

export function PemOutput({ label, pem, filename }: { label: string; pem: string; filename: string }) {
  if (!pem) return null;
  const download = () => {
    const blob = new Blob([pem], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = filename; a.click();
    URL.revokeObjectURL(url);
  };
  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[11.5px] font-medium" style={{ color: 'hsl(var(--muted-foreground))' }}>{label}</span>
        <div className="flex gap-1">
          <CopyBtn text={pem} />
          <Button variant="ghost" size="sm" onClick={download} className="gap-1">
            <Download size={11} />Download
          </Button>
        </div>
      </div>
      <textarea
        readOnly
        rows={6}
        className="w-full rounded-lg font-mono text-[11.5px] leading-relaxed px-3 py-2 resize-none focus:outline-none"
        style={{
          background: 'hsl(var(--muted)/0.4)',
          border: '1px solid hsl(var(--border))',
          color: 'hsl(var(--foreground))',
        }}
        value={pem}
      />
    </div>
  );
}
