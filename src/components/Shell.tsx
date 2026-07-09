import { useState, useEffect } from 'react';
import {
  FileKey2, FileSearch, KeyRound, GitMerge, Link2, ShieldCheck,
  BookOpen, Database, FilePlus2, BadgePlus, Package,
  Sun, Moon, type LucideIcon,
} from 'lucide-react';
import { cn } from '@/lib/utils';

export type TabId =
  | 'cert-decode' | 'csr-decode'
  | 'cert-key' | 'cert-csr' | 'csr-key'
  | 'chain'
  | 'ca-bundle' | 'keystore'
  | 'gen-csr' | 'gen-cert' | 'to-pfx';

interface NavItem { id: TabId; label: string; icon: LucideIcon; group: string }

export const NAV: NavItem[] = [
  { id: 'cert-decode', label: 'Cert Decode',   icon: FileSearch, group: 'Inspect'  },
  { id: 'csr-decode',  label: 'CSR Decode',    icon: FileKey2,   group: 'Inspect'  },
  { id: 'cert-key',    label: 'Cert ↔ Key',    icon: KeyRound,   group: 'Verify'   },
  { id: 'cert-csr',    label: 'Cert ↔ CSR',    icon: GitMerge,   group: 'Verify'   },
  { id: 'csr-key',     label: 'CSR ↔ Key',     icon: Link2,      group: 'Verify'   },
  { id: 'chain',       label: 'Chain Verify',  icon: ShieldCheck,group: 'Verify'   },
  { id: 'ca-bundle',   label: 'CA Bundle',     icon: BookOpen,   group: 'Stores'   },
  { id: 'keystore',    label: 'Keystore',      icon: Database,   group: 'Stores'   },
  { id: 'gen-csr',     label: 'Generate CSR',  icon: FilePlus2,  group: 'Generate' },
  { id: 'gen-cert',    label: 'Generate Cert', icon: BadgePlus,  group: 'Generate' },
  { id: 'to-pfx',      label: 'To PFX / P12',  icon: Package,    group: 'Generate' },
];

const GROUPS = ['Inspect', 'Verify', 'Stores', 'Generate'];

const GROUP_COLORS: Record<string, string> = {
  Inspect:  'hsl(245 70% 65%)',
  Verify:   'hsl(165 60% 48%)',
  Stores:   'hsl(38 88% 52%)',
  Generate: 'hsl(310 60% 60%)',
};

function useTheme() {
  const [dark, setDark] = useState(() =>
    window.matchMedia('(prefers-color-scheme: dark)').matches
  );
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
  }, [dark]);
  return { dark, toggle: () => setDark((d) => !d) };
}

export function Shell({
  active,
  onSelect,
  children,
}: {
  active: TabId;
  onSelect: (id: TabId) => void;
  children: React.ReactNode;
}) {
  const { dark, toggle } = useTheme();
  const activeItem = NAV.find((n) => n.id === active);

  return (
    <div className="flex h-screen overflow-hidden" style={{ background: 'hsl(var(--background))' }}>

      {/* ── Sidebar ───────────────────────────────────────────── */}
      <aside
        className="flex-shrink-0 flex flex-col"
        style={{
          width: 212,
          background: 'hsl(var(--sidebar))',
          borderRight: '1px solid hsl(var(--sidebar-border))',
        }}
      >
        {/* Logo */}
        <div
          className="flex items-center gap-2.5 px-4 py-[18px]"
          style={{ borderBottom: '1px solid hsl(var(--sidebar-border))' }}
        >
          <div
            className="w-7 h-7 rounded-lg flex items-center justify-center text-white text-[11px] font-bold flex-shrink-0 shadow-sm"
            style={{
              background: 'linear-gradient(135deg, hsl(245,70%,58%) 0%, hsl(270,65%,55%) 100%)',
              boxShadow: '0 2px 8px hsl(245 70% 60% / 0.4)',
            }}
          >
            C
          </div>
          <div>
            <div className="font-semibold text-[13px] leading-tight" style={{ color: 'hsl(var(--foreground))' }}>
              CertUp
            </div>
            <div className="text-[9.5px] leading-tight" style={{ color: 'hsl(var(--muted-foreground))' }}>
              Certificate Toolkit
            </div>
          </div>
        </div>

        {/* Nav groups */}
        <nav className="flex-1 overflow-y-auto px-2 py-3 space-y-5">
          {GROUPS.map((group) => {
            const items = NAV.filter((n) => n.group === group);
            const color = GROUP_COLORS[group];
            return (
              <div key={group}>
                {/* Group label with colored dot */}
                <div className="flex items-center gap-1.5 px-2 pb-1.5">
                  <span
                    className="w-1.5 h-1.5 rounded-full flex-shrink-0"
                    style={{ background: color, boxShadow: `0 0 4px ${color}` }}
                  />
                  <span
                    className="text-[9.5px] font-semibold uppercase tracking-[0.08em] select-none"
                    style={{ color: 'hsl(var(--muted-foreground))' }}
                  >
                    {group}
                  </span>
                </div>

                {/* Items */}
                {items.map(({ id, label, icon: Icon }) => {
                  const isActive = active === id;
                  return (
                    <button
                      key={id}
                      onClick={() => onSelect(id)}
                      className={cn(
                        'w-full flex items-center gap-2.5 px-3 py-[7px] rounded-md text-[12px] transition-all text-left cursor-pointer mb-0.5',
                        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring',
                      )}
                      style={
                        isActive
                          ? {
                              background: `hsl(var(--accent-subtle))`,
                              color: `hsl(var(--primary))`,
                              fontWeight: 600,
                              boxShadow: `inset 3px 0 0 hsl(var(--primary))`,
                            }
                          : {
                              color: 'hsl(var(--muted-foreground))',
                            }
                      }
                      onMouseEnter={(e) => {
                        if (!isActive) (e.currentTarget as HTMLButtonElement).style.background = 'hsl(var(--muted))';
                        if (!isActive) (e.currentTarget as HTMLButtonElement).style.color = 'hsl(var(--foreground))';
                      }}
                      onMouseLeave={(e) => {
                        if (!isActive) (e.currentTarget as HTMLButtonElement).style.background = '';
                        if (!isActive) (e.currentTarget as HTMLButtonElement).style.color = 'hsl(var(--muted-foreground))';
                      }}
                    >
                      <Icon
                        size={13}
                        className="flex-shrink-0"
                        style={{ color: isActive ? `hsl(var(--primary))` : color, opacity: isActive ? 1 : 0.7 }}
                      />
                      {label}
                    </button>
                  );
                })}
              </div>
            );
          })}
        </nav>

        {/* Bottom: theme toggle */}
        <div
          className="px-3 py-3"
          style={{ borderTop: '1px solid hsl(var(--sidebar-border))' }}
        >
          <button
            onClick={toggle}
            className="w-full flex items-center gap-2 px-3 py-2 rounded-md text-xs transition-colors cursor-pointer"
            style={{ color: 'hsl(var(--muted-foreground))' }}
            onMouseEnter={(e) => { (e.currentTarget as HTMLButtonElement).style.background = 'hsl(var(--muted))'; (e.currentTarget as HTMLButtonElement).style.color = 'hsl(var(--foreground))'; }}
            onMouseLeave={(e) => { (e.currentTarget as HTMLButtonElement).style.background = ''; (e.currentTarget as HTMLButtonElement).style.color = 'hsl(var(--muted-foreground))'; }}
          >
            {dark ? <Sun size={13} /> : <Moon size={13} />}
            {dark ? 'Light mode' : 'Dark mode'}
          </button>
        </div>
      </aside>

      {/* ── Main ──────────────────────────────────────────────── */}
      <main className="flex-1 overflow-hidden flex flex-col min-w-0">

        {/* Topbar */}
        <div
          className="flex items-center justify-between px-5 flex-shrink-0"
          style={{
            height: 52,
            background: 'hsl(var(--card))',
            borderBottom: '1px solid hsl(var(--border))',
            boxShadow: 'var(--shadow-xs)',
          }}
        >
          <div className="flex items-center gap-2.5">
            {activeItem && (
              <>
                <div
                  className="w-7 h-7 rounded-md flex items-center justify-center flex-shrink-0"
                  style={{
                    background: `${GROUP_COLORS[activeItem.group]}18`,
                    border: `1px solid ${GROUP_COLORS[activeItem.group]}35`,
                  }}
                >
                  <activeItem.icon
                    size={14}
                    style={{ color: GROUP_COLORS[activeItem.group] }}
                  />
                </div>
                <div>
                  <h1 className="text-[13px] font-semibold leading-tight" style={{ color: 'hsl(var(--foreground))' }}>
                    {activeItem.label}
                  </h1>
                  <p className="text-[10.5px] leading-tight" style={{ color: 'hsl(var(--muted-foreground))' }}>
                    {activeItem.group}
                  </p>
                </div>
              </>
            )}
          </div>
        </div>

        {/* Content */}
        <div
          className="flex-1 overflow-y-auto"
          style={{
            background: 'hsl(var(--background))',
            padding: '24px 32px',
          }}
        >
          {children}
        </div>
      </main>
    </div>
  );
}

