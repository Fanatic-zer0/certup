import { cn } from '@/lib/utils';

type Variant = 'default' | 'success' | 'warning' | 'danger' | 'info' | 'purple';

const styles: Record<Variant, { bg: string; text: string; border: string }> = {
  default: {
    bg: 'hsl(var(--muted))',
    text: 'hsl(var(--muted-foreground))',
    border: 'hsl(var(--border))',
  },
  success: {
    bg: 'hsl(142 65% 89%)',
    text: 'hsl(142 72% 26%)',
    border: 'hsl(142 65% 68%)',
  },
  warning: {
    bg: 'hsl(38 95% 88%)',
    text: 'hsl(32 90% 32%)',
    border: 'hsl(38 90% 66%)',
  },
  danger: {
    bg: 'hsl(0 80% 92%)',
    text: 'hsl(0 80% 38%)',
    border: 'hsl(0 75% 72%)',
  },
  info: {
    bg: 'hsl(214 90% 92%)',
    text: 'hsl(214 80% 36%)',
    border: 'hsl(214 80% 70%)',
  },
  purple: {
    bg: 'hsl(270 65% 91%)',
    text: 'hsl(270 65% 40%)',
    border: 'hsl(270 60% 70%)',
  },
};

/* dark-mode overrides (applied via CSS variables so they auto-switch) */
const darkStyles: Record<Variant, { bg: string; text: string; border: string }> = {
  default: {
    bg: 'hsl(var(--muted))',
    text: 'hsl(var(--muted-foreground))',
    border: 'hsl(var(--border))',
  },
  success: {
    bg: 'hsl(142 40% 14%)',
    text: 'hsl(142 65% 52%)',
    border: 'hsl(142 50% 28%)',
  },
  warning: {
    bg: 'hsl(38 60% 14%)',
    text: 'hsl(38 90% 58%)',
    border: 'hsl(38 65% 30%)',
  },
  danger: {
    bg: 'hsl(0 55% 15%)',
    text: 'hsl(0 75% 62%)',
    border: 'hsl(0 60% 32%)',
  },
  info: {
    bg: 'hsl(214 55% 14%)',
    text: 'hsl(214 80% 64%)',
    border: 'hsl(214 60% 30%)',
  },
  purple: {
    bg: 'hsl(270 40% 16%)',
    text: 'hsl(270 65% 68%)',
    border: 'hsl(270 50% 32%)',
  },
};

export function Badge({
  children,
  variant = 'default',
  className,
}: { children: React.ReactNode; variant?: Variant; className?: string }) {
  const s = styles[variant];
  const d = darkStyles[variant];
  return (
    <span
      className={cn(
        'badge-themed inline-flex items-center rounded-full px-[7px] py-[2px] text-[10px] font-semibold leading-none tracking-wide',
        `badge-themed-${variant}`,
        className,
      )}
      style={{
        background: s.bg,
        color: s.text,
        border: `1px solid ${s.border}`,
        /* store dark values as custom properties so CSS can override */
        ['--_bg-dark' as string]: d.bg,
        ['--_text-dark' as string]: d.text,
        ['--_border-dark' as string]: d.border,
      }}
    >
      {children}
    </span>
  );
}
