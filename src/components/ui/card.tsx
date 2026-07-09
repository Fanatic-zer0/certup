import * as React from 'react';
import { cn } from '@/lib/utils';

export function Card({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('rounded-lg overflow-hidden', className)}
      style={{
        background: 'hsl(var(--card))',
        border: '1px solid hsl(var(--border))',
        boxShadow: 'var(--shadow-xs)',
      }}
      {...props}
    />
  );
}

export function CardHeader({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return (
    <div
      className={cn('px-4 py-2.5 flex items-center gap-2', className)}
      style={{ borderBottom: '1px solid hsl(var(--border))', background: 'hsl(var(--muted)/0.4)' }}
      {...props}
    />
  );
}

export function CardTitle({ className, ...props }: React.HTMLAttributes<HTMLHeadingElement>) {
  return (
    <h3
      className={cn('text-[11.5px] font-semibold tracking-tight', className)}
      style={{ color: 'hsl(var(--primary))' }}
      {...props}
    />
  );
}

export function CardContent({ className, ...props }: React.HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('px-4 py-3', className)} {...props} />;
}

/** A key-value row inside a Card */
export function FieldRow({ label, value, mono = true }: { label: string; value: React.ReactNode; mono?: boolean }) {
  return (
    <div
      className="flex gap-3 py-1.5 items-start"
      style={{ borderBottom: '1px solid hsl(var(--border)/0.5)' }}
    >
      <span
        className="text-[11px] font-medium flex-shrink-0 pt-px"
        style={{ color: 'hsl(var(--muted-foreground))', width: 126 }}
      >
        {label}
      </span>
      <span
        className={cn('text-[11.5px] break-all flex-1', mono ? 'font-mono' : '')}
        style={{ color: 'hsl(var(--foreground))' }}
      >
        {value}
      </span>
    </div>
  );
}
