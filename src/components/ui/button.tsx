import * as React from 'react';
import { cn } from '@/lib/utils';

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'default' | 'outline' | 'ghost' | 'destructive' | 'link';
  size?: 'default' | 'sm' | 'xs' | 'lg' | 'icon';
}

const variants: Record<string, string> = {
  default:
    'bg-[hsl(var(--primary))] text-[hsl(var(--primary-foreground))] hover:opacity-90 shadow-sm'
    + ' [box-shadow:0_1px_3px_hsl(var(--primary-glow)/0.4),0_0_0_0px_hsl(var(--primary-glow)/0)]'
    + ' hover:[box-shadow:0_2px_8px_hsl(var(--primary-glow)/0.45),0_0_0_0px_hsl(var(--primary-glow)/0)]',
  outline:
    'border border-[hsl(var(--border))] bg-[hsl(var(--card))] text-[hsl(var(--foreground))]'
    + ' hover:bg-[hsl(var(--muted))] hover:border-[hsl(var(--primary)/0.4)]',
  ghost:
    'text-[hsl(var(--muted-foreground))] hover:bg-[hsl(var(--muted))] hover:text-[hsl(var(--foreground))]',
  destructive:
    'bg-[hsl(var(--destructive))] text-[hsl(var(--destructive-foreground))] hover:opacity-90 shadow-sm',
  link:
    'text-[hsl(var(--primary))] underline-offset-4 hover:underline p-0 h-auto shadow-none',
};

const sizes: Record<string, string> = {
  default: 'h-[30px] px-3 py-1.5 text-[12px]',
  sm:      'h-7 px-2.5 py-1 text-[11.5px]',
  xs:      'h-[22px] px-2 py-0.5 text-[10.5px]',
  lg:      'h-9 px-4 py-2 text-[13px]',
  icon:    'h-7 w-7 p-0',
};

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'default', ...props }, ref) => (
    <button
      ref={ref}
      className={cn(
        'inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-all duration-150',
        'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[hsl(var(--ring))] focus-visible:ring-offset-1',
        'disabled:opacity-40 disabled:pointer-events-none cursor-pointer select-none',
        variants[variant], sizes[size], className,
      )}
      {...props}
    />
  ),
);
Button.displayName = 'Button';
