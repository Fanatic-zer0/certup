import * as React from 'react';
import { cn } from '@/lib/utils';

const baseInput = [
  'w-full rounded-2xl transition-all duration-200',
  'border-2 bg-[hsl(var(--input))]',
  'text-[12.5px] text-foreground placeholder:text-muted-foreground',
  'focus-visible:outline-none',
  'disabled:opacity-40 disabled:cursor-not-allowed',
].join(' ');

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, style, ...props }, ref) => (
    <input
      ref={ref}
      className={cn(baseInput, 'h-[34px] px-4', className)}
      style={{
        borderColor: 'hsl(var(--border))',
        boxShadow: 'inset 0 1px 2px rgba(0,0,0,0.04)',
        ...style,
      }}
      onFocus={(e) => {
        e.currentTarget.style.borderColor = 'hsl(var(--ring))';
        e.currentTarget.style.boxShadow = 'var(--shadow-glow), inset 0 1px 2px rgba(0,0,0,0.04)';
        (props.onFocus as any)?.(e);
      }}
      onBlur={(e) => {
        e.currentTarget.style.borderColor = 'hsl(var(--border))';
        e.currentTarget.style.boxShadow = 'inset 0 1px 2px rgba(0,0,0,0.04)';
        (props.onBlur as any)?.(e);
      }}
      {...props}
    />
  ),
);
Input.displayName = 'Input';

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, style, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cn(baseInput, 'px-4 py-3 font-mono resize-none leading-relaxed', className)}
      style={{
        borderColor: 'hsl(var(--border))',
        boxShadow: 'inset 0 1px 2px rgba(0,0,0,0.04)',
        ...style,
      }}
      onFocus={(e) => {
        e.currentTarget.style.borderColor = 'hsl(var(--ring))';
        e.currentTarget.style.boxShadow = 'var(--shadow-glow), inset 0 1px 2px rgba(0,0,0,0.04)';
        (props.onFocus as any)?.(e);
      }}
      onBlur={(e) => {
        e.currentTarget.style.borderColor = 'hsl(var(--border))';
        e.currentTarget.style.boxShadow = 'inset 0 1px 2px rgba(0,0,0,0.04)';
        (props.onBlur as any)?.(e);
      }}
      {...props}
    />
  ),
);
Textarea.displayName = 'Textarea';

export const Label = React.forwardRef<HTMLLabelElement, React.LabelHTMLAttributes<HTMLLabelElement>>(
  ({ className, ...props }, ref) => (
    <label
      ref={ref}
      className={cn('block text-[11.5px] font-medium mb-1.5 text-muted-foreground', className)}
      {...props}
    />
  ),
);
Label.displayName = 'Label';
