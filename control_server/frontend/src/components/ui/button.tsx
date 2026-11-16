import type { ButtonHTMLAttributes } from 'react'
import { cn } from '@/lib/cn'

type Variant = 'primary' | 'outline' | 'ghost' | 'danger'
type Size = 'md' | 'sm' | 'icon'

const VARIANT: Record<Variant, string> = {
  primary: 'bg-accent text-ink font-semibold hover:bg-accent-strong border border-transparent',
  outline: 'border border-line-strong text-text hover:border-accent',
  ghost: 'border border-transparent text-muted hover:text-text hover:bg-raised',
  danger: 'border border-alert-line text-alert-soft hover:border-alert bg-alert-surface',
}

const SIZE: Record<Size, string> = {
  md: 'h-10 px-4 text-sm',
  sm: 'h-8 px-3 text-[13px]',
  icon: 'h-9 w-9',
}

type Props = ButtonHTMLAttributes<HTMLButtonElement> & { variant?: Variant; size?: Size }

export function Button({ variant = 'outline', size = 'md', className, type = 'button', ...props }: Props) {
  return (
    <button
      type={type}
      className={cn(
        'inline-flex shrink-0 items-center justify-center gap-2 rounded-control font-medium transition-colors',
        'disabled:pointer-events-none disabled:opacity-40',
        VARIANT[variant],
        SIZE[size],
        className,
      )}
      {...props}
    />
  )
}
