import { cn } from '@/lib/cn'

type Props<T extends string> = {
  value: T
  options: { id: T; label: string }[]
  onChange: (value: T) => void
  label: string
  className?: string
}

export function Segmented<T extends string>({ value, options, onChange, label, className }: Props<T>) {
  return (
    <div role="radiogroup" aria-label={label} className={cn('inline-flex max-w-full overflow-x-auto rounded-control border border-line bg-surface p-0.5 [scrollbar-width:none]', className)}>
      {options.map((option) => (
        <button
          key={option.id}
          type="button"
          role="radio"
          aria-checked={option.id === value}
          onClick={() => onChange(option.id)}
          className={cn(
            'h-8 shrink-0 rounded-[calc(var(--radius-control)-2px)] px-3 text-[13px] transition-colors @max-[440px]/tabs:px-1.5 @max-[440px]/tabs:text-xs',
            option.id === value ? 'bg-text font-semibold text-ink' : 'text-muted hover:text-text',
          )}
        >
          {option.label}
        </button>
      ))}
    </div>
  )
}
