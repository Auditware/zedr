import { Search, X } from 'lucide-react'
import type { ReactNode, Ref } from 'react'
import { cn } from '@/lib/cn'

type Props = {
  value: string
  onChange: (value: string) => void
  placeholder: string
  label: string
  inputRef?: Ref<HTMLInputElement>
  onEnter?: (backwards: boolean) => void
  children?: ReactNode
  className?: string
}

export function FindBox({ value, onChange, placeholder, label, inputRef, onEnter, children, className }: Props) {
  return (
    <label className={cn('flex h-8 w-[260px] max-w-full items-center gap-2 rounded-control border border-line bg-surface px-2.5 focus-within:border-line-hover', className)}>
      <Search size={14} strokeWidth={1.5} className="shrink-0 text-muted" aria-hidden />
      <input
        ref={inputRef}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        onKeyDown={(event) => {
          if (event.key === 'Enter') onEnter?.(event.shiftKey)
          if (event.key === 'Escape') {
            event.stopPropagation()
            onChange('')
            event.currentTarget.blur()
          }
        }}
        placeholder={placeholder}
        aria-label={label}
        className="min-w-0 flex-1 bg-transparent font-mono text-xs text-text outline-none placeholder:font-sans placeholder:text-muted focus-visible:outline-none"
      />
      {value ? (
        <>
          {children}
          <button type="button" aria-label="Clear find" onClick={() => onChange('')} className="shrink-0 rounded text-muted hover:text-text">
            <X size={14} strokeWidth={1.5} aria-hidden />
          </button>
        </>
      ) : (
        <kbd className="shrink-0 rounded-md border border-line-strong px-1.5 font-mono text-[10px] text-muted">/</kbd>
      )}
    </label>
  )
}
