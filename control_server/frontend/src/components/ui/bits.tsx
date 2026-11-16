import * as Tooltip from '@radix-ui/react-tooltip'
import { Check, Copy } from 'lucide-react'
import { useEffect, useState, type ButtonHTMLAttributes, type HTMLAttributes, type ReactNode } from 'react'
import { cn } from '@/lib/cn'
import type { NodeState } from '@/lib/map-layout'

export function Tip({ label, children }: { label: string; children: ReactNode }) {
  return (
    <Tooltip.Root delayDuration={250}>
      <Tooltip.Trigger asChild>{children}</Tooltip.Trigger>
      <Tooltip.Portal>
        <Tooltip.Content
          sideOffset={6}
          className="z-50 rounded-md border border-line-strong bg-raised px-2 py-1 font-mono text-[11px] text-soft shadow-lg"
        >
          {label}
        </Tooltip.Content>
      </Tooltip.Portal>
    </Tooltip.Root>
  )
}

const DOT: Record<NodeState | 'shell', string> = {
  active: 'bg-node',
  shell: 'bg-accent ring-[3px] ring-accent/20',
  stale: 'border-[1.5px] border-soft',
  suspect: 'border-2 border-warn',
  incident: 'bg-alert',
  stopped: 'border-[1.5px] border-faint bg-chip',
}

export function StateDot({ state, className }: { state: NodeState | 'shell'; className?: string }) {
  return <span aria-hidden className={cn('inline-block h-[9px] w-[9px] shrink-0 rounded-full', DOT[state], className)} />
}

const CHIP: Record<NodeState, string> = {
  active: 'bg-chip text-text',
  stale: 'bg-chip text-soft',
  suspect: 'bg-warn-surface text-warn',
  incident: 'bg-alert-surface text-alert-soft',
  stopped: 'bg-chip text-muted',
}

export function StateChip({ state, children }: { state: NodeState; children: ReactNode }) {
  return <span className={cn('inline-block rounded-full px-2.5 py-0.5 text-xs font-semibold', CHIP[state])}>{children}</span>
}

export function CopyButton({ value, label = 'Copy', className }: { value: string; label?: string; className?: string }) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!copied) return
    const timer = setTimeout(() => setCopied(false), 1400)
    return () => clearTimeout(timer)
  }, [copied])

  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={() => {
        void navigator.clipboard.writeText(value).then(() => setCopied(true))
      }}
      className={cn('inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-muted hover:bg-raised hover:text-text', className)}
    >
      {copied ? <Check size={14} strokeWidth={2} className="text-accent" /> : <Copy size={14} strokeWidth={1.5} />}
    </button>
  )
}

export function Empty({ title, children }: { title: string; children?: ReactNode }) {
  return (
    <div className="flex h-full min-h-40 flex-col items-center justify-center gap-3 p-6 text-center">
      <div className="font-display text-lg text-soft">{title}</div>
      {children}
    </div>
  )
}

export function PageHeader({ title, meta, children }: { title: string; meta?: ReactNode; children?: ReactNode }) {
  return (
    <header className="flex shrink-0 flex-wrap items-center gap-x-5 gap-y-2">
      <div className="mr-auto">
        <h1 className="font-display text-[22px] font-medium leading-tight tracking-tight">{title}</h1>
        {meta ? <div className="font-mono text-xs text-muted">{meta}</div> : null}
      </div>
      {children}
    </header>
  )
}

export function Card({ className, ...props }: HTMLAttributes<HTMLDivElement>) {
  return <div className={cn('rounded-card border border-line bg-surface', className)} {...props} />
}

type RowProps = ButtonHTMLAttributes<HTMLButtonElement> & { selected?: boolean; dim?: boolean }

export function Row({ selected, dim, className, type = 'button', ...props }: RowProps) {
  return (
    <button
      type={type}
      className={cn(
        'flex min-h-[52px] w-full items-center gap-3 rounded-xl border border-line bg-row px-3 py-2 text-left transition-colors hover:border-line-hover',
        selected && 'border-accent bg-selected hover:border-accent',
        dim && 'opacity-55',
        className,
      )}
      {...props}
    />
  )
}

export function SectionTitle({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <h3 className={cn('font-display text-xs font-medium uppercase tracking-wider text-muted', className)}>{children}</h3>
  )
}

type Tone = 'neutral' | 'accent' | 'warn' | 'alert'

const TONE: Record<Tone, string> = {
  neutral: 'bg-chip text-soft',
  accent: 'bg-selected text-text',
  warn: 'bg-warn-surface text-warn',
  alert: 'bg-alert-surface text-alert-soft',
}

export function Chip({ tone = 'neutral', children, className }: { tone?: Tone; children: ReactNode; className?: string }) {
  return (
    <span className={cn('inline-block whitespace-nowrap rounded-full px-2.5 py-0.5 text-xs font-semibold', TONE[tone], className)}>
      {children}
    </span>
  )
}

export function FindingLine({ title, technique, high, meta }: { title: string; technique: string; high: boolean; meta?: string }) {
  return (
    <span className="flex min-w-0 flex-1 items-start gap-2.5">
      <span className={cn('mt-[5px] h-2 w-2 shrink-0 rounded-full', high ? 'bg-alert' : 'bg-warn')} aria-hidden />
      <span className="min-w-0 flex-1">
        <span className="block text-[13px] leading-snug text-text">{title}</span>
        {meta ? <span className="block truncate font-mono text-[11px] text-muted">{meta}</span> : null}
      </span>
      <span className="shrink-0 font-mono text-[11px] text-muted">{technique}</span>
    </span>
  )
}
