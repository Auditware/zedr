import * as Primitive from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import type { ReactNode } from 'react'
import { cn } from '@/lib/cn'

type Props = {
  open: boolean
  onOpenChange: (open: boolean) => void
  title: string
  children: ReactNode
  className?: string
}

export function Dialog({ open, onOpenChange, title, children, className }: Props) {
  return (
    <Primitive.Root open={open} onOpenChange={onOpenChange}>
      <Primitive.Portal>
        <Primitive.Overlay className="fixed inset-0 z-40 bg-black/60 backdrop-blur-[2px]" />
        <Primitive.Content
          aria-describedby={undefined}
          className={cn(
            'fixed left-1/2 top-1/2 z-50 w-[min(440px,calc(100vw-32px))] -translate-x-1/2 -translate-y-1/2',
            'rounded-card border border-line-strong bg-raised p-5 shadow-2xl shadow-black/60',
            className,
          )}
        >
          <div className="mb-4 flex items-center justify-between gap-4">
            <Primitive.Title className="font-display text-lg font-medium">{title}</Primitive.Title>
            <Primitive.Close aria-label="Close" className="rounded-md p-1 text-muted hover:text-text">
              <X size={18} strokeWidth={1.5} />
            </Primitive.Close>
          </div>
          {children}
        </Primitive.Content>
      </Primitive.Portal>
    </Primitive.Root>
  )
}

export function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="mb-3 block">
      <span className="mb-1 block text-xs text-muted">{label}</span>
      {children}
    </label>
  )
}

export const inputClass =
  'h-10 w-full rounded-control border border-line-strong bg-ink px-3 text-sm text-text outline-none placeholder:text-muted/70 focus:border-accent'
