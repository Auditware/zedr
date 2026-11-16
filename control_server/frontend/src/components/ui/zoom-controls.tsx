import { Maximize, Minus, Plus } from 'lucide-react'
import type { ReactNode } from 'react'

type Props = { onZoomIn: () => void; onZoomOut: () => void; onFit: () => void }

function Control({ label, onClick, children }: { label: string; onClick: () => void; children: ReactNode }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      onClick={onClick}
      className="flex h-[30px] w-[30px] items-center justify-center border-r border-line text-soft last:border-r-0 hover:bg-raised hover:text-text"
    >
      {children}
    </button>
  )
}

export function ZoomControls({ onZoomIn, onZoomOut, onFit }: Props) {
  return (
    <div className="absolute bottom-[15px] right-[15px] z-10 flex cursor-default overflow-hidden rounded-control border border-line bg-surface">
      <Control label="Zoom in" onClick={onZoomIn}>
        <Plus size={14} strokeWidth={1.75} aria-hidden />
      </Control>
      <Control label="Zoom out" onClick={onZoomOut}>
        <Minus size={14} strokeWidth={1.75} aria-hidden />
      </Control>
      <Control label="Fit view" onClick={onFit}>
        <Maximize size={13} strokeWidth={1.75} aria-hidden />
      </Control>
    </div>
  )
}
