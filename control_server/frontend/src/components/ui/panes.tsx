import { PanelBottomClose, PanelLeftClose, PanelLeftOpen } from 'lucide-react'
import { useCallback, useState, type ReactNode } from 'react'
import {
  Group,
  Separator,
  useDefaultLayout,
  usePanelRef,
  type PanelSize,
} from 'react-resizable-panels'
import { cn } from '@/lib/cn'
import { Tip } from './bits'

export { Panel } from 'react-resizable-panels'

type Orientation = 'horizontal' | 'vertical'

type SplitProps = {
  id: string
  orientation?: Orientation
  panelIds?: string[]
  className?: string
  children: ReactNode
}

export function Split({ id, orientation = 'horizontal', panelIds, className, children }: SplitProps) {
  const { defaultLayout, onLayoutChanged } = useDefaultLayout({ id: `zedr.panes.${id}`, panelIds })
  return (
    <Group
      orientation={orientation}
      defaultLayout={defaultLayout}
      onLayoutChanged={onLayoutChanged}
      className={cn('h-full w-full', className)}
    >
      {children}
    </Group>
  )
}

export function Handle({ orientation = 'horizontal' }: { orientation?: Orientation }) {
  const horizontal = orientation === 'horizontal'
  return (
    <Separator
      className={cn(
        'group relative shrink-0 outline-none',
        horizontal ? 'w-3 cursor-col-resize' : 'h-3 cursor-row-resize',
      )}
    >
      <span
        aria-hidden
        className={cn(
          'absolute left-1/2 top-1/2 -translate-x-1/2 -translate-y-1/2 rounded-full bg-line-strong opacity-0 transition-opacity',
          'group-hover:opacity-100 group-focus-visible:bg-accent group-focus-visible:opacity-100 group-data-[separator=active]:bg-accent group-data-[separator=active]:opacity-100',
          horizontal ? 'h-12 w-1' : 'h-1 w-12',
        )}
      />
    </Separator>
  )
}

export function useCollapsible(collapsedSize = 0) {
  const panelRef = usePanelRef()
  const [collapsed, setCollapsed] = useState(false)
  const onResize = useCallback((size: PanelSize) => setCollapsed(size.inPixels < collapsedSize + 8), [collapsedSize])
  const toggle = useCallback(() => {
    const panel = panelRef.current
    if (!panel) return
    if (panel.isCollapsed()) panel.expand()
    else panel.collapse()
  }, [panelRef])
  return { panelRef, collapsed, collapsedSize, onResize, toggle }
}

export const STRIP_SIZE = 44

export function PaneStrip({
  label,
  icon,
  onOpen,
  orientation = 'horizontal',
}: {
  label: string
  icon: ReactNode
  onOpen: () => void
  orientation?: Orientation
}) {
  const upright = orientation === 'horizontal'
  return (
    <Tip label={`Open ${label.toLowerCase()}`}>
      <button
        type="button"
        onClick={onOpen}
        aria-label={`Open ${label.toLowerCase()}`}
        aria-expanded={false}
        className={cn(
          'flex h-full w-full items-center justify-center gap-2.5 rounded-card border border-line bg-surface text-muted transition-colors hover:border-line-hover hover:bg-raised hover:text-text',
          upright && 'flex-col',
        )}
      >
        {icon}
        <span
          className={cn(
            'font-display text-[11px] font-medium uppercase tracking-[0.16em]',
            upright && '[writing-mode:vertical-rl]',
          )}
        >
          {label}
        </span>
      </button>
    </Tip>
  )
}

export function CollapseToggle({
  collapsed,
  onToggle,
  label,
  flip = false,
  bottom = false,
  className,
}: {
  collapsed: boolean
  onToggle: () => void
  label: string
  flip?: boolean
  bottom?: boolean
  className?: string
}) {
  const Icon = bottom ? PanelBottomClose : collapsed !== flip ? PanelLeftOpen : PanelLeftClose
  return (
    <Tip label={collapsed ? `Show ${label}` : `Hide ${label}`}>
      <button
        type="button"
        onClick={onToggle}
        aria-label={collapsed ? `Show ${label}` : `Hide ${label}`}
        aria-expanded={!collapsed}
        className={cn(
          'inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted hover:bg-raised hover:text-text',
          className,
        )}
      >
        <Icon size={16} strokeWidth={1.5} aria-hidden />
      </button>
    </Tip>
  )
}
