import { useVirtualizer } from '@tanstack/react-virtual'
import { ArrowUpRight, ChevronDown, ChevronRight, FileText } from 'lucide-react'
import { useEffect, useRef, type KeyboardEvent } from 'react'
import { cn } from '@/lib/cn'
import { clock, span } from '@/lib/format'
import { severity, type TreeNode } from '@/lib/process-tree'
import { activate, SEVERITY_DOT, useProbe } from './probe'

const ROW = 30
const INDENT = 18

export function ProcessList({ now }: { now: number }) {
  const probe = useProbe()
  const rows = probe.layout.nodes
  const scrollRef = useRef<HTMLDivElement>(null)
  const virtual = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW, overscan: 16 })
  const selectedId = probe.selectedKey ? (probe.layout.nodeOf.get(probe.selectedKey) ?? null) : null
  const selectedIndex = selectedId ? rows.findIndex((node) => node.id === selectedId) : -1

  useEffect(() => {
    if (selectedIndex >= 0) virtual.scrollToIndex(selectedIndex, { align: 'auto' })
    // follow the selection, not every re-measure
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedIndex])

  const pick = (node: TreeNode | undefined) => {
    if (node) activate(probe, node)
  }

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.metaKey || event.ctrlKey || event.altKey) return
    const current = selectedIndex >= 0 ? rows[selectedIndex] : undefined
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      pick(rows.slice(selectedIndex + 1).find((node) => node.kind === 'proc'))
    } else if (event.key === 'ArrowUp' && selectedIndex > 0) {
      event.preventDefault()
      pick(rows.slice(0, selectedIndex).reverse().find((node) => node.kind === 'proc'))
    } else if (event.key === 'ArrowLeft' && current) {
      event.preventDefault()
      if (current.foldable && current.hidden === 0) probe.onFold(current.procs[0]!.key)
      else if (current.parentId) probe.onSelect(current.parentId)
    } else if (event.key === 'ArrowRight' && current?.foldable) {
      event.preventDefault()
      if (current.hidden > 0) probe.onFold(current.procs[0]!.key)
      else pick(rows[selectedIndex + 1])
    }
  }

  return (
    <div
      ref={scrollRef}
      role="tree"
      aria-label="Process list"
      tabIndex={0}
      onKeyDown={onKeyDown}
      className="@container absolute inset-0 overflow-auto px-3 pb-3 outline-none"
    >
      <div className="sticky top-0 z-10 flex h-7 items-center gap-3 border-b border-hairline bg-ink pr-2 font-display text-[11px] uppercase tracking-wider text-faint">
        <span className="min-w-0 flex-1 pl-2">Process</span>
        <span className="w-14 text-right">pid</span>
        <span className="hidden w-12 text-right @[600px]:block">uid</span>
        <span className="hidden w-[68px] text-right @[600px]:block">started</span>
        <span className="hidden w-16 text-right @[460px]:block">ran</span>
      </div>
      <div style={{ height: virtual.getTotalSize(), position: 'relative' }}>
        {virtual.getVirtualItems().map((item) => {
          const node = rows[item.index]!
          const proc = node.procs[0]!
          const single = node.kind === 'proc'
          const selected = single && proc.key === probe.selectedKey
          const dimmed = probe.matches !== null && !(single && probe.matches.has(proc.key))
          return (
            <div
              key={node.id}
              role="treeitem"
              aria-level={node.depth + 1}
              aria-selected={selected}
              aria-expanded={node.foldable ? node.hidden === 0 : undefined}
              data-proc={single ? proc.key : undefined}
              data-name={proc.name}
              onClick={() => activate(probe, node)}
              className={cn(
                'absolute left-0 flex w-full cursor-pointer items-center gap-3 rounded-md pr-2 font-mono text-xs hover:bg-raised',
                selected && 'bg-selected hover:bg-selected',
                single && !selected && probe.lineage.has(proc.key) && 'bg-row',
                single && proc.end !== null && 'text-muted',
                dimmed && 'opacity-30',
              )}
              style={{ height: ROW, transform: `translateY(${item.start}px)` }}
            >
              <span className="flex min-w-0 flex-1 items-center gap-1.5" style={{ paddingLeft: 4 + node.depth * INDENT }}>
                {node.foldable ? (
                  <button
                    type="button"
                    aria-label={node.hidden > 0 ? `Expand ${proc.name}` : `Collapse ${proc.name}`}
                    onClick={(event) => {
                      event.stopPropagation()
                      probe.onFold(proc.key)
                    }}
                    className="inline-flex h-5 w-4 shrink-0 items-center justify-center rounded text-muted hover:bg-line-strong hover:text-text"
                  >
                    {node.hidden > 0 ? <ChevronRight size={13} strokeWidth={1.75} aria-hidden /> : <ChevronDown size={13} strokeWidth={1.75} aria-hidden />}
                  </button>
                ) : (
                  <span className="w-4 shrink-0" aria-hidden />
                )}
                {single ? (
                  <span className={cn('h-2 w-2 shrink-0 rounded-full', SEVERITY_DOT[severity(proc)])} aria-hidden />
                ) : (
                  <span className="h-2 w-2 shrink-0 rounded-full border border-dashed border-muted" aria-hidden />
                )}
                <span className={cn('truncate', single ? 'text-text' : 'text-muted')}>
                  {node.kind === 'quiet' ? `+${node.procs.length} quiet` : node.kind === 'stack' ? `${proc.name} ×${node.procs.length}` : proc.name}
                </span>
                {single && node.hidden > 0 ? <span className="shrink-0 text-faint">+{node.hidden}</span> : null}
                {single && proc.connections.length > 0 ? (
                  <span className="inline-flex shrink-0 items-center text-soft">
                    <ArrowUpRight size={12} strokeWidth={1.75} aria-hidden />
                    {proc.connections.length}
                  </span>
                ) : null}
                {single && proc.files.length > 0 ? (
                  <span className="inline-flex shrink-0 items-center gap-0.5 text-warn">
                    <FileText size={11} strokeWidth={1.75} aria-hidden />
                    {proc.files.length}
                  </span>
                ) : null}
                {single && proc.command !== proc.name ? <span className="min-w-0 flex-1 truncate pl-2 text-faint">{proc.command}</span> : null}
              </span>
              {single ? (
                <>
                  <span className="w-14 shrink-0 text-right text-soft">{proc.pid}</span>
                  <span className="hidden w-12 shrink-0 text-right text-muted @[600px]:block">{proc.uid}</span>
                  <span className="hidden w-[68px] shrink-0 text-right text-muted @[600px]:block">{clock(proc.start)}</span>
                  <span className="hidden w-16 shrink-0 text-right text-muted @[460px]:block">{span((proc.end ?? now) - proc.start)}</span>
                </>
              ) : null}
            </div>
          )
        })}
      </div>
    </div>
  )
}
