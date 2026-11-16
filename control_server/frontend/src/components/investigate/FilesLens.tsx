import { useVirtualizer } from '@tanstack/react-virtual'
import { ChevronRight, File, Folder, FolderOpen } from 'lucide-react'
import { useMemo, useRef, useState } from 'react'
import { FindBox } from '@/components/ui/find-box'
import type { Period } from '@/lib/activity'
import { cn } from '@/lib/cn'
import { actionSummary, buildFileTree, fileRows, quietFolders, type FileNode, type Touch } from '@/lib/file-tree'
import { clock } from '@/lib/format'
import { severity } from '@/lib/process-tree'
import { SEVERITY_DOT, useProbe } from './probe'
import { SealedList } from './SealedList'

type Props = { period: Period | null; find: string; onFind: (find: string) => void }

const ROW = 30
const INDENT = 16
const SLOTS = 56
const GRID =
  'grid items-center gap-x-3 grid-cols-[minmax(0,1fr)_40px] @[560px]:grid-cols-[minmax(0,1.25fr)_minmax(120px,1fr)_40px] @[720px]:grid-cols-[minmax(0,1.25fr)_minmax(140px,1fr)_156px_40px]'
const TICK = { alert: 'bg-alert', warn: 'bg-warn', link: 'bg-soft', plain: 'bg-soft' }

function Track({ touches, from, to, dir }: { touches: Touch[]; from: number; to: number; dir: boolean }) {
  const slots = useMemo(() => {
    const out = new Map<number, { count: number; level: keyof typeof TICK; first: Touch }>()
    for (const touch of touches) {
      const index = Math.min(SLOTS - 1, Math.max(0, Math.floor(((touch.time - from) / (to - from)) * SLOTS)))
      const level = severity(touch.proc)
      const slot = out.get(index)
      if (!slot) out.set(index, { count: 1, level, first: touch })
      else {
        slot.count += 1
        if (level === 'alert' || (level === 'warn' && slot.level !== 'alert')) slot.level = level
      }
    }
    return [...out]
  }, [touches, from, to])
  const peak = Math.max(1, ...slots.map(([, slot]) => slot.count))

  return (
    <span className="relative hidden h-4 @[560px]:block" aria-hidden>
      <span className="absolute inset-x-0 top-1/2 h-px bg-hairline" />
      {slots.map(([index, slot]) => (
        <span
          key={index}
          title={`${clock(slot.first.time)} ${slot.first.proc.name} ${slot.first.action.toLowerCase()}${slot.count > 1 ? `, ${slot.count} in all` : ''}`}
          className={cn('absolute top-1/2 w-[3px] -translate-y-1/2 rounded-full', TICK[slot.level], dir && slot.level !== 'alert' && slot.level !== 'warn' && 'bg-faint')}
          style={{ left: `calc(${(index / SLOTS) * 100}% + 1px)`, height: dir ? 4 + 12 * Math.sqrt(slot.count / peak) : 14 }}
        />
      ))}
    </span>
  )
}

function By({ node }: { node: FileNode }) {
  const latest = node.touches[node.touches.length - 1]!
  const procs = new Set(node.touches.map((touch) => touch.proc))
  if (node.dir && procs.size > 1) return <span className="hidden truncate text-muted @[720px]:block">{procs.size} processes</span>
  return (
    <span className="hidden min-w-0 items-center gap-2 text-soft @[720px]:flex" title={latest.proc.command || latest.proc.path}>
      <span className={cn('h-2 w-2 shrink-0 rounded-full', SEVERITY_DOT[severity(latest.proc)])} aria-hidden />
      <span className="truncate">{latest.proc.name}</span>
      {procs.size > 1 ? <span className="shrink-0 text-faint">+{procs.size - 1}</span> : null}
    </span>
  )
}

export function FilesLens({ period, find, onFind }: Props) {
  const probe = useProbe()
  const scrollRef = useRef<HTMLDivElement>(null)
  const findRef = useRef<HTMLInputElement>(null)
  const [toggled, setToggled] = useState<ReadonlyMap<string, boolean>>(new Map())
  const tree = useMemo(() => buildFileTree(probe.model, period, find), [probe.model, period, find])
  const quiet = useMemo(() => quietFolders(tree), [tree])
  const rows = useMemo(
    () => fileRows(tree, (node) => toggled.get(node.id) ?? (!quiet.has(node.id) || node.touches.some((touch) => touch.proc.key === probe.selectedKey))),
    [tree, toggled, quiet, probe.selectedKey],
  )
  const virtual = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW, overscan: 14 })
  const any = useMemo(() => probe.model.all.some((proc) => proc.files.length > 0), [probe.model])
  const { folders, flagged } = useMemo(() => {
    let dirs = 0
    let hot = 0
    const visit = (node: FileNode) => {
      if (node.dir) dirs += 1
      else if (node.severity === 'alert') hot += 1
      node.children.forEach(visit)
    }
    tree.roots.forEach(visit)
    return { folders: dirs, flagged: hot }
  }, [tree])

  if (!any) return <SealedList agentId={probe.agentId} lead="No file event was opened." />

  const from = period ? period[0] : tree.from
  const to = Math.max(from + 1, period ? period[1] : tree.to)

  return (
    <div
      className="absolute inset-0 flex flex-col"
      onKeyDown={(event) => {
        if (event.key === '/' && !(event.target instanceof HTMLInputElement)) {
          event.preventDefault()
          findRef.current?.focus()
        }
      }}
    >
      <div className="flex shrink-0 flex-wrap items-center gap-2 px-4 pb-2">
        <FindBox value={find} onChange={onFind} placeholder="Find path or process" label="Find in files" inputRef={findRef} />
        <span className="ml-auto font-mono text-xs text-muted">
          {tree.files} {tree.files === 1 ? 'file' : 'files'} in {folders} {folders === 1 ? 'folder' : 'folders'}
          {flagged > 0 ? <span className="text-alert-soft"> · {flagged} by a flagged process</span> : null}
        </span>
      </div>
      <div ref={scrollRef} className="@container mx-4 mb-3 min-h-0 flex-1 overflow-y-auto rounded-card border border-line bg-surface">
        <div className={cn(GRID, 'sticky top-0 z-10 h-8 border-b border-line bg-surface px-3 font-display text-[11px] uppercase tracking-wider text-muted')}>
          <span>Path</span>
          <span className="hidden justify-between font-mono normal-case tracking-normal text-faint @[560px]:flex">
            <span>{clock(from)}</span>
            <span>{clock(to)}</span>
          </span>
          <span className="hidden @[720px]:block">Touched by</span>
          <span className="text-right">Times</span>
        </div>
        {rows.length === 0 ? <div className="px-3 py-3 font-mono text-xs text-muted">Nothing matches.</div> : null}
        <div role="tree" aria-label="Touched paths" style={{ height: virtual.getTotalSize(), position: 'relative' }}>
          {virtual.getVirtualItems().map((item) => {
            const { node, depth, open } = rows[item.index]!
            const latest = node.touches[node.touches.length - 1]!
            const held = !node.dir && node.touches.some((touch) => touch.proc.key === probe.selectedKey)
            const gone = !node.dir && latest.action === 'Delete'
            const hot = node.severity === 'alert'
            return (
              <button
                key={node.id}
                type="button"
                role="treeitem"
                aria-level={depth + 1}
                aria-expanded={node.dir ? open : undefined}
                aria-selected={held}
                data-path={node.id}
                title={node.dir ? node.id : `${node.id}\n${actionSummary(node.touches)}`}
                onClick={() => {
                  if (node.dir) setToggled((current) => new Map(current).set(node.id, !open))
                  else probe.onSelect(latest.proc.key)
                }}
                className={cn(
                  GRID,
                  'absolute left-0 w-full border-b border-hairline px-3 text-left font-mono text-xs hover:bg-raised',
                  held && 'bg-selected hover:bg-selected',
                )}
                style={{ height: ROW, transform: `translateY(${item.start}px)` }}
              >
                <span className="relative flex h-full min-w-0 items-center gap-1.5" style={{ paddingLeft: depth * INDENT }}>
                  {Array.from({ length: depth }, (_, level) => (
                    <span key={level} className="absolute inset-y-0 w-px bg-line" style={{ left: level * INDENT + 6 }} aria-hidden />
                  ))}
                  {node.dir ? (
                    <ChevronRight size={13} strokeWidth={1.75} className={cn('shrink-0 text-muted transition-transform', open && 'rotate-90')} aria-hidden />
                  ) : (
                    <span className="w-[13px] shrink-0" aria-hidden />
                  )}
                  {node.dir ? (
                    open ? (
                      <FolderOpen size={14} strokeWidth={1.5} className={cn('shrink-0', hot ? 'text-alert' : 'text-muted')} aria-hidden />
                    ) : (
                      <Folder size={14} strokeWidth={1.5} className={cn('shrink-0', hot ? 'text-alert' : 'text-muted')} aria-hidden />
                    )
                  ) : (
                    <File size={14} strokeWidth={1.5} className={cn('shrink-0', hot ? 'text-alert' : 'text-faint')} aria-hidden />
                  )}
                  <span className={cn('truncate', node.dir ? 'text-soft' : hot ? 'text-accent-strong' : 'text-text', gone && 'text-muted line-through')}>{node.label}</span>
                  {node.dir && !open ? <span className="shrink-0 text-faint">{node.files}</span> : null}
                </span>
                <Track touches={node.touches} from={from} to={to} dir={node.dir} />
                <By node={node} />
                <span className={cn('text-right', hot ? 'text-alert-soft' : 'text-muted')}>{node.touches.length}</span>
              </button>
            )
          })}
        </div>
      </div>
    </div>
  )
}
