import { Handle, Position, type Edge, type Node, type NodeProps, type Viewport } from '@xyflow/react'
import { ArrowUpRight, ChevronDown, ChevronRight, FileText } from 'lucide-react'
import { useEffect, useMemo, useState, type KeyboardEvent } from 'react'
import { cn } from '@/lib/cn'
import { tone } from '@/lib/palette'
import { leadProc, severity, stepNode, TREE, type Step, type TreeNode } from '@/lib/process-tree'
import { FlowCanvas, type Spot } from './FlowCanvas'
import { activate, SEVERITY_DOT, SEVERITY_TONE, useProbe } from './probe'

type TreeFlowNode = Node<{ node: TreeNode; cursor: boolean }, 'proc' | 'stack'>

const anchor = '!pointer-events-none !h-px !min-h-0 !w-px !min-w-0 !border-0 !bg-transparent !opacity-0'
const shell =
  'flex h-full w-full items-center gap-2 rounded-lg border px-2.5 text-left font-mono text-xs transition-colors group-[.far]/flow:border-transparent'
const hideFar = 'group-[.far]/flow:invisible'

function ProcNode({ data }: NodeProps<TreeFlowNode>) {
  const probe = useProbe()
  const { node, cursor } = data
  const proc = node.procs[0]!
  const level = severity(proc)
  const selected = proc.key === probe.selectedKey
  const dimmed = probe.matches !== null && !probe.matches.has(proc.key) && !probe.lineage.has(proc.key)
  const links = proc.connections.length
  const files = proc.files.length

  return (
    <div
      data-proc={proc.key}
      data-name={proc.name}
      title={proc.command || proc.path}
      style={{ ['--far' as string]: SEVERITY_TONE[level] }}
      className={cn(
        shell,
        'border-line bg-surface hover:border-line-hover group-[.far]/flow:bg-(--far)',
        probe.lineage.has(proc.key) && 'border-accent/50',
        level === 'alert' && 'border-alert-line bg-alert-surface',
        selected && 'border-accent bg-selected hover:border-accent',
        cursor && !selected && 'border-line-hover',
        proc.end !== null && 'opacity-60',
        dimmed && 'opacity-25',
      )}
    >
      <Handle type="target" position={Position.Left} className={anchor} />
      <span className={cn('h-2 w-2 shrink-0 rounded-full', SEVERITY_DOT[level], hideFar)} aria-hidden />
      <span className={cn('min-w-0 flex-1 truncate text-text', hideFar)}>{proc.name}</span>
      {links > 0 ? (
        <span className={cn('inline-flex shrink-0 items-center text-soft', hideFar)}>
          <ArrowUpRight size={12} strokeWidth={1.75} aria-hidden />
          {links}
        </span>
      ) : null}
      {files > 0 ? (
        <span className={cn('inline-flex shrink-0 items-center gap-0.5 text-warn', hideFar)}>
          <FileText size={11} strokeWidth={1.75} aria-hidden />
          {files}
        </span>
      ) : null}
      {links === 0 && files === 0 && !node.foldable ? (
        <span className={cn('shrink-0 text-[10px] text-faint', hideFar)}>{proc.pid}</span>
      ) : null}
      {node.foldable ? (
        <button
          type="button"
          aria-label={node.hidden > 0 ? `Expand ${proc.name}` : `Collapse ${proc.name}`}
          aria-expanded={node.hidden === 0}
          onClick={(event) => {
            event.stopPropagation()
            probe.onFold(proc.key)
          }}
          className={cn(
            '-mr-1.5 inline-flex h-5 shrink-0 items-center rounded px-0.5 text-[10px] text-muted hover:bg-line-strong hover:text-text',
            hideFar,
          )}
        >
          {node.hidden > 0 ? (
            <>
              {node.hidden}
              <ChevronRight size={13} strokeWidth={1.75} aria-hidden />
            </>
          ) : (
            <ChevronDown size={13} strokeWidth={1.75} aria-hidden />
          )}
        </button>
      ) : null}
      <Handle type="source" position={Position.Right} className={anchor} />
    </div>
  )
}

function StackNode({ data }: NodeProps<TreeFlowNode>) {
  const { node, cursor } = data
  const quiet = node.kind === 'quiet'
  return (
    <div
      data-group={node.id}
      style={{ ['--far' as string]: tone('line') }}
      className={cn(
        shell,
        'border-dashed border-line-strong text-muted hover:border-line-hover hover:text-text group-[.far]/flow:bg-(--far)',
        cursor && 'border-line-hover text-text',
      )}
    >
      <Handle type="target" position={Position.Left} className={anchor} />
      <span className={cn('min-w-0 flex-1 truncate', hideFar)}>{quiet ? `+${node.procs.length} quiet` : node.procs[0]!.name}</span>
      {quiet ? null : <span className={cn('shrink-0', hideFar)}>×{node.procs.length}</span>}
    </div>
  )
}

const nodeTypes = { proc: ProcNode, stack: StackNode }

const STEPS: Record<string, Step> = { ArrowUp: 'up', ArrowDown: 'down', ArrowLeft: 'left', ArrowRight: 'right' }

function spotOf(node: TreeNode): Spot {
  return { key: node.id, x: node.x, y: node.y - TREE.nodeHeight / 2, width: TREE.nodeWidth, height: TREE.nodeHeight }
}

type Props = { cam: Viewport | null; onCam: (viewport: Viewport) => void }

export function ProcessGraph({ cam, onCam }: Props) {
  const probe = useProbe()
  const { layout, selectedKey } = probe
  const selectedNodeId = selectedKey ? (layout.nodeOf.get(selectedKey) ?? null) : null
  const [cursorId, setCursorId] = useState<string | null>(selectedNodeId)

  useEffect(() => {
    if (selectedNodeId) setCursorId(selectedNodeId)
  }, [selectedNodeId])

  const cursor = cursorId ? layout.byId.get(cursorId) : undefined

  const nodes = useMemo<TreeFlowNode[]>(
    () =>
      layout.nodes.map((node) => ({
        id: node.id,
        type: node.kind === 'proc' ? 'proc' : 'stack',
        position: { x: node.x, y: node.y - TREE.nodeHeight / 2 },
        width: TREE.nodeWidth,
        height: TREE.nodeHeight,
        data: { node, cursor: node.id === cursorId },
      })),
    [layout, cursorId],
  )

  const edges = useMemo<Edge[]>(() => {
    const list: Edge[] = []
    for (const node of layout.nodes) {
      if (!node.parentId) continue
      const key = node.kind === 'proc' ? node.procs[0]!.key : null
      const lit = key !== null && probe.lineage.has(key) && probe.lineage.has(node.parentId)
      const hot = key !== null && probe.trail.has(key)
      list.push({
        id: `e:${node.id}`,
        source: node.parentId,
        target: node.id,
        style: {
          stroke: lit ? tone('accent') : hot ? tone('alert') : tone('line-strong'),
          strokeWidth: lit ? 1.75 : hot ? 1.5 : 1,
          opacity: hot && !lit ? 0.75 : 1,
        },
      })
    }
    return list
  }, [layout, probe.lineage, probe.trail])

  const onKeyDown = (event: KeyboardEvent<HTMLDivElement>) => {
    if (event.metaKey || event.ctrlKey || event.altKey) return
    const step = STEPS[event.key]
    if (step) {
      event.preventDefault()
      const next = cursor ? stepNode(layout, cursor.id, step) : (layout.nodes[0] ?? null)
      if (!next) return
      setCursorId(next.id)
      probe.onSelect(next.kind === 'proc' ? next.procs[0]!.key : null)
      return
    }
    if ((event.key === 'Enter' || event.key === ' ') && cursor) {
      event.preventDefault()
      if (cursor.kind === 'proc') {
        if (cursor.foldable) probe.onFold(cursor.procs[0]!.key)
      } else {
        probe.onOpen(cursor.id)
      }
    }
  }

  const first = layout.nodes[0]
  const lead = useMemo(() => {
    const proc = leadProc(probe.model)
    const node = proc ? layout.byId.get(layout.nodeOf.get(proc.key) ?? '') : undefined
    return node ? spotOf(node) : null
  }, [probe.model, layout])

  return (
    <FlowCanvas
      label="Process tree"
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      cam={cam}
      onCam={onCam}
      home={first ? spotOf(first) : null}
      lead={lead}
      spot={cursor ? spotOf(cursor) : null}
      anchor={probe.anchor}
      homeKey={probe.focus}
      minimapColor={(flowNode) => {
        const node = flowNode.data.node
        return node.kind === 'proc' ? SEVERITY_TONE[severity(node.procs[0]!)] : tone('line')
      }}
      onNodeClick={(_, flowNode) => {
        setCursorId(flowNode.id)
        activate(probe, flowNode.data.node)
      }}
      onPaneClick={() => probe.onSelect(null)}
      onKeyDown={onKeyDown}
    />
  )
}
