import { Handle, Position, type Edge, type Node, type NodeProps, type Viewport } from '@xyflow/react'
import { useMemo, useState } from 'react'
import { Empty } from '@/components/ui/bits'
import { cn } from '@/lib/cn'
import { bytes } from '@/lib/format'
import { tone } from '@/lib/palette'
import { remotes, severity, TREE, type Proc, type Remote } from '@/lib/process-tree'
import { FlowCanvas } from './FlowCanvas'
import { SEVERITY_DOT, SEVERITY_TONE, useProbe } from './probe'

type TalkerNode = Node<{ proc: Proc; volume: number }, 'talker'>
type RemoteNode = Node<{ remote: Remote; flagged: boolean; picked: boolean }, 'remote'>
type NetNode = TalkerNode | RemoteNode

const anchor = '!pointer-events-none !h-px !min-h-0 !w-px !min-w-0 !border-0 !bg-transparent !opacity-0'
const shell = 'flex h-full w-full items-center gap-2 rounded-lg border px-2.5 font-mono text-xs transition-colors'
const GAP = 320

function Talker({ data }: NodeProps<TalkerNode>) {
  const probe = useProbe()
  const { proc } = data
  const level = severity(proc)
  const selected = proc.key === probe.selectedKey
  return (
    <div
      data-proc={proc.key}
      data-name={proc.name}
      title={proc.command || proc.path}
      className={cn(
        shell,
        'border-line bg-surface hover:border-line-hover',
        level === 'alert' && 'border-alert-line bg-alert-surface',
        selected && 'border-accent bg-selected hover:border-accent',
      )}
    >
      <span className={cn('h-2 w-2 shrink-0 rounded-full', SEVERITY_DOT[level])} aria-hidden />
      <span className="min-w-0 flex-1 truncate text-text">{proc.name}</span>
      <span className="shrink-0 text-[10px] text-faint">{proc.pid}</span>
      <Handle type="source" position={Position.Right} className={anchor} />
    </div>
  )
}

function RemoteEnd({ data }: NodeProps<RemoteNode>) {
  const { remote, flagged, picked } = data
  return (
    <div
      data-remote={remote.key}
      className={cn(
        shell,
        'border-line bg-row hover:border-line-hover',
        flagged && 'border-alert-line bg-alert-surface',
        picked && 'border-accent bg-selected hover:border-accent',
      )}
    >
      <Handle type="target" position={Position.Left} className={anchor} />
      <span className={cn('h-2 w-2 shrink-0 rounded-sm', flagged ? 'bg-alert' : 'bg-node')} aria-hidden />
      <span className="min-w-0 flex-1 truncate text-text">
        {remote.destIp}:{remote.destPort}
      </span>
      <span className="shrink-0 text-soft">{bytes(remote.bytes)}</span>
    </div>
  )
}

const nodeTypes = { talker: Talker, remote: RemoteEnd }

type Props = { cam: Viewport | null; onCam: (viewport: Viewport) => void }

export function NetworkGraph({ cam, onCam }: Props) {
  const probe = useProbe()
  const [remoteKey, setRemoteKey] = useState<string | null>(null)
  const list = useMemo(() => remotes(probe.model), [probe.model])

  const { nodes, edges } = useMemo(() => {
    const volume = new Map<Proc, number>()
    for (const remote of list) {
      for (const proc of remote.procs) {
        const sent = proc.connections
          .filter((connection) => `${connection.destIp}:${connection.destPort}/${connection.protocol}` === remote.key)
          .reduce((sum, connection) => sum + connection.sent + connection.received, 0)
        volume.set(proc, (volume.get(proc) ?? 0) + sent)
      }
    }
    const talkers = [...volume.keys()].sort((a, b) => (volume.get(b) ?? 0) - (volume.get(a) ?? 0))
    const row = new Map(talkers.map((proc, index) => [proc, index]))
    const ordered = [...list].sort((a, b) => {
      const rank = (remote: Remote) => remote.procs.reduce((sum, proc) => sum + (row.get(proc) ?? 0), 0) / remote.procs.length
      return rank(a) - rank(b) || b.bytes - a.bytes
    })
    const peak = Math.max(1, ...list.map((remote) => remote.bytes))
    const shift = (Math.max(talkers.length, ordered.length) * TREE.row) / 2
    const column = (count: number, index: number) => TREE.pad + shift - (count * TREE.row) / 2 + index * TREE.row

    const built: NetNode[] = [
      ...talkers.map<TalkerNode>((proc, index) => ({
        id: proc.key,
        type: 'talker',
        position: { x: TREE.pad, y: column(talkers.length, index) },
        width: TREE.nodeWidth,
        height: TREE.nodeHeight,
        data: { proc, volume: volume.get(proc) ?? 0 },
      })),
      ...ordered.map<RemoteNode>((remote, index) => ({
        id: remote.key,
        type: 'remote',
        position: { x: TREE.pad + TREE.nodeWidth + GAP, y: column(ordered.length, index) },
        width: TREE.nodeWidth + 28,
        height: TREE.nodeHeight,
        data: {
          remote,
          flagged: remote.procs.some((proc) => severity(proc) === 'alert'),
          picked: remote.key === remoteKey,
        },
      })),
    ]

    const links: Edge[] = []
    for (const remote of ordered) {
      for (const proc of remote.procs) {
        const flagged = severity(proc) === 'alert'
        const lit = proc.key === probe.selectedKey || remote.key === remoteKey
        links.push({
          id: `${proc.key}>${remote.key}`,
          source: proc.key,
          target: remote.key,
          style: {
            stroke: lit ? tone('accent') : flagged ? tone('alert') : tone('line-hover'),
            strokeWidth: 1 + 4 * Math.sqrt(remote.bytes / peak),
            opacity: lit ? 1 : flagged ? 0.8 : 0.55,
          },
        })
      }
    }
    return { nodes: built, edges: links }
  }, [list, probe.selectedKey, remoteKey])

  if (list.length === 0) return <Empty title="No connections reported" />

  const first = nodes[0]

  return (
    <FlowCanvas<NetNode>
      label="Outbound connections"
      nodes={nodes}
      edges={edges}
      nodeTypes={nodeTypes}
      cam={cam}
      onCam={onCam}
      home={first ? { key: first.id, x: first.position.x, y: first.position.y, width: TREE.nodeWidth, height: TREE.nodeHeight } : null}
      lead={null}
      spot={null}
      anchor={null}
      homeKey="network"
      minimapColor={(node) =>
        node.type === 'talker' ? SEVERITY_TONE[severity(node.data.proc)] : node.data.flagged ? tone('alert') : tone('line-strong')
      }
      onNodeClick={(_, node) => {
        if (node.type === 'talker') {
          setRemoteKey(null)
          probe.onSelect(node.data.proc.key)
        } else {
          setRemoteKey(node.id === remoteKey ? null : node.id)
          probe.onSelect(null)
        }
      }}
      onPaneClick={() => {
        setRemoteKey(null)
        probe.onSelect(null)
      }}
    />
  )
}
