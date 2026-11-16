import { createContext, useContext } from 'react'
import type { Viewport } from '@xyflow/react'
import type { Period } from '@/lib/activity'
import { tone } from '@/lib/palette'
import type { Focus, ProcessModel, Severity, TreeLayout, TreeNode } from '@/lib/process-tree'

export type Probe = {
  agentId: string
  model: ProcessModel
  layout: TreeLayout
  focus: Focus
  anchor: string | null
  selectedKey: string | null
  lineage: ReadonlySet<string>
  trail: ReadonlySet<string>
  matches: ReadonlySet<string> | null
  onSelect: (key: string | null) => void
  onFold: (key: string) => void
  onOpen: (groupId: string) => void
}

export const ProbeContext = createContext<Probe | null>(null)

export function useProbe(): Probe {
  const probe = useContext(ProbeContext)
  if (!probe) throw new Error('ProbeContext is missing')
  return probe
}

export const SEVERITY_DOT: Record<Severity, string> = {
  alert: 'bg-alert',
  warn: 'bg-warn',
  link: 'bg-accent',
  plain: 'bg-node',
}

export const SEVERITY_TONE: Record<Severity, string> = {
  alert: tone('alert'),
  warn: tone('warn'),
  link: tone('soft'),
  plain: tone('line-strong'),
}

export function activate(probe: Probe, node: TreeNode) {
  if (node.kind === 'proc') probe.onSelect(node.procs[0]!.key)
  else probe.onOpen(node.id)
}

export function parseCam(value: string | undefined): Viewport | null {
  if (!value) return null
  const parts = value.split(',').map(Number)
  const [x, y, zoom] = parts
  if (parts.length !== 3 || x === undefined || y === undefined || zoom === undefined) return null
  if (!Number.isFinite(x) || !Number.isFinite(y) || !Number.isFinite(zoom) || zoom <= 0) return null
  return { x, y, zoom }
}

export function formatCam(viewport: Viewport): string {
  return `${Math.round(viewport.x)},${Math.round(viewport.y)},${Math.round(viewport.zoom * 100) / 100}`
}

export function parsePeriod(value: string | undefined): Period | null {
  if (!value) return null
  const parts = value.split(',').map(Number)
  const [from, to] = parts
  if (parts.length !== 2 || from === undefined || to === undefined) return null
  return Number.isInteger(from) && Number.isInteger(to) && from < to ? [from, to] : null
}

export function formatPeriod([from, to]: Period): string {
  return `${from},${to}`
}
