import type { Agent } from './api'
import { subnet } from './format'

export type NodeState = 'active' | 'stale' | 'suspect' | 'incident' | 'stopped'
export type GroupBy = 'subnet' | 'os' | 'version' | 'liveness'

export const GROUP_BY: { id: GroupBy; label: string }[] = [
  { id: 'subnet', label: 'Subnet' },
  { id: 'os', label: 'OS' },
  { id: 'version', label: 'Version' },
  { id: 'liveness', label: 'Liveness' },
]

export const STATE_LABEL: Record<NodeState, string> = {
  active: 'Active',
  stale: 'Stale',
  suspect: 'Suspect',
  incident: 'Incident',
  stopped: 'Stopped',
}

export const STATE_ORDER: NodeState[] = ['active', 'stale', 'suspect', 'incident', 'stopped']

export function nodeState(agent: Pick<Agent, 'liveness_state'>, hasOpenIncident: boolean): NodeState {
  if (hasOpenIncident) return 'incident'
  switch (agent.liveness_state) {
    case 'stale':
    case 'suspect':
    case 'incident':
    case 'stopped':
      return agent.liveness_state
    default:
      return 'active'
  }
}

export function groupKey(agent: Agent, state: NodeState, by: GroupBy): string {
  switch (by) {
    case 'subnet':
      return subnet(agent.ip_address)
    case 'os':
      return agent.os_version || agent.platform
    case 'version':
      return `v${agent.version}`
    case 'liveness':
      return STATE_LABEL[state]
  }
}

export type Point = { x: number; y: number }
export type GroupBox = { key: string; count: number; x: number; y: number; r: number }
export type Layout = {
  points: Map<string, Point>
  groups: GroupBox[]
  bounds: { minX: number; minY: number; maxX: number; maxY: number }
}

const GOLDEN_ANGLE = 2.399963229728653
const LABEL_WIDTH = 104
const LABEL_HEIGHT = 40
const PADDING = 48

export type Viewport = { width: number; height: number }

type Box = GroupBox & { halfWidth: number; below: number }

function scaleFor(bounds: Layout['bounds'], viewport: Viewport): number {
  const worldWidth = Math.max(1, bounds.maxX - bounds.minX)
  const worldHeight = Math.max(1, bounds.maxY - bounds.minY)
  const scale = Math.min(
    2.2,
    (viewport.width - PADDING * 2) / worldWidth,
    (viewport.height - PADDING * 2) / worldHeight,
  )
  return Math.max(0.05, scale)
}

export function layoutMap(
  nodes: { id: string; group: string }[],
  viewport: Viewport = { width: 1200, height: 800 },
  spacing = 22,
): Layout {
  const byGroup = new Map<string, string[]>()
  for (const node of nodes) {
    const members = byGroup.get(node.group)
    if (members) members.push(node.id)
    else byGroup.set(node.group, [node.id])
  }

  const step = spacing / 1.77
  const ordered = [...byGroup.entries()]
    .map(([key, ids]) => ({ key, ids: ids.sort(), r: step * Math.sqrt(ids.length) + spacing * 0.6 }))
    .sort((a, b) => b.ids.length - a.ids.length || a.key.localeCompare(b.key))

  const aspect = Math.min(3, Math.max(0.4, viewport.width / Math.max(1, viewport.height)))
  const stretchX = Math.sqrt(aspect)
  const stretchY = 1 / stretchX
  const gap = spacing * 0.7

  let scale = 1
  let boxes: Box[] = []
  let bounds = { minX: -1, minY: -1, maxX: 1, maxY: 1 }

  for (let pass = 0; pass < 3; pass++) {
    const halfLabel = LABEL_WIDTH / 2 / scale
    const below = LABEL_HEIGHT / scale
    boxes = []
    for (const group of ordered) {
      const box: Box = {
        key: group.key,
        count: group.ids.length,
        x: 0,
        y: 0,
        r: group.r,
        halfWidth: Math.max(group.r, halfLabel),
        below: group.r + below,
      }
      if (boxes.length > 0) {
        for (let i = 1; i < 6000; i++) {
          const angle = i * 0.35
          const radius = spacing * 0.8 * Math.sqrt(i)
          const x = Math.cos(angle) * radius * stretchX
          const y = Math.sin(angle) * radius * stretchY
          const clear = boxes.every((other) => {
            const apartX = Math.abs(other.x - x) >= other.halfWidth + box.halfWidth + gap
            const apartY = y - box.r >= other.y + other.below + gap || other.y - other.r >= y + box.below + gap
            return apartX || apartY
          })
          if (clear) {
            box.x = x
            box.y = y
            break
          }
        }
      }
      boxes.push(box)
    }

    bounds = { minX: Infinity, minY: Infinity, maxX: -Infinity, maxY: -Infinity }
    for (const box of boxes) {
      bounds.minX = Math.min(bounds.minX, box.x - box.halfWidth)
      bounds.maxX = Math.max(bounds.maxX, box.x + box.halfWidth)
      bounds.minY = Math.min(bounds.minY, box.y - box.r)
      bounds.maxY = Math.max(bounds.maxY, box.y + box.below)
    }
    if (boxes.length === 0) bounds = { minX: -1, minY: -1, maxX: 1, maxY: 1 }
    scale = scaleFor(bounds, viewport)
  }

  const points = new Map<string, Point>()
  ordered.forEach((group, index) => {
    const box = boxes[index]!
    group.ids.forEach((id, i) => {
      const radius = step * Math.sqrt(i + 0.5)
      const angle = i * GOLDEN_ANGLE
      points.set(id, { x: box.x + radius * Math.cos(angle), y: box.y + radius * Math.sin(angle) })
    })
  })

  return {
    points,
    groups: boxes.map(({ key, count, x, y, r }) => ({ key, count, x, y, r })),
    bounds,
  }
}

export type View = { scale: number; x: number; y: number }

export function fitView(bounds: Layout['bounds'], width: number, height: number): View {
  const scale = scaleFor(bounds, { width, height })
  return {
    scale,
    x: width / 2 - ((bounds.minX + bounds.maxX) / 2) * scale,
    y: height / 2 - ((bounds.minY + bounds.maxY) / 2) * scale,
  }
}
