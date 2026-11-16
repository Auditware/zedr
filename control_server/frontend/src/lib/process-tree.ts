import type { ApiEvent } from './api'
import { eventData } from './events'
import { detect, type Finding } from './findings'
import { baseName, isInterpreter } from './images'

export { baseName, isInterpreter }

export type Connection = {
  time: number
  action: string
  protocol: string
  destIp: string
  destPort: number
  sent: number
  received: number
}

export type FileTouch = { time: number; action: string; path: string }

export type Proc = {
  key: string
  pid: number
  ppid: number
  name: string
  path: string
  command: string
  uid: number
  start: number
  end: number | null
  parent: Proc | null
  children: Proc[]
  connections: Connection[]
  files: FileTouch[]
  findings: Finding[]
}

export type ProcessModel = { roots: Proc[]; all: Proc[]; byKey: Map<string, Proc> }

function number(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

export function buildProcessModel(events: ApiEvent[]): ProcessModel {
  const ordered = [...events].sort((a, b) => a.timestamp - b.timestamp)
  const live = new Map<number, Proc>()
  const all: Proc[] = []
  const roots: Proc[] = []

  for (const event of ordered) {
    const data = eventData(event)
    if (event.event_type === 'process') {
      const pid = number(data.pid)
      const action = text(data.action)
      if (action === 'Terminate') {
        const proc = live.get(pid)
        if (proc) {
          proc.end = event.timestamp
          live.delete(pid)
        }
        continue
      }
      if (action !== 'Create') continue
      const path = text(data.executable_path)
      const proc: Proc = {
        key: `${pid}@${event.timestamp}`,
        pid,
        ppid: number(data.ppid),
        name: baseName(path) || `pid ${pid}`,
        path,
        command: Array.isArray(data.command_line) ? data.command_line.filter((part) => typeof part === 'string').join(' ') : '',
        uid: number(data.uid),
        start: event.timestamp,
        end: null,
        parent: null,
        children: [],
        connections: [],
        files: [],
        findings: [],
      }
      const parent = live.get(proc.ppid)
      if (parent && parent.pid !== pid) {
        proc.parent = parent
        parent.children.push(proc)
      } else {
        roots.push(proc)
      }
      live.set(pid, proc)
      all.push(proc)
    } else if (event.event_type === 'network') {
      const proc = live.get(number(data.pid))
      proc?.connections.push({
        time: event.timestamp,
        action: text(data.action),
        protocol: text(data.protocol),
        destIp: text(data.dest_ip),
        destPort: number(data.dest_port),
        sent: number(data.bytes_sent),
        received: number(data.bytes_received),
      })
    } else if (event.event_type === 'file') {
      const proc = live.get(number(data.pid))
      proc?.files.push({ time: event.timestamp, action: text(data.action), path: text(data.path) })
    }
  }

  for (const proc of all) proc.findings = detect(proc)
  return { roots, all, byKey: new Map(all.map((proc) => [proc.key, proc])) }
}

export type Severity = 'alert' | 'warn' | 'link' | 'plain'

export function severity(proc: Proc): Severity {
  if (proc.findings.some((finding) => finding.level === 'high')) return 'alert'
  if (proc.findings.length > 0) return 'warn'
  if (proc.connections.length > 0) return 'link'
  return 'plain'
}

const RANK: Record<Severity, number> = { alert: 0, warn: 1, link: 2, plain: 3 }

export function isNotable(proc: Proc): boolean {
  return isInterpreter(proc.name) || proc.connections.length > 0 || proc.files.length > 0
}

export function hotSet(model: ProcessModel): Set<Proc> {
  const hot = new Set<Proc>()
  for (const proc of model.all) {
    if (!isNotable(proc)) continue
    for (let current: Proc | null = proc; current && !hot.has(current); current = current.parent) hot.add(current)
  }
  return hot
}

export type Focus = 'all' | 'notable'

export type TreeOptions = { focus: Focus; folded: ReadonlySet<string>; opened: ReadonlySet<string> }

export type TreeNode = {
  id: string
  kind: 'proc' | 'stack' | 'quiet'
  procs: Proc[]
  depth: number
  x: number
  y: number
  parentId: string | null
  hidden: number
  foldable: boolean
}

export type TreeLayout = {
  nodes: TreeNode[]
  byId: Map<string, TreeNode>
  nodeOf: Map<string, string>
  width: number
  height: number
}

export const TREE = { column: 232, row: 38, nodeWidth: 196, nodeHeight: 28, pad: 24 }
export const ROOT = 'root'

export const stackId = (parentKey: string, name: string) => `${parentKey}/stack:${name}`
export const quietId = (parentKey: string) => `${parentKey}/quiet`

function leafGroupKey(proc: Proc): string | null {
  return proc.children.length === 0 && proc.connections.length === 0 && proc.files.length === 0 ? proc.name : null
}

function descendants(proc: Proc): number {
  let count = 0
  for (const child of proc.children) count += 1 + descendants(child)
  return count
}

export function layoutProcessTree(model: ProcessModel, options: TreeOptions): TreeLayout {
  const nodes: TreeNode[] = []
  const nodeOf = new Map<string, string>()
  const hot = options.focus === 'notable' ? hotSet(model) : null
  let nextRow = 0
  let maxDepth = 0

  const claim = (proc: Proc, id: string) => {
    nodeOf.set(proc.key, id)
    for (const child of proc.children) claim(child, id)
  }

  const leaf = (node: TreeNode) => {
    node.y = TREE.pad + TREE.nodeHeight / 2 + nextRow * TREE.row
    nextRow += 1
    return node.y
  }

  const add = (id: string, kind: TreeNode['kind'], procs: Proc[], depth: number, parentId: string | null): TreeNode => {
    const node: TreeNode = { id, kind, procs, depth, x: TREE.pad + depth * TREE.column, y: 0, parentId, hidden: 0, foldable: false }
    nodes.push(node)
    maxDepth = Math.max(maxDepth, depth)
    return node
  }

  const placeChildren = (children: Proc[], parentKey: string, depth: number, parentId: string | null): number[] => {
    const quiet = hot && !options.opened.has(quietId(parentKey)) ? children.filter((child) => !hot.has(child)) : []
    const shown = quiet.length > 0 ? children.filter((child) => hot!.has(child)) : children

    const groups: Proc[][] = []
    const byName = new Map<string, Proc[]>()
    for (const child of shown) {
      const name = leafGroupKey(child)
      const stackable = name !== null && !options.opened.has(stackId(parentKey, name))
      const group = stackable ? byName.get(name) : undefined
      if (group) {
        group.push(child)
      } else {
        const created = [child]
        if (stackable) byName.set(name, created)
        groups.push(created)
      }
    }

    const rows = groups.map((group) => {
      if (group.length === 1) return place(group[0]!, depth, parentId)
      const node = add(stackId(parentKey, group[0]!.name), 'stack', group, depth, parentId)
      for (const proc of group) nodeOf.set(proc.key, node.id)
      return leaf(node)
    })
    if (quiet.length > 0) {
      const node = add(quietId(parentKey), 'quiet', quiet, depth, parentId)
      for (const proc of quiet) claim(proc, node.id)
      rows.push(leaf(node))
    }
    return rows
  }

  const place = (proc: Proc, depth: number, parentId: string | null): number => {
    const node = add(proc.key, 'proc', [proc], depth, parentId)
    nodeOf.set(proc.key, node.id)
    node.foldable = proc.children.length > 0
    if (proc.children.length === 0) return leaf(node)
    if (options.folded.has(proc.key)) {
      node.hidden = descendants(proc)
      for (const child of proc.children) claim(child, node.id)
      return leaf(node)
    }
    const rows = placeChildren(proc.children, proc.key, depth + 1, node.id)
    node.y = (rows[0]! + rows[rows.length - 1]!) / 2
    return node.y
  }

  placeChildren(model.roots, ROOT, 0, null)

  return {
    nodes,
    byId: new Map(nodes.map((node) => [node.id, node])),
    nodeOf,
    width: TREE.pad * 2 + maxDepth * TREE.column + TREE.nodeWidth,
    height: TREE.pad * 2 + Math.max(1, nextRow) * TREE.row - (TREE.row - TREE.nodeHeight),
  }
}

export function expose(proc: Proc, options: TreeOptions, hot: ReadonlySet<Proc>): TreeOptions {
  const folded = new Set(options.folded)
  const opened = new Set(options.opened)
  for (let current: Proc = proc; ; current = current.parent) {
    const parentKey = current.parent ? current.parent.key : ROOT
    if (current.parent) folded.delete(parentKey)
    if (options.focus === 'notable' && !hot.has(current)) opened.add(quietId(parentKey))
    if (current === proc && leafGroupKey(current) !== null) opened.add(stackId(parentKey, current.name))
    if (!current.parent) break
  }
  return { focus: options.focus, folded, opened }
}

export type Step = 'up' | 'down' | 'left' | 'right'

export function stepNode(layout: TreeLayout, id: string, step: Step): TreeNode | null {
  const current = layout.byId.get(id)
  if (!current) return null
  if (step === 'left') return current.parentId ? (layout.byId.get(current.parentId) ?? null) : null
  if (step === 'right') return layout.nodes.find((node) => node.parentId === current.id) ?? null
  let best: TreeNode | null = null
  for (const node of layout.nodes) {
    if (node.depth !== current.depth || node === current) continue
    if (step === 'up' ? node.y >= current.y : node.y <= current.y) continue
    if (!best || Math.abs(node.y - current.y) < Math.abs(best.y - current.y)) best = node
  }
  return best
}

export function alertTrail(model: ProcessModel): Set<string> {
  const trail = new Set<string>()
  for (const proc of model.all) {
    if (severity(proc) !== 'alert') continue
    for (let current: Proc | null = proc; current && !trail.has(current.key); current = current.parent) trail.add(current.key)
  }
  return trail
}

export function leadProc(model: ProcessModel): Proc | null {
  let lead: Proc | null = null
  for (const proc of model.all) {
    const level = severity(proc)
    if (level !== 'alert' && level !== 'warn') continue
    if (!lead || RANK[level] < RANK[severity(lead)] || (level === severity(lead) && proc.start > lead.start)) lead = proc
  }
  return lead
}

export function shownCount(layout: TreeLayout): number {
  let count = 0
  for (const node of layout.nodes) if (node.kind !== 'quiet') count += node.procs.length
  return count
}

export function findProcs(model: ProcessModel, query: string): Proc[] {
  const needle = query.trim().toLowerCase()
  if (!needle) return []
  return model.all.filter(
    (proc) =>
      proc.name.toLowerCase().includes(needle) ||
      proc.command.toLowerCase().includes(needle) ||
      proc.path.toLowerCase().includes(needle) ||
      String(proc.pid) === needle,
  )
}

export type App = {
  key: string
  name: string
  path: string
  procs: Proc[]
  running: number
  first: number
  last: number
  connections: number
  bytes: number
  files: number
  users: number[]
  severity: Severity
}

export function apps(model: ProcessModel): App[] {
  const byKey = new Map<string, App>()
  for (const proc of model.all) {
    const key = (proc.path || proc.name).toLowerCase()
    let app = byKey.get(key)
    if (!app) {
      app = { key, name: proc.name, path: proc.path, procs: [], running: 0, first: proc.start, last: proc.start, connections: 0, bytes: 0, files: 0, users: [], severity: 'plain' }
      byKey.set(key, app)
    }
    app.procs.push(proc)
    if (proc.end === null) app.running += 1
    app.first = Math.min(app.first, proc.start)
    app.last = Math.max(app.last, proc.end ?? proc.start)
    app.connections += proc.connections.length
    for (const connection of proc.connections) app.bytes += connection.sent + connection.received
    app.files += proc.files.length
    if (!app.users.includes(proc.uid)) app.users.push(proc.uid)
    const level = severity(proc)
    if (RANK[level] < RANK[app.severity]) app.severity = level
  }
  return [...byKey.values()].sort(
    (a, b) => RANK[a.severity] - RANK[b.severity] || b.bytes - a.bytes || b.procs.length - a.procs.length || a.name.localeCompare(b.name),
  )
}

export function lineage(proc: Proc): Proc[] {
  const chain: Proc[] = []
  for (let current: Proc | null = proc; current; current = current.parent) chain.unshift(current)
  return chain
}

export type Remote = { key: string; destIp: string; destPort: number; protocol: string; count: number; bytes: number; procs: Proc[] }

export function remotes(model: ProcessModel): Remote[] {
  const byKey = new Map<string, Remote>()
  for (const proc of model.all) {
    for (const connection of proc.connections) {
      const key = `${connection.destIp}:${connection.destPort}/${connection.protocol}`
      let remote = byKey.get(key)
      if (!remote) {
        remote = { key, destIp: connection.destIp, destPort: connection.destPort, protocol: connection.protocol, count: 0, bytes: 0, procs: [] }
        byKey.set(key, remote)
      }
      remote.count += 1
      remote.bytes += connection.sent + connection.received
      if (!remote.procs.includes(proc)) remote.procs.push(proc)
    }
  }
  return [...byKey.values()].sort((a, b) => b.bytes - a.bytes || b.count - a.count)
}
