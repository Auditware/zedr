import type { Period } from './activity'
import { severity, type Proc, type ProcessModel, type Severity } from './process-tree'

export type Touch = { time: number; action: string; proc: Proc }

export type FileNode = {
  id: string
  label: string
  dir: boolean
  touches: Touch[]
  files: number
  severity: Severity
  children: FileNode[]
}

export type FileRow = { node: FileNode; depth: number; open: boolean }

export type FileTree = { roots: FileNode[]; files: number; touches: number; from: number; to: number }

const RANK: Record<Severity, number> = { alert: 0, warn: 1, link: 2, plain: 3 }
const ROOMY = 40

function worst(touches: Touch[]): Severity {
  let level: Severity = 'plain'
  for (const touch of touches) {
    const next = severity(touch.proc)
    if (RANK[next] < RANK[level]) level = next
  }
  return level
}

function finish(node: FileNode, split: string): FileNode {
  let current = node
  while (current.dir && current.children.length === 1 && current.children[0]!.dir) {
    const only = current.children[0]!
    current = { ...only, label: `${current.label}${split}${only.label}` }
  }
  const children = current.children
    .map((child) => finish(child, split))
    .sort((a, b) => RANK[a.severity] - RANK[b.severity] || Number(b.dir) - Number(a.dir) || a.label.localeCompare(b.label))
  const touches = (current.dir ? children.flatMap((child) => child.touches) : [...current.touches]).sort((a, b) => a.time - b.time)
  return {
    ...current,
    children,
    touches,
    files: current.dir ? children.reduce((sum, child) => sum + child.files, 0) : 1,
    severity: worst(touches),
  }
}

export function buildFileTree(model: ProcessModel, period: Period | null, find: string): FileTree {
  const needle = find.trim().toLowerCase()
  const holder: FileNode = { id: '', label: '', dir: true, touches: [], files: 0, severity: 'plain', children: [] }
  const index = new Map<FileNode, Map<string, FileNode>>()
  const splits = new Map<FileNode, string>()
  let from = Infinity
  let to = -Infinity
  let touches = 0

  for (const proc of model.all) {
    for (const file of proc.files) {
      if (period && (file.time < period[0] || file.time > period[1])) continue
      if (needle && !file.path.toLowerCase().includes(needle) && !proc.name.toLowerCase().includes(needle)) continue
      const split = file.path.includes('\\') ? '\\' : '/'
      const parts = file.path.split(split).filter(Boolean)
      if (parts.length === 0) continue
      let node = holder
      parts.forEach((part, position) => {
        const label = position === 0 && file.path.startsWith(split) ? `${split}${part}` : part
        const dir = position < parts.length - 1
        const key = `${dir ? 'd' : 'f'}:${split === '\\' ? label.toLowerCase() : label}`
        let known = index.get(node)
        if (!known) index.set(node, (known = new Map()))
        let child = known.get(key)
        if (!child) {
          child = { id: position === 0 ? label : `${node.id}${split}${part}`, label, dir, touches: [], files: 0, severity: 'plain', children: [] }
          known.set(key, child)
          node.children.push(child)
          if (position === 0) splits.set(child, split)
        }
        node = child
      })
      node.touches.push({ time: file.time, action: file.action, proc })
      from = Math.min(from, file.time)
      to = Math.max(to, file.time)
      touches += 1
    }
  }

  const roots = holder.children
    .map((root) => finish(root, splits.get(root)!))
    .sort((a, b) => RANK[a.severity] - RANK[b.severity] || a.label.localeCompare(b.label))
  return { roots, files: roots.reduce((sum, root) => sum + root.files, 0), touches, from, to }
}

export function quietFolders(tree: FileTree): Set<string> {
  const closed = new Set<string>()
  if (tree.files <= ROOMY) return closed
  const visit = (node: FileNode, depth: number) => {
    if (!node.dir) return
    if (depth > 0 && node.severity !== 'alert' && node.severity !== 'warn') closed.add(node.id)
    else node.children.forEach((child) => visit(child, depth + 1))
  }
  tree.roots.forEach((root) => visit(root, 0))
  return closed
}

export function fileRows(tree: FileTree, isOpen: (node: FileNode) => boolean): FileRow[] {
  const rows: FileRow[] = []
  const visit = (node: FileNode, depth: number) => {
    const open = node.dir && isOpen(node)
    rows.push({ node, depth, open })
    if (open) node.children.forEach((child) => visit(child, depth + 1))
  }
  tree.roots.forEach((root) => visit(root, 0))
  return rows
}

export function actionSummary(touches: Touch[]): string {
  const counts = new Map<string, number>()
  for (const touch of touches) counts.set(touch.action, (counts.get(touch.action) ?? 0) + 1)
  return [...counts].map(([action, count]) => (count > 1 ? `${action.toLowerCase()} ×${count}` : action.toLowerCase())).join(', ')
}
