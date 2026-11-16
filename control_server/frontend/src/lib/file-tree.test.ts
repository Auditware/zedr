import { describe, expect, it } from 'vitest'
import type { ApiEvent } from './api'
import { actionSummary, buildFileTree, fileRows, quietFolders } from './file-tree'
import { buildProcessModel } from './process-tree'

let serial = 0

function event(type: string, timestamp: number, data: Record<string, unknown>): ApiEvent {
  serial += 1
  return { id: `e${serial}`, agent_id: 'a1', event_type: type, timestamp, data: JSON.stringify(data), received_at: timestamp }
}

const create = (timestamp: number, pid: number, ppid: number, path: string, args: string[] = []) =>
  event('process', timestamp, { action: 'Create', pid, ppid, executable_path: path, command_line: [path, ...args], uid: 1000 })
const touch = (timestamp: number, pid: number, action: string, path: string) => event('file', timestamp, { action, pid, path })

const model = buildProcessModel([
  create(100, 1, 0, 'C:\\Windows\\explorer.exe'),
  create(110, 2, 1, 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'),
  create(150, 3, 1, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-enc', 'SQBFAFgAIAAoAE4A']),
  touch(120, 2, 'Write', 'C:\\Users\\user\\AppData\\Local\\Cache\\data_1'),
  touch(125, 2, 'Write', 'C:\\Users\\user\\AppData\\Local\\Cache\\data_1'),
  touch(130, 2, 'Create', 'C:\\Users\\user\\Downloads\\report.pdf'),
  touch(155, 3, 'Create', 'C:\\Users\\Public\\update.dll'),
  touch(156, 3, 'Write', 'c:\\users\\public\\update.dll'),
  touch(160, 3, 'Delete', 'C:\\Users\\user\\Downloads\\report.pdf'),
])

const labels = (tree: ReturnType<typeof buildFileTree>, closed = new Set<string>()) =>
  fileRows(tree, (node) => !closed.has(node.id)).map((row) => `${'  '.repeat(row.depth)}${row.node.label}`)

describe('buildFileTree', () => {
  const tree = buildFileTree(model, null, '')

  it('folds a chain of single folders into one row and puts flagged paths first', () => {
    expect(labels(tree)).toEqual([
      'C:\\Users',
      '  Public',
      '    update.dll',
      '  user',
      '    Downloads',
      '      report.pdf',
      '    AppData\\Local\\Cache',
      '      data_1',
    ])
  })

  it('treats Windows paths as one file whatever their case', () => {
    const dll = fileRows(tree, () => true).find((row) => row.node.label === 'update.dll')!.node
    expect(dll.touches.map((item) => item.action)).toEqual(['Create', 'Write'])
    expect(dll.id).toBe('C:\\Users\\Public\\update.dll')
  })

  it('counts files and touches, and carries the worst process up to each folder', () => {
    expect(tree).toMatchObject({ files: 3, touches: 6, from: 120, to: 160 })
    const [root] = tree.roots
    expect(root).toMatchObject({ files: 3, severity: 'alert' })
    expect(root!.children.map((child) => [child.label, child.severity, child.files])).toEqual([
      ['Public', 'alert', 1],
      ['user', 'alert', 2],
    ])
  })

  it('keeps only what was touched in the time window', () => {
    expect(labels(buildFileTree(model, [100, 126], ''))).toEqual(['C:\\Users\\user\\AppData\\Local\\Cache', '  data_1'])
  })

  it('finds by path or by the process that touched it', () => {
    expect(buildFileTree(model, null, 'downloads').files).toBe(1)
    expect(buildFileTree(model, null, 'chrome').touches).toBe(3)
    expect(buildFileTree(model, null, 'nothing').roots).toEqual([])
  })

  it('reads POSIX paths from the root', () => {
    const linux = buildProcessModel([
      create(100, 1, 0, '/usr/sbin/nginx'),
      touch(110, 1, 'Write', '/var/log/nginx/access.log'),
      touch(111, 1, 'Write', '/var/log/nginx/error.log'),
    ])
    expect(labels(buildFileTree(linux, null, ''))).toEqual(['/var/log/nginx', '  access.log', '  error.log'])
  })
})

describe('quietFolders', () => {
  it('leaves a small tree open', () => {
    expect(quietFolders(buildFileTree(model, null, '')).size).toBe(0)
  })

  it('closes unflagged folders once the tree is long', () => {
    const events = [create(100, 1, 0, 'C:\\Build\\cl.exe'), create(101, 2, 0, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-enc', 'SQBFAFgAIAAoAE4A'])]
    for (let unit = 0; unit < 50; unit++) events.push(touch(110 + unit, 1, 'Write', `C:\\Build\\work\\job${unit % 5}\\unit${unit}.obj`))
    events.push(touch(200, 2, 'Create', 'C:\\Build\\tools\\run.ps1'))
    const tree = buildFileTree(buildProcessModel(events), null, '')
    const closed = quietFolders(tree)
    expect([...closed]).toEqual(['C:\\Build\\work'])
    expect(labels(tree, closed)).toEqual(['C:\\Build', '  tools', '    run.ps1', '  work'])
  })
})

describe('actionSummary', () => {
  it('says what was done to a file in order of first use', () => {
    const tree = buildFileTree(model, null, '')
    const pdf = fileRows(tree, () => true).find((row) => row.node.label === 'report.pdf')!.node
    const cache = fileRows(tree, () => true).find((row) => row.node.label === 'data_1')!.node
    expect(actionSummary(pdf.touches)).toBe('create, delete')
    expect(actionSummary(cache.touches)).toBe('write ×2')
  })
})
