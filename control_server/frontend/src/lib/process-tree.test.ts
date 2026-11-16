import { describe, expect, it } from 'vitest'
import type { ApiEvent } from './api'
import {
  alertTrail,
  apps,
  baseName,
  buildProcessModel,
  expose,
  findProcs,
  hotSet,
  isInterpreter,
  layoutProcessTree,
  lineage,
  quietId,
  remotes,
  ROOT,
  severity,
  stackId,
  stepNode,
  type TreeOptions,
} from './process-tree'

const ALL: TreeOptions = { focus: 'all', folded: new Set(), opened: new Set() }
const NOTABLE: TreeOptions = { focus: 'notable', folded: new Set(), opened: new Set() }

let serial = 0

function event(type: string, timestamp: number, data: Record<string, unknown>): ApiEvent {
  serial += 1
  return { id: `e${serial}`, agent_id: 'a1', event_type: type, timestamp, data: JSON.stringify(data), received_at: timestamp }
}

function create(timestamp: number, pid: number, ppid: number, path: string, args: string[] = []): ApiEvent {
  return event('process', timestamp, { action: 'Create', pid, ppid, executable_path: path, command_line: [path, ...args], uid: 1000 })
}

function connect(timestamp: number, pid: number, ip: string, port: number, sent = 100, received = 400): ApiEvent {
  return event('network', timestamp, {
    action: 'Connect',
    pid,
    process_path: '',
    protocol: 'tcp',
    source_ip: '10.0.0.5',
    source_port: 50000,
    dest_ip: ip,
    dest_port: port,
    bytes_sent: sent,
    bytes_received: received,
  })
}

const events: ApiEvent[] = [
  create(10, 1, 0, 'C:\\Windows\\explorer.exe'),
  create(20, 2, 1, 'C:\\Program Files\\Office\\WINWORD.EXE'),
  create(30, 3, 2, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe', ['-nop', '-enc', 'AAAA']),
  connect(31, 3, '203.0.113.9', 443),
  connect(32, 3, '203.0.113.9', 443),
  event('file', 33, { action: 'Write', pid: 3, path: 'C:\\Users\\Public\\a.dll', process_path: '' }),
  create(40, 4, 1, 'C:\\Windows\\System32\\svchost.exe'),
  create(41, 5, 1, 'C:\\Windows\\System32\\svchost.exe'),
  create(42, 6, 1, 'C:\\Windows\\System32\\svchost.exe'),
  event('process', 50, { action: 'Terminate', pid: 2 }),
]

describe('names', () => {
  it('takes the file name from Windows and POSIX paths', () => {
    expect(baseName('C:\\Windows\\System32\\cmd.exe')).toBe('cmd.exe')
    expect(baseName('/usr/bin/bash')).toBe('bash')
    expect(baseName('plain')).toBe('plain')
  })

  it('knows the interpreters that can run arbitrary code', () => {
    expect(isInterpreter('PowerShell.exe')).toBe(true)
    expect(isInterpreter('bash')).toBe(true)
    expect(isInterpreter('WINWORD.EXE')).toBe(false)
  })
})

describe('buildProcessModel', () => {
  const model = buildProcessModel([...events].reverse())

  it('links children to the parent that was alive, whatever order events arrive in', () => {
    expect(model.roots.map((proc) => proc.name)).toEqual(['explorer.exe'])
    const word = model.all.find((proc) => proc.pid === 2)!
    expect(word.parent?.pid).toBe(1)
    expect(word.children.map((proc) => proc.name)).toEqual(['powershell.exe'])
  })

  it('records exits, command lines, connections and files on the right process', () => {
    const word = model.all.find((proc) => proc.pid === 2)!
    const shell = model.all.find((proc) => proc.pid === 3)!
    expect(word.end).toBe(50)
    expect(shell.end).toBeNull()
    expect(shell.command).toContain('-enc AAAA')
    expect(shell.connections).toHaveLength(2)
    expect(shell.files[0]).toMatchObject({ action: 'Write', path: 'C:\\Users\\Public\\a.dll' })
  })

  it('treats a reused pid as a new process', () => {
    const reused = buildProcessModel([...events, create(60, 2, 1, 'C:\\Windows\\notepad.exe')])
    const second = reused.all.filter((proc) => proc.pid === 2)
    expect(second.map((proc) => proc.name)).toEqual(['WINWORD.EXE', 'notepad.exe'])
    expect(second[1]!.children).toHaveLength(0)
  })

  it('keeps a process whose parent was never seen as a root', () => {
    const orphan = buildProcessModel([create(5, 900, 77, '/usr/sbin/sshd')])
    expect(orphan.roots).toHaveLength(1)
  })

  it('walks the lineage from the root down', () => {
    const shell = model.all.find((proc) => proc.pid === 3)!
    expect(lineage(shell).map((proc) => proc.name)).toEqual(['explorer.exe', 'WINWORD.EXE', 'powershell.exe'])
  })
})

describe('layoutProcessTree', () => {
  const model = buildProcessModel(events)
  const layout = layoutProcessTree(model, ALL)

  it('stacks identical idle leaves into one node', () => {
    const stacked = layout.nodes.find((node) => node.procs[0]!.name === 'svchost.exe')!
    expect(stacked.procs).toHaveLength(3)
    expect(layout.nodes).toHaveLength(4)
  })

  it('moves one column right per generation and centres a parent on its children', () => {
    const byName = (name: string) => layout.nodes.find((node) => node.procs[0]!.name === name)!
    expect(byName('WINWORD.EXE').x).toBeGreaterThan(byName('explorer.exe').x)
    expect(byName('powershell.exe').x).toBeGreaterThan(byName('WINWORD.EXE').x)
    const children = layout.nodes.filter((node) => node.parentId === byName('explorer.exe').id).map((node) => node.y)
    expect(byName('explorer.exe').y).toBeGreaterThanOrEqual(Math.min(...children))
    expect(byName('explorer.exe').y).toBeLessThanOrEqual(Math.max(...children))
  })

  it('never puts two nodes on the same spot and reports a size that contains them', () => {
    const spots = new Set(layout.nodes.map((node) => `${node.x},${node.y}`))
    expect(spots.size).toBe(layout.nodes.length)
    for (const node of layout.nodes) {
      expect(node.x).toBeLessThan(layout.width)
      expect(node.y).toBeLessThan(layout.height)
    }
  })

  it('survives an endpoint with no telemetry', () => {
    const empty = layoutProcessTree(buildProcessModel([]), ALL)
    expect(empty.nodes).toEqual([])
    expect(empty.height).toBeGreaterThan(0)
  })
})

describe('focus, folding and stacks', () => {
  const model = buildProcessModel(events)
  const pid = (value: number) => model.all.find((proc) => proc.pid === value)!

  it('rates an interpreter that talks to the network above everything else', () => {
    expect(severity(pid(3))).toBe('alert')
    expect(severity(pid(2))).toBe('plain')
    expect([...alertTrail(model)].sort()).toEqual([pid(1).key, pid(2).key, pid(3).key].sort())
  })

  it('keeps only the branches that lead to something notable and counts the rest', () => {
    const layout = layoutProcessTree(model, NOTABLE)
    expect(layout.nodes.filter((node) => node.kind === 'proc').map((node) => node.procs[0]!.name)).toEqual([
      'explorer.exe',
      'WINWORD.EXE',
      'powershell.exe',
    ])
    const quiet = layout.byId.get(quietId(pid(1).key))!
    expect(quiet.procs).toHaveLength(3)
    expect(layout.nodeOf.get(pid(4).key)).toBe(quiet.id)
  })

  it('folds a subtree into its parent and says how much is hidden', () => {
    const layout = layoutProcessTree(model, { ...ALL, folded: new Set([pid(2).key]) })
    const word = layout.byId.get(pid(2).key)!
    expect(word.hidden).toBe(1)
    expect(layout.nodeOf.get(pid(3).key)).toBe(word.id)
    expect(layout.byId.has(pid(3).key)).toBe(false)
  })

  it('opens a stack into one node per process', () => {
    const closed = layoutProcessTree(model, ALL)
    expect(closed.byId.get(stackId(pid(1).key, 'svchost.exe'))!.procs).toHaveLength(3)
    const open = layoutProcessTree(model, { ...ALL, opened: new Set([stackId(pid(1).key, 'svchost.exe')]) })
    expect(open.nodes.filter((node) => node.procs[0]!.name === 'svchost.exe')).toHaveLength(3)
  })

  it('exposes a hidden process by unfolding and opening exactly what hides it', () => {
    const hot = hotSet(model)
    const folded = { ...NOTABLE, folded: new Set([pid(1).key, pid(2).key]) }
    for (const target of [pid(3), pid(5)]) {
      const next = expose(target, folded, hot)
      expect(layoutProcessTree(model, next).nodeOf.get(target.key)).toBe(target.key)
    }
    expect(expose(pid(1), NOTABLE, hot).opened.has(quietId(ROOT))).toBe(false)
  })

  it('steps to the parent, the first child and the neighbours in a column', () => {
    const layout = layoutProcessTree(model, { ...ALL, opened: new Set([stackId(pid(1).key, 'svchost.exe')]) })
    expect(stepNode(layout, pid(2).key, 'left')!.id).toBe(pid(1).key)
    expect(stepNode(layout, pid(2).key, 'right')!.id).toBe(pid(3).key)
    expect(stepNode(layout, pid(2).key, 'down')!.id).toBe(pid(4).key)
    expect(stepNode(layout, pid(4).key, 'up')!.id).toBe(pid(2).key)
    expect(stepNode(layout, pid(1).key, 'left')).toBeNull()
  })
})

describe('findProcs', () => {
  const model = buildProcessModel(events)

  it('matches names, command lines and exact pids without caring about case', () => {
    expect(findProcs(model, 'WINWORD').map((proc) => proc.pid)).toEqual([2])
    expect(findProcs(model, '-enc').map((proc) => proc.pid)).toEqual([3])
    expect(findProcs(model, '4').map((proc) => proc.pid)).toEqual([4])
    expect(findProcs(model, '  ')).toEqual([])
  })
})

describe('apps', () => {
  it('groups processes by image and puts the riskiest first', () => {
    const list = apps(buildProcessModel(events))
    expect(list[0]).toMatchObject({ name: 'powershell.exe', severity: 'alert', connections: 2, bytes: 1000, files: 1 })
    const svchost = list.find((app) => app.name === 'svchost.exe')!
    expect(svchost.procs).toHaveLength(3)
    expect(svchost.running).toBe(3)
    expect(list.find((app) => app.name === 'WINWORD.EXE')!.running).toBe(0)
  })
})

describe('remotes', () => {
  it('adds up connections per destination and names the processes behind them', () => {
    const list = remotes(buildProcessModel(events))
    expect(list).toHaveLength(1)
    expect(list[0]).toMatchObject({ destIp: '203.0.113.9', destPort: 443, count: 2, bytes: 1000 })
    expect(list[0]!.procs.map((proc) => proc.name)).toEqual(['powershell.exe'])
  })
})
