import { describe, expect, it } from 'vitest'
import { binIndex, binPeriod, buildActivity, inPeriod, nextMember } from './activity'
import type { ApiEvent } from './api'
import { findingOf } from './findings'
import { buildProcessModel } from './process-tree'

let serial = 0

function event(type: string, timestamp: number, data: Record<string, unknown>): ApiEvent {
  serial += 1
  return { id: `e${serial}`, agent_id: 'a1', event_type: type, timestamp, data: JSON.stringify(data), received_at: timestamp }
}

const create = (timestamp: number, pid: number, ppid: number, path: string) =>
  event('process', timestamp, { action: 'Create', pid, ppid, executable_path: path, command_line: [path], uid: 1000 })

const connect = (timestamp: number, pid: number, port: number, sent: number, received: number) =>
  event('network', timestamp, { action: 'Connect', pid, protocol: 'tcp', dest_ip: '203.0.113.9', dest_port: port, bytes_sent: sent, bytes_received: received })

const flagged = (pid: number, started_at: number, level = 'high') =>
  findingOf({ rule: 'shell-network', title: 'Shell with an outbound connection', technique: 'T1071', level, pid, started_at })!

const model = buildProcessModel([
  create(100, 1, 0, 'C:\\Windows\\explorer.exe'),
  create(105, 2, 1, 'C:\\Windows\\System32\\svchost.exe'),
  create(108, 3, 1, 'C:\\Windows\\System32\\svchost.exe'),
  create(150, 4, 1, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'),
  connect(152, 4, 443, 1000, 9000),
  connect(190, 4, 8443, 200, 300),
  connect(120, 2, 443, 50, 50),
  event('file', 155, { action: 'Write', pid: 4, path: 'C:\\Users\\Public\\a.dll' }),
  event('file', 125, { action: 'Write', pid: 2, path: 'C:\\Windows\\Temp\\svc.log' }),
], [flagged(4, 150)])

describe('bins', () => {
  it('maps a time to its bin and back to the seconds that bin covers', () => {
    expect(binIndex(100, 100, 200, 10)).toBe(0)
    expect(binIndex(155, 100, 200, 10)).toBe(5)
    expect(binIndex(200, 100, 200, 10)).toBe(9)
    expect(binIndex(99, 100, 200, 10)).toBeNull()
    expect(binPeriod(5, 100, 200, 10)).toEqual([150, 160])
  })
})

describe('buildActivity', () => {
  const activity = buildActivity(model, 100, 200, 10)

  it('counts launches per bin and names what ran', () => {
    expect(activity.bins.processes.map((bin) => bin.count)).toEqual([3, 0, 0, 0, 0, 1, 0, 0, 0, 0])
    expect(activity.bins.processes[0]!.names).toEqual(['svchost.exe ×2', 'explorer.exe'])
    expect(activity.peaks.processes).toBe(3)
  })

  it('weighs the network lane by bytes', () => {
    expect(activity.bins.network[5]).toMatchObject({ count: 1, weight: 10000, names: ['203.0.113.9:443'] })
    expect(activity.bins.network[2]).toMatchObject({ count: 1, weight: 100 })
    expect(activity.peaks.network).toBe(10000)
  })

  it('marks what an analyst should click: risky launches, their connections and their file writes', () => {
    const shell = model.all.find((proc) => proc.pid === 4)!
    expect(activity.marks.map((group) => [group.lane, group.bin, group.severity, group.members.map((member) => member.time)])).toEqual([
      ['processes', 5, 'alert', [150]],
      ['network', 5, 'alert', [152]],
      ['network', 9, 'alert', [190]],
      ['files', 5, 'alert', [155]],
    ])
    expect(activity.marks.every((group) => group.members.every((member) => member.key === shell.key))).toBe(true)
    expect(activity.bins.files[2]).toMatchObject({ count: 1, names: ['svc.log'] })
  })

  it('leaves out what happened outside the window', () => {
    const late = buildActivity(model, 160, 200, 4)
    expect(late.bins.processes.every((bin) => bin.count === 0)).toBe(true)
    expect(late.marks.flatMap((group) => group.members.map((member) => member.time))).toEqual([190])
  })
})

describe('marks that share a slot', () => {
  const crowded = buildProcessModel([
    create(100, 1, 0, 'C:\\Windows\\explorer.exe'),
    create(150, 2, 1, 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe'),
    connect(151, 2, 443, 10, 10),
    create(152, 3, 2, 'C:\\Windows\\System32\\rundll32.exe'),
    connect(153, 3, 443, 10, 10),
  ], [flagged(2, 150, 'medium'), flagged(3, 152)])
  const group = buildActivity(crowded, 100, 200, 10).marks.find((item) => item.lane === 'processes')!
  const key = (pid: number) => crowded.all.find((proc) => proc.pid === pid)!.key

  it('become one mark that takes the worst severity', () => {
    expect(group.members).toHaveLength(2)
    expect(group.severity).toBe('alert')
  })

  it('steps through its processes on repeated clicks', () => {
    expect(nextMember(group, null).key).toBe(key(2))
    expect(nextMember(group, key(2)).key).toBe(key(3))
    expect(nextMember(group, key(3)).key).toBe(key(2))
  })
})

describe('inPeriod', () => {
  const pid = (value: number) => model.all.find((proc) => proc.pid === value)!

  it('keeps a process that started, connected or wrote inside the period', () => {
    expect(inPeriod(pid(4), [140, 160])).toBe(true)
    expect(inPeriod(pid(4), [185, 195])).toBe(true)
    expect(inPeriod(pid(2), [115, 125])).toBe(true)
    expect(inPeriod(pid(3), [115, 125])).toBe(false)
    expect(inPeriod(pid(1), [140, 160])).toBe(false)
  })
})
