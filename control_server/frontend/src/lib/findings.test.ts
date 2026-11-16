import { describe, expect, it } from 'vitest'
import type { ApiEvent, WindowView } from './api'
import { findingOf, findingsByProcess, proofOf, releaseOf, type Finding } from './findings'
import { buildProcessModel, severity } from './process-tree'

const EVIDENCE = {
  rule: 'server-child',
  title: 'Server process started a shell',
  technique: 'T1505.003',
  level: 'high',
  pid: 21,
  started_at: 2,
  image: '/bin/sh',
  command: '/bin/sh -c id',
  parent: 'nginx',
  subject: null,
  autostart: null,
  trigger: 7,
  window: 3,
  proof: 'pending',
}

function finding(more: Record<string, unknown> = {}): Finding {
  return findingOf({ ...EVIDENCE, ...more })!
}

function windowView(proof: string, proven: boolean): WindowView {
  return {
    header: { epoch: 1, window: 3, first_index: 6, count: 2, fresh: false, gap: false, prev_head: 'a', root: 'b', head: 'c' },
    received_at: 100,
    proving: proof !== 'none',
    proof,
    events: [],
    releases: [{ trigger: 7, rule: 'server-child', title: 'Server process started a shell', technique: 'T1505.003', level: 'high', context: [0], proven }],
  }
}

let serial = 0
function event(type: string, timestamp: number, data: Record<string, unknown>): ApiEvent {
  serial += 1
  return { id: `f${serial}`, agent_id: 'a1', event_type: type, timestamp, data: JSON.stringify(data), received_at: timestamp }
}
const run = (timestamp: number, pid: number, ppid: number, path: string) =>
  event('process', timestamp, { action: 'Create', pid, ppid, executable_path: path, command_line: [path], uid: 33 })

describe('findingOf', () => {
  it('reads what the server tells about a rule that fired, with where it sits in the chain', () => {
    expect(finding()).toEqual({
      rule: 'server-child',
      title: 'Server process started a shell',
      technique: 'T1505.003',
      level: 'high',
      processKey: '21@2',
      image: '/bin/sh',
      autostart: null,
      subject: null,
      trigger: 7,
      window: 3,
      proven: false,
    })
    expect(finding({ level: 'medium', proof: 'verified' })).toMatchObject({ level: 'medium', proven: true })
    expect(finding({ autostart: 'cron', subject: 'sysupdate', pid: 0 })).toMatchObject({ autostart: 'cron', subject: 'sysupdate' })
  })

  it('reads nothing out of evidence that is not a finding', () => {
    expect(findingOf({ reason: 'the agent service was stopped' })).toBeNull()
    expect(findingOf({})).toBeNull()
  })
})

describe('findings of a process', () => {
  it('come from the server and land on the process they name, the high ones first', () => {
    const findings = [finding({ rule: 'shell-network', level: 'medium', trigger: 9 }), finding(), finding(), finding({ rule: 'autostart-fetch', autostart: 'cron', pid: 0 })]
    expect(findingsByProcess(findings).get('21@2')!.map((found) => found.rule)).toEqual(['server-child', 'shell-network'])
    expect([...findingsByProcess(findings).keys()]).toEqual(['21@2'])

    const model = buildProcessModel([run(1, 20, 0, '/usr/sbin/nginx'), run(2, 21, 20, '/bin/sh')], findings)
    expect(model.all.map((proc) => [proc.name, proc.findings.map((found) => found.rule), severity(proc)])).toEqual([
      ['nginx', [], 'plain'],
      ['sh', ['server-child', 'shell-network'], 'alert'],
    ])
  })

  it('are none when the server told none, whatever the process looks like', () => {
    const model = buildProcessModel([run(1, 20, 0, '/usr/sbin/nginx'), run(2, 21, 20, '/bin/sh'), run(3, 22, 0, '/tmp/.x/kworker')])
    expect(model.all.flatMap((proc) => proc.findings)).toEqual([])
  })
})

describe('proofOf', () => {
  it('follows the release in its window, and the evidence until the window is known', () => {
    expect(proofOf(finding(), undefined)).toBe('pending')
    expect(proofOf(finding({ proof: 'verified' }), undefined)).toBe('verified')
    expect(proofOf(finding(), windowView('pending', false))).toBe('pending')
    expect(proofOf(finding(), windowView('verified', true))).toBe('verified')
    expect(proofOf(finding(), windowView('none', false))).toBe('none')
  })

  it('tells a release the proof left out from one it holds, in a window whose proof did not match', () => {
    expect(proofOf(finding(), windowView('mismatch', false))).toBe('mismatch')
    expect(proofOf(finding(), windowView('mismatch', true))).toBe('verified')
  })

  it('finds the release by rule and trigger', () => {
    expect(releaseOf(finding(), windowView('pending', false))?.context).toEqual([0])
    expect(releaseOf(finding({ trigger: 8 }), windowView('pending', false))).toBeUndefined()
    expect(releaseOf(finding({ rule: 'reverse-shell' }), windowView('pending', false))).toBeUndefined()
  })
})
