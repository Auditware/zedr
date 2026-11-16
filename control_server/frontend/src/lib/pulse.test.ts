import { describe, expect, it } from 'vitest'
import type { ApiEvent, Incident } from './api'
import { buildPulse } from './pulse'

let serial = 0
function event(type: string, timestamp: number): ApiEvent {
  return { id: `e${++serial}`, agent_id: 'a1', event_type: type, timestamp, received_at: timestamp, data: '{}' }
}

function beats(from: number, count: number, every = 30): ApiEvent[] {
  return Array.from({ length: count }, (_, index) => event('heartbeat', from + index * every))
}

function incident(type: string, opened: number, closed: number | null = null): Incident {
  return { id: `i${++serial}`, agent_id: 'a1', incident_type: type, evidence: '{}', opened_at: opened, closed_at: closed }
}

function shape(rail: ReturnType<typeof buildPulse>['rail']): string[] {
  return rail.map((entry) => (entry.kind === 'event' ? entry.event.event_type : entry.kind === 'beats' ? `beats x${entry.count}` : entry.kind))
}

describe('buildPulse', () => {
  it('folds steady heartbeats into one run and reads their interval', () => {
    const pulse = buildPulse(beats(1000, 20), [], 1000 + 19 * 30 + 10)
    expect(pulse.interval).toBe(30)
    expect(pulse.silences).toEqual([])
    expect(shape(pulse.rail)).toEqual(['beats x20'])
  })

  it('splits the run where the agent went quiet, and puts what happened meanwhile after the silence began', () => {
    const stop = event('agent_stopping', 1310)
    const pulse = buildPulse([...beats(1000, 10), stop, ...beats(2000, 5)], [incident('service_stopped', 1320, 2000)], 2000 + 4 * 30 + 5)
    expect(pulse.silences).toEqual([{ from: 1270, to: 2000, ongoing: false }])
    expect(shape(pulse.rail)).toEqual(['beats x5', 'incident', 'agent_stopping', 'silence', 'beats x10'])
  })

  it('reports an agent that is silent now', () => {
    const pulse = buildPulse(beats(1000, 4), [], 5000)
    expect(pulse.silences).toEqual([{ from: 1090, to: 5000, ongoing: true }])
    expect(shape(pulse.rail)).toEqual(['silence', 'beats x4'])
  })

  it('leaves out rows that an incident or a finding already stands for', () => {
    const pulse = buildPulse(
      [...beats(1000, 3), event('incident_opened', 1040), event('detection', 1045), event('incident_closed', 1050)],
      [incident('detection.office-child', 1045), incident('replay', 1040, 1050)],
      1070,
    )
    expect(shape(pulse.rail)).toEqual(['beats x1', 'detection', 'incident', 'beats x2'])
  })

  it('always shows at least a quarter of an hour', () => {
    const pulse = buildPulse(beats(5000, 2), [], 5040)
    expect(pulse.to - pulse.from).toBe(900)
  })

  it('shows exactly the time window it is given', () => {
    const pulse = buildPulse(beats(5000, 2), [], 5040, [4990, 5040])
    expect([pulse.from, pulse.to]).toEqual([4990, 5040])
  })
})
