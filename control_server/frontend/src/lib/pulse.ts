import type { ApiEvent, Incident } from './api'

export type RailEntry =
  | { kind: 'event'; id: string; at: number; event: ApiEvent }
  | { kind: 'incident'; id: string; at: number; incident: Incident }
  | { kind: 'beats'; id: string; at: number; from: number; count: number }
  | { kind: 'silence'; id: string; at: number; from: number; ongoing: boolean }

export type Silence = { from: number; to: number; ongoing: boolean }

export type Pulse = {
  beats: number[]
  interval: number
  silences: Silence[]
  rail: RailEntry[]
  from: number
  to: number
}

const DEFAULT_INTERVAL = 30
const SHORTEST_VIEW = 900
const OWN_ROW = new Set(['heartbeat', 'incident_opened', 'incident_closed'])

function median(values: number[]): number {
  const sorted = [...values].sort((a, b) => a - b)
  return sorted[Math.floor(sorted.length / 2)]!
}

export function buildPulse(events: ApiEvent[], incidents: Incident[], now: number, view: [number, number] | null = null): Pulse {
  const beats = events
    .filter((event) => event.event_type === 'heartbeat')
    .map((event) => event.timestamp)
    .sort((a, b) => a - b)
  const gaps = beats.slice(1).map((beat, index) => beat - beats[index]!)
  const interval = gaps.length > 0 ? Math.max(1, median(gaps)) : DEFAULT_INTERVAL
  const limit = Math.max(interval * 3, 90)

  const entries: RailEntry[] = [
    ...events.filter((event) => !OWN_ROW.has(event.event_type)).map((event) => ({ kind: 'event' as const, id: event.id, at: event.timestamp, event })),
    ...incidents
      .filter((incident) => !incident.incident_type.startsWith('detection.'))
      .map((incident) => ({ kind: 'incident' as const, id: incident.id, at: incident.opened_at, incident })),
  ].sort((a, b) => a.at - b.at)

  const rail: RailEntry[] = []
  const silences: Silence[] = []
  let run: { from: number; to: number; count: number } | null = null
  let lastBeat: number | null = null
  let afterRun = 0
  const flush = () => {
    if (!run) return
    rail.push({ kind: 'beats', id: `beats:${run.from}`, at: run.to, from: run.from, count: run.count })
    afterRun = rail.length
    run = null
  }
  const silent = (from: number, to: number, ongoing: boolean) => {
    flush()
    silences.push({ from, to, ongoing })
    rail.splice(afterRun, 0, { kind: 'silence', id: `silence:${from}`, at: to, from, ongoing })
  }

  let next = 0
  for (const beat of beats) {
    while (next < entries.length && entries[next]!.at < beat) {
      flush()
      rail.push(entries[next++]!)
    }
    if (lastBeat !== null && beat - lastBeat > limit) silent(lastBeat, beat, false)
    run = run ? { from: run.from, to: beat, count: run.count + 1 } : { from: beat, to: beat, count: 1 }
    lastBeat = beat
  }
  flush()
  rail.push(...entries.slice(next))
  if (lastBeat !== null && now - lastBeat > limit) silent(lastBeat, now, true)

  const first = Math.min(beats[0] ?? now, entries[0]?.at ?? now)
  const [from, to] = view ?? [Math.min(first, now - SHORTEST_VIEW), now]
  return { beats, interval, silences, rail: rail.reverse(), from, to }
}
