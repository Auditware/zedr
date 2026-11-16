import { useMemo } from 'react'
import type { ApiEvent, Incident } from '@/lib/api'
import { cn } from '@/lib/cn'
import { categoryOf, incidentTitle, summarize } from '@/lib/events'
import { clock, span } from '@/lib/format'

export type Lane = { id: string; label: string; events: ApiEvent[]; incidents: Incident[] }

const QUIET_AFTER = 100

type TrackProps = { lane: Lane; from: number; to: number; now: number; tall: boolean; onIncident?: (incident: Incident) => void }

export function LaneTrack({ lane, from, to, now, tall, onIncident }: TrackProps) {
  const width = Math.max(1, to - from)
  const at = (timestamp: number) => `${Math.min(100, Math.max(0, ((timestamp - from) / width) * 100))}%`
  const between = (start: number, end: number) => ({
    left: at(start),
    width: `calc(${at(end)} - ${at(start)})`,
  })

  const model = useMemo(() => {
    const beats = lane.events
      .filter((event) => event.event_type === 'heartbeat')
      .map((event) => event.timestamp)
      .sort((a, b) => a - b)
    const gaps: [number, number][] = []
    for (let i = 0; i < beats.length; i++) {
      const start = beats[i]!
      const end = i + 1 < beats.length ? beats[i + 1]! : now
      if (end - start > QUIET_AFTER && end > from && start < to) gaps.push([Math.max(start, from), Math.min(end, to)])
    }
    if (beats.length === 0) gaps.push([from, to])
    else if (beats[0]! > from + QUIET_AFTER && lane.events.length >= 300) gaps.unshift([from, beats[0]!])
    return {
      beats: beats.filter((beat) => beat >= from && beat <= to),
      gaps,
      marks: lane.events.filter(
        (event) => event.event_type !== 'heartbeat' && event.timestamp >= from && event.timestamp <= to,
      ),
      incidents: lane.incidents.filter(
        (incident) => incident.opened_at <= to && (incident.closed_at ?? now) >= from,
      ),
    }
  }, [lane, from, to, now])

  return (
    <div
      className={cn('relative min-w-0 flex-1 overflow-hidden rounded-lg bg-sunken', tall ? 'h-[92px]' : 'h-[30px]')}
      role="group"
      aria-label={`${lane.label}: ${model.beats.length} heartbeats, ${model.incidents.length} incidents`}
    >
      {model.gaps.map(([start, end], index) => (
        <div
          key={index}
          className="absolute bottom-0 top-0 bg-[repeating-linear-gradient(135deg,var(--color-hairline)_0_5px,transparent_5px_10px)]"
          style={between(start, end)}
          title={`No heartbeat for ${span(end - start)}`}
        />
      ))}
      {model.incidents.map((incident) => (
        <button
          key={incident.id}
          type="button"
          data-mark="incident"
          disabled={!onIncident}
          onClick={() => onIncident?.(incident)}
          aria-label={`${incidentTitle(incident)}, ${clock(incident.opened_at)}`}
          className={cn(
            'absolute bottom-0 top-0 z-10 min-w-2 border-l-2 border-alert enabled:cursor-pointer enabled:hover:bg-alert/25',
            incident.closed_at == null ? 'bg-alert/15' : 'bg-alert/[0.07]',
          )}
          style={between(Math.max(incident.opened_at, from), Math.min(incident.closed_at ?? now, to))}
          title={`${incident.incident_type}: ${incidentTitle(incident)}, ${clock(incident.opened_at)}`}
        />
      ))}
      <div className={cn('absolute left-0 right-0 h-px bg-line', tall ? 'top-[34px]' : 'top-1/2')} />
      {model.beats.map((beat, index) => (
        <div
          key={index}
          className={cn('absolute w-[1.5px] rounded-full bg-accent', tall ? 'top-[14px] h-[40px]' : 'top-[7px] h-[16px]')}
          style={{ left: at(beat) }}
        />
      ))}
      {model.marks.map((event) => (
        <div
          key={event.id}
          className={cn(
            'absolute -translate-x-1/2 rotate-45 rounded-[2px]',
            tall ? 'top-[66px] h-3 w-3' : 'top-[11px] h-2 w-2',
          )}
          style={{ left: at(event.timestamp), background: categoryOf(event.event_type).color }}
          title={`${clock(event.timestamp)} ${event.event_type} ${summarize(event)}`}
        />
      ))}
    </div>
  )
}

type Props = {
  lanes: Lane[]
  seconds: number
  now: number
  onPick?: (id: string) => void
}

export function Timeline({ lanes, seconds, now, onPick }: Props) {
  const from = now - seconds
  const tall = lanes.length === 1
  const ticks = [0, 0.25, 0.5, 0.75].map((fraction) => from + Math.round(seconds * fraction))

  return (
    <div className="flex min-h-0 flex-1 flex-col gap-1">
      <div className="flex min-h-0 flex-1 flex-col gap-1 overflow-y-auto">
        {lanes.map((lane) => (
          <div key={lane.id} className="flex shrink-0 items-center gap-3">
            {tall ? null : (
              <button
                type="button"
                onClick={() => onPick?.(lane.id)}
                className="w-[132px] shrink-0 truncate rounded-md px-1.5 py-1 text-left font-mono text-xs text-soft hover:bg-raised hover:text-text"
              >
                {lane.label}
              </button>
            )}
            <LaneTrack lane={lane} from={from} to={now} now={now} tall={tall} />
          </div>
        ))}
      </div>
      <div className={cn('flex shrink-0 justify-between font-mono text-[10px] text-muted', !tall && 'pl-[144px]')}>
        {ticks.map((tick) => (
          <span key={tick}>{clock(tick)}</span>
        ))}
        <span className="text-soft">now</span>
      </div>
    </div>
  )
}
