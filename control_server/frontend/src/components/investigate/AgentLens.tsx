import { Activity } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { CloseIncident } from '@/components/common/IncidentCard'
import { JsonView } from '@/components/common/JsonView'
import { Empty } from '@/components/ui/bits'
import type { Period } from '@/lib/activity'
import type { Agent, ApiEvent, Incident } from '@/lib/api'
import { cn } from '@/lib/cn'
import { categoryOf, eventData, incidentTitle, summarize } from '@/lib/events'
import { ago, clock, span } from '@/lib/format'
import { baseName } from '@/lib/images'
import { tone } from '@/lib/palette'
import { buildPulse, type Pulse, type RailEntry } from '@/lib/pulse'
import { useAgentEvents, useSize } from '@/lib/queries'

type Props = {
  agent: Agent
  incidents: Incident[]
  period: Period | null
  now: number
  openId: string | null
  onOpen: (id: string | null) => void
}

const HEIGHT = 124
const BASE = 82
const PEAK = 34
const PIN = 14
const TICKS = 5
const FEW_TICKS = 3
const TIGHT = 440

function level(event: ApiEvent): string {
  const data = eventData(event)
  return typeof data.level === 'string' ? data.level : ''
}

function entryColor(entry: RailEntry): string {
  if (entry.kind === 'incident') return tone('alert')
  if (entry.kind !== 'event') return tone('faint')
  if (entry.event.event_type === 'detection') return level(entry.event) === 'high' ? tone('alert') : tone('warn')
  return categoryOf(entry.event.event_type).color
}

function entryLabel(entry: RailEntry): string {
  if (entry.kind === 'incident') return incidentTitle(entry.incident)
  if (entry.kind !== 'event') return ''
  const data = eventData(entry.event)
  return entry.event.event_type === 'detection' && typeof data.title === 'string' ? data.title : entry.event.event_type
}

function Trace({
  pulse,
  incidents,
  openId,
  onOpen,
}: {
  pulse: Pulse
  incidents: Incident[]
  openId: string | null
  onOpen: (id: string) => void
}) {
  const [frame, { width }] = useSize<HTMLDivElement>()
  const [hover, setHover] = useState<number | null>(null)

  const { from, to } = pulse
  const x = (time: number) => ((Math.min(Math.max(time, from), to) - from) / (to - from)) * width
  const path = useMemo(() => {
    const scale = (time: number) => ((time - from) / (to - from)) * width
    const spikes = pulse.beats
      .filter((beat) => beat >= from && beat <= to)
      .map((beat) => {
        const at = scale(beat)
        return `L${at - 2.2} ${BASE} L${at - 1} ${BASE + 4} L${at} ${BASE - PEAK} L${at + 1} ${BASE + 9} L${at + 2.2} ${BASE}`
      })
    return `M0 ${BASE} ${spikes.join(' ')} L${width} ${BASE}`
  }, [pulse.beats, from, to, width])
  const pins = pulse.rail.filter((entry) => entry.kind === 'event' || entry.kind === 'incident')
  const ticks = width < TIGHT ? FEW_TICKS : TICKS

  return (
    <div
      ref={frame}
      className="relative"
      style={{ height: HEIGHT }}
      onMouseMove={(event) => setHover(event.clientX - event.currentTarget.getBoundingClientRect().left)}
      onMouseLeave={() => setHover(null)}
    >
      {width > 0 ? (
        <svg width={width} height={HEIGHT} role="img" aria-label={`${pulse.beats.length} signed heartbeats, ${pulse.silences.length} silent gaps`}>
          {incidents.map((incident) => {
            const start = x(incident.opened_at)
            return (
              <g key={incident.id}>
                <rect x={start} y={0} width={Math.max(2, x(incident.closed_at ?? to) - start)} height={HEIGHT - 20} className="fill-alert/10" />
                <line x1={start} x2={start} y1={0} y2={HEIGHT - 20} className="stroke-alert/60" />
              </g>
            )
          })}
          <path d={path} fill="none" strokeWidth={1.25} strokeLinejoin="round" className="stroke-text" />
          {pulse.silences.map((silence) => {
            const start = x(silence.from)
            const end = x(silence.to)
            return (
              <g key={silence.from}>
                <line x1={start + 3} x2={end - 3} y1={BASE} y2={BASE} strokeWidth={2.5} strokeDasharray="2 5" className="stroke-alert" />
                {end - start > 84 ? (
                  <text x={(start + end) / 2} y={BASE - 9} textAnchor="middle" className="fill-alert-soft font-mono text-[10px]">
                    silent {span(silence.to - silence.from)}
                  </text>
                ) : null}
              </g>
            )
          })}
          {pins.map((entry) => {
            const at = x(entry.at)
            const picked = entry.id === openId
            return (
              <g
                key={entry.id}
                role="button"
                tabIndex={0}
                aria-label={`${entryLabel(entry)} at ${clock(entry.at)}`}
                onClick={() => onOpen(entry.id)}
                onKeyDown={(event) => {
                  if (event.key === 'Enter' || event.key === ' ') onOpen(entry.id)
                }}
                className="cursor-pointer outline-none"
              >
                <title>{`${entryLabel(entry)} · ${clock(entry.at)}`}</title>
                <line x1={at} x2={at} y1={PIN} y2={BASE} strokeDasharray="1 3" style={{ stroke: entryColor(entry) }} opacity={picked ? 0.9 : 0.45} />
                <circle cx={at} cy={PIN} r={picked ? 5 : 3.5} style={{ fill: entryColor(entry) }} />
                {picked ? <circle cx={at} cy={PIN} r={8} fill="none" style={{ stroke: entryColor(entry) }} opacity={0.5} /> : null}
                <rect x={at - 7} y={PIN - 9} width={14} height={18} fill="transparent" />
              </g>
            )
          })}
          {Array.from({ length: ticks }, (_, index) => {
            const time = from + ((to - from) * index) / (ticks - 1)
            return (
              <text
                key={index}
                x={(width * index) / (ticks - 1)}
                y={HEIGHT - 5}
                textAnchor={index === 0 ? 'start' : index === ticks - 1 ? 'end' : 'middle'}
                className="fill-faint font-mono text-[10px]"
              >
                {clock(time)}
              </text>
            )
          })}
          {hover !== null ? (
            <g pointerEvents="none">
              <line x1={hover} x2={hover} y1={0} y2={HEIGHT - 20} className="stroke-line-hover" />
              <text x={hover < width - 70 ? hover + 6 : hover - 6} y={HEIGHT - 26} textAnchor={hover < width - 70 ? 'start' : 'end'} className="fill-soft font-mono text-[10px]">
                {clock(from + (hover / width) * (to - from))}
              </text>
            </g>
          ) : null}
        </svg>
      ) : null}
    </div>
  )
}

function Row({
  entry,
  interval,
  open,
  onToggle,
  incidents,
  now,
  live,
}: {
  entry: RailEntry
  interval: number
  open: boolean
  onToggle: () => void
  incidents: Incident[]
  now: number
  live: boolean
}) {
  const grid = 'grid grid-cols-[60px_20px_minmax(0,1fr)] gap-x-2'
  const line = (className: string) => <span className={cn('absolute inset-y-0 left-1/2 -translate-x-1/2', className)} aria-hidden />

  if (entry.kind === 'beats') {
    return (
      <li data-rail="beats" className={cn(grid, 'min-h-8 items-center font-mono text-[11px] text-muted')}>
        <span className="text-faint">{clock(entry.at)}</span>
        <span className="relative flex h-full items-center justify-center">
          {line('w-px bg-line-strong')}
          <Activity size={12} strokeWidth={1.75} className="relative bg-ink text-faint" aria-hidden />
        </span>
        <span className="truncate">
          {entry.count} signed {entry.count === 1 ? 'heartbeat' : `heartbeats, every ${span(interval)}, since ${clock(entry.from)}`}
        </span>
      </li>
    )
  }

  if (entry.kind === 'silence') {
    return (
      <li data-rail="silence" className={cn(grid, 'min-h-9 items-center font-mono text-[11px] text-alert-soft')}>
        <span className="text-faint">{clock(entry.at)}</span>
        <span className="relative flex h-full items-center justify-center">
          {line('border-l border-dashed border-alert')}
          <span className="relative h-2 w-2 rounded-full border border-alert bg-ink" aria-hidden />
        </span>
        <span className="truncate">
          No heartbeat for {span(entry.at - entry.from)}
          {entry.ongoing && live ? ', still silent' : ''}
        </span>
      </li>
    )
  }

  const incident = entry.kind === 'incident' ? entry.incident : undefined
  const event = entry.kind === 'event' ? entry.event : undefined
  const data = event ? eventData(event) : {}
  const finding = event?.event_type === 'detection'
  const closable = incident ?? (finding ? incidents.find((item) => item.closed_at == null && item.incident_type === `detection.${String(data.rule)}`) : undefined)
  const openIncident = incident && incident.closed_at == null
  const meta = incident
    ? `${incident.incident_type} · ${incident.closed_at == null ? `open ${ago(incident.opened_at, now)}` : `closed after ${span(incident.closed_at - incident.opened_at)}`}`
    : finding
      ? `${String(data.technique)} · ${baseName(String(data.image))}`
      : event
        ? summarize(event)
        : ''

  return (
    <li data-rail={incident ? 'incident' : finding ? 'finding' : 'event'} data-rail-id={entry.id} className={cn(grid, 'items-start')}>
      <span className="pt-[9px] font-mono text-[11px] text-muted">{clock(entry.at)}</span>
      <span className="relative flex h-full justify-center pt-[13px]">
        {line('w-px bg-line')}
        <span
          className={cn('relative h-2 w-2 rounded-full', openIncident && 'ring-4 ring-alert/25', incident && !openIncident && 'border border-alert bg-ink')}
          style={incident && !openIncident ? undefined : { background: entryColor(entry) }}
          aria-hidden
        />
      </span>
      <div className={cn('mb-1 min-w-0 rounded-lg border border-transparent', open && 'border-line bg-surface', openIncident && 'border-alert-line bg-alert-surface')}>
        <div className="flex items-center gap-1 pr-1">
          <button type="button" aria-expanded={open} onClick={onToggle} className="flex min-h-9 min-w-0 flex-1 flex-wrap items-baseline gap-x-3 rounded-lg px-2.5 py-1.5 text-left hover:bg-raised">
            <span className={cn('min-w-0 truncate', incident || finding ? 'text-[13px] text-text' : 'font-mono text-xs text-text', openIncident && 'font-medium text-accent-strong')}>
              {entryLabel(entry)}
            </span>
            <span className={cn('min-w-0 truncate font-mono text-[11px]', openIncident ? 'text-alert-soft' : 'text-muted')}>{meta}</span>
          </button>
          {closable ? <CloseIncident incident={closable} /> : null}
        </div>
        {open ? <JsonView value={incident ? incident.evidence : data} className="rounded-t-none border-x-0 border-b-0 border-t border-line/60 bg-transparent" /> : null}
      </div>
    </li>
  )
}

export function AgentLens({ agent, incidents, period, now, openId, onOpen }: Props) {
  const { data, isLoading } = useAgentEvents(agent.id)
  const end = period ? Math.min(now, period[1]) : now
  const pulse = useMemo(() => {
    const within = (from: number, to: number) => !period || (from <= period[1] && to >= period[0])
    return buildPulse(
      (data ?? []).filter((event) => within(event.timestamp, event.timestamp)),
      incidents.filter((incident) => within(incident.opened_at, incident.closed_at ?? end)),
      end,
      period ? [period[0], end] : null,
    )
  }, [data, incidents, period, end])
  const shown = useMemo(() => {
    const ids = new Set(pulse.rail.filter((entry) => entry.kind === 'incident').map((entry) => entry.id))
    return incidents.filter((incident) => ids.has(incident.id) || (incident.incident_type.startsWith('detection.') && incident.opened_at <= pulse.to && (incident.closed_at ?? pulse.to) >= pulse.from))
  }, [incidents, pulse])
  const rail = useRef<HTMLOListElement>(null)

  useEffect(() => {
    if (!openId) return
    rail.current?.querySelector(`[data-rail-id="${CSS.escape(openId)}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [openId])

  if (!isLoading && pulse.rail.length === 0) {
    return <Empty title={period ? 'Nothing from the agent in this time window' : 'Nothing from the agent yet'} />
  }

  const gaps = pulse.silences.length
  return (
    <div className="absolute inset-0 overflow-auto px-4 pb-3">
      <section aria-label="Signed heartbeats" className="rounded-card border border-line bg-surface px-3 pb-1 pt-2">
        <div className="flex h-6 items-center justify-between gap-3">
          <h3 className="font-display text-[11px] uppercase tracking-wider text-muted">Signed heartbeats</h3>
          <span className="truncate font-mono text-[11px] text-muted">
            {pulse.beats.length} beats, every {span(pulse.interval)}
            {gaps > 0 ? `, ${gaps} silent ${gaps === 1 ? 'gap' : 'gaps'}` : ''}
          </span>
        </div>
        <Trace pulse={pulse} incidents={shown} openId={openId} onOpen={onOpen} />
      </section>
      <ol ref={rail} aria-label="What the agent reported" className="mt-3">
        {pulse.rail.map((entry) => (
          <Row
            key={entry.id}
            entry={entry}
            interval={pulse.interval}
            open={entry.id === openId}
            onToggle={() => onOpen(entry.id === openId ? null : entry.id)}
            incidents={incidents}
            now={now}
            live={!period}
          />
        ))}
      </ol>
    </div>
  )
}
