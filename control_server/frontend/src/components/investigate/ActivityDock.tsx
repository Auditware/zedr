import { X } from 'lucide-react'
import { useMemo, useRef, useState, type PointerEvent } from 'react'
import { LaneTrack } from '@/components/map/Timeline'
import { CollapseToggle } from '@/components/ui/panes'
import { Segmented } from '@/components/ui/segmented'
import { binIndex, binPeriod, buildActivity, nextMember, type ActivityLane, type Period } from '@/lib/activity'
import type { Agent, Incident } from '@/lib/api'
import { cn } from '@/lib/cn'
import { bytes, clock } from '@/lib/format'
import type { ProcessModel } from '@/lib/process-tree'
import { useAgentEvents, useNow } from '@/lib/queries'
import { SEVERITY_DOT } from './probe'

type Range = '15m' | '1h' | '6h'
const RANGES: { id: Range; label: string; seconds: number }[] = [
  { id: '15m', label: '15m', seconds: 900 },
  { id: '1h', label: '1h', seconds: 3600 },
  { id: '6h', label: '6h', seconds: 21600 },
]
const LANES: { id: ActivityLane; label: string }[] = [
  { id: 'processes', label: 'Processes' },
  { id: 'network', label: 'Network' },
  { id: 'files', label: 'Files' },
]
const BINS = 96
const ROW = 22
const GAP = 4
const BRUSH_AFTER = 4

type Props = {
  agent: Agent
  model: ProcessModel
  incidents: Incident[]
  selectedKey: string | null
  period: Period | null
  onSelect: (key: string) => void
  onPeriod: (period: Period | null) => void
  onIncident: (incident: Incident, now: number) => void
  onCollapse: () => void
}

export function ActivityDock({ agent, model, incidents, selectedKey, period, onSelect, onPeriod, onIncident, onCollapse }: Props) {
  const now = useNow(5000)
  const [range, setRange] = useState<Range>('1h')
  const [hover, setHover] = useState<number | null>(null)
  const [brush, setBrush] = useState<{ start: number; end: number } | null>(null)
  const tracksRef = useRef<HTMLDivElement>(null)
  const press = useRef<{ x: number; fraction: number } | null>(null)

  const seconds = RANGES.find((option) => option.id === range)!.seconds
  const from = period ? Math.min(now - seconds, period[0] - Math.ceil((now - period[0]) * 0.05)) : now - seconds
  const width = Math.max(1, now - from)

  const { data: hostEvents } = useAgentEvents(agent.id)
  const activity = useMemo(() => buildActivity(model, from, now, BINS), [model, from, now])
  const selected = selectedKey ? model.byKey.get(selectedKey) : undefined
  const lane = useMemo(
    () => ({ id: agent.id, label: agent.hostname, events: hostEvents ?? [], incidents }),
    [agent.id, agent.hostname, hostEvents, incidents],
  )

  const percent = (time: number) => `${Math.min(100, Math.max(0, ((time - from) / width) * 100))}%`
  const fractionAt = (event: PointerEvent) => {
    const rect = tracksRef.current!.getBoundingClientRect()
    return Math.min(1, Math.max(0, (event.clientX - rect.left) / rect.width))
  }
  const timeAt = (fraction: number) => Math.round(from + fraction * width)

  const onDown = (event: PointerEvent<HTMLDivElement>) => {
    if (event.button !== 0 || (event.target as HTMLElement).closest('[data-mark]')) return
    press.current = { x: event.clientX, fraction: fractionAt(event) }
    event.currentTarget.setPointerCapture(event.pointerId)
  }
  const onMove = (event: PointerEvent<HTMLDivElement>) => {
    const fraction = fractionAt(event)
    setHover(binIndex(timeAt(fraction), from, now, BINS))
    if (!press.current) return
    if (brush || Math.abs(event.clientX - press.current.x) > BRUSH_AFTER) setBrush({ start: press.current.fraction, end: fraction })
  }
  const onUp = (event: PointerEvent<HTMLDivElement>) => {
    if (!press.current) return
    press.current = null
    event.currentTarget.releasePointerCapture(event.pointerId)
    if (brush) {
      const start = timeAt(Math.min(brush.start, brush.end))
      const end = timeAt(Math.max(brush.start, brush.end))
      setBrush(null)
      onPeriod([start, Math.max(end, start + 1)])
    } else if (period) {
      onPeriod(null)
    }
  }

  const readout = hover === null ? null : binPeriod(hover, from, now, BINS)
  const said: string[] = []
  if (hover !== null) {
    const launched = activity.bins.processes[hover]!
    const talked = activity.bins.network[hover]!
    const wrote = activity.bins.files[hover]!
    if (launched.count > 0) said.push(`${launched.count} launched: ${launched.names.join(', ')}`)
    if (talked.count > 0) said.push(`${bytes(talked.weight)} to ${talked.names.join(', ')}`)
    if (wrote.count > 0) said.push(`${wrote.count} written: ${wrote.names.join(', ')}`)
  }
  const ticks = [0, 0.25, 0.5, 0.75].map((fraction) => timeAt(fraction))
  const band = brush
    ? { left: `${Math.min(brush.start, brush.end) * 100}%`, width: `${Math.abs(brush.end - brush.start) * 100}%` }
    : period
      ? { left: percent(period[0]), width: `calc(${percent(period[1])} - ${percent(period[0])})` }
      : null

  return (
    <div className="flex h-full min-h-0 flex-col gap-2 rounded-card border border-line bg-surface px-4 pb-2.5 pt-3">
      <div className="flex h-8 shrink-0 items-center gap-3">
        <span className="shrink-0 font-display text-xs font-medium uppercase tracking-wider text-muted">Opened activity</span>
        {period ? (
          <button
            type="button"
            onClick={() => onPeriod(null)}
            aria-label="Clear time window"
            className="inline-flex h-7 shrink-0 items-center gap-1.5 rounded-control border border-accent/50 bg-selected px-2.5 font-mono text-xs text-text hover:border-accent"
          >
            {clock(period[0])} to {clock(period[1])}
            <X size={13} strokeWidth={1.5} aria-hidden />
          </button>
        ) : null}
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-soft">
          {readout ? (
            <>
              <span className="text-muted">{clock(readout[0])}</span> {said.join(' · ')}
            </>
          ) : null}
        </span>
        <Segmented label="Range" value={range} options={RANGES} onChange={setRange} className="shrink-0" />
        <CollapseToggle collapsed={false} onToggle={onCollapse} label="activity" bottom />
      </div>

      <div className="flex min-h-0 flex-1 gap-3 overflow-y-auto">
        <div className="flex w-[68px] shrink-0 flex-col font-mono text-[11px] text-muted" style={{ gap: GAP }}>
          {LANES.map((item) => (
            <span key={item.id} className="flex items-center" style={{ height: ROW }}>
              {item.label}
            </span>
          ))}
          <span className="flex items-center" style={{ height: 30 }}>
            Agent
          </span>
        </div>
        <div className="min-w-0 flex-1">
          <div
            ref={tracksRef}
            role="group"
            aria-label="Activity over time, drag to pick a time window"
            data-testid="activity-tracks"
            className="relative flex cursor-crosshair touch-none select-none flex-col"
            style={{ gap: GAP }}
            onPointerDown={onDown}
            onPointerMove={onMove}
            onPointerUp={onUp}
            onPointerLeave={() => setHover(null)}
          >
            {LANES.map((item) => {
              const peak = activity.peaks[item.id]
              return (
                <div key={item.id} className="relative overflow-hidden rounded-md bg-sunken" style={{ height: ROW }}>
                  {item.id === 'processes' && selected ? (
                    <div
                      className="absolute bottom-0 top-0 border-l border-accent bg-accent/10"
                      style={{ left: percent(selected.start), width: `calc(${percent(selected.end ?? now)} - ${percent(selected.start)})` }}
                    />
                  ) : null}
                  {activity.bins[item.id].map((bin, index) => {
                    const value = item.id === 'network' ? bin.weight : bin.count
                    if (value === 0) return null
                    return (
                      <span
                        key={index}
                        className={cn('absolute bottom-0 rounded-t-[1px]', index === hover ? 'bg-soft' : 'bg-node')}
                        style={{
                          left: `${(index / BINS) * 100}%`,
                          width: `calc(${100 / BINS}% - 1px)`,
                          height: `${Math.max(14, Math.sqrt(value / peak) * 100)}%`,
                        }}
                      />
                    )
                  })}
                  {activity.marks.map((group) => {
                    if (group.lane !== item.id) return null
                    const said = group.members.slice(0, 3).map((member) => `${clock(member.time)} ${member.detail}`)
                    if (group.members.length > 3) said.push(`and ${group.members.length - 3} more`)
                    const holds = group.members.some((member) => member.key === selectedKey)
                    return (
                      <button
                        key={group.bin}
                        type="button"
                        data-mark={group.lane}
                        title={said.join('\n')}
                        aria-label={said.join(', ')}
                        onClick={() => onSelect(nextMember(group, selectedKey).key)}
                        className={cn(
                          'absolute top-1/2 h-2 w-2 -translate-x-1/2 -translate-y-1/2 rotate-45 cursor-pointer rounded-[2px] ring-1 ring-sunken hover:scale-125',
                          SEVERITY_DOT[group.severity],
                          holds && 'ring-2 ring-accent',
                        )}
                        style={{ left: `${((group.bin + 0.5) / BINS) * 100}%` }}
                      />
                    )
                  })}
                </div>
              )
            })}
            <div className="flex">
              <LaneTrack lane={lane} from={from} to={now} now={now} tall={false} onIncident={(incident) => onIncident(incident, now)} />
            </div>
            {band ? <div className="pointer-events-none absolute bottom-0 top-0 border-x border-accent bg-accent/10" style={band} /> : null}
            {hover !== null ? (
              <div
                className="pointer-events-none absolute bottom-0 top-0 w-px bg-line-hover"
                style={{ left: `${((hover + 0.5) / BINS) * 100}%` }}
              />
            ) : null}
          </div>
          <div className="mt-1 flex justify-between font-mono text-[10px] text-muted">
            {ticks.map((tick) => (
              <span key={tick}>{clock(tick)}</span>
            ))}
            <span className="text-soft">now</span>
          </div>
        </div>
      </div>
    </div>
  )
}
