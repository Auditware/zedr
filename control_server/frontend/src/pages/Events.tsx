import { keepPreviousData, useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { getRouteApi, Link } from '@tanstack/react-router'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Lock, LockOpen, Pause, Play, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState, type PointerEvent } from 'react'
import { JsonView } from '@/components/common/JsonView'
import { FindingProof } from '@/components/common/Proof'
import { formatPeriod, parsePeriod } from '@/components/investigate/probe'
import { Chip, CopyButton, PageHeader } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { inputClass } from '@/components/ui/input'
import { Handle, Panel, Split } from '@/components/ui/panes'
import { Segmented } from '@/components/ui/segmented'
import type { Period } from '@/lib/activity'
import { api, type ApiEvent, type EventHistogram } from '@/lib/api'
import { isAdmin, useSession } from '@/lib/auth'
import { count, PROOF_FILL, PROOF_LABEL, PROOF_ORDER, share } from '@/lib/chain'
import { cn } from '@/lib/cn'
import { auditEvent, CATEGORIES, categoryOf, eventData, summarize, typesOf, type Category } from '@/lib/events'
import { findingOf } from '@/lib/findings'
import { clock, dateTime } from '@/lib/format'
import { bucketsOf, buildLanes, countIn, LANE_BUCKETS, laneWindow, periodOf, RANGES, tickLabel, type Lane, type Range } from '@/lib/lanes'
import { useLive } from '@/lib/live'
import { useAgentIndex, useChainSummary, useMedia, useNow, useSize } from '@/lib/queries'

const route = getRouteApi('/app/events')
const PAGE = 500
const AUDIT_PAGE = 200
const TICKS = 5
const LANE = 16

function FleetChain() {
  const { data } = useChainSummary()
  if (!data) return null
  const shown = PROOF_ORDER.filter((status) => data.proofs[status] > 0)
  return (
    <section aria-label="What the server holds" className="flex shrink-0 flex-wrap items-center gap-x-8 gap-y-2 rounded-card border border-line bg-surface px-3 py-2.5">
      <div className="flex items-baseline gap-2" data-fleet="sealed">
        <Lock size={14} strokeWidth={1.75} className="self-center text-steel" aria-hidden />
        <span className="font-display text-xl font-medium leading-none text-steel">{count(data.events)}</span>
        <span className="text-xs text-muted">
          events sealed by {count(data.agents)} {data.agents === 1 ? 'endpoint' : 'endpoints'}
        </span>
      </div>
      <div className="flex items-baseline gap-2" data-fleet="opened">
        <LockOpen size={14} strokeWidth={1.75} className="self-center text-text" aria-hidden />
        <span className="font-display text-xl font-medium leading-none text-text">{count(data.opened)}</span>
        <span className="text-xs text-muted">opened by rule matches, {share(data.opened, data.events)} of what the server holds</span>
      </div>
      <div className="min-w-[240px] flex-1" data-fleet="windows">
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-0.5 font-mono text-[11px] text-muted">
          <span className="text-soft">{count(data.windows)} windows</span>
          {shown.map((status) => (
            <span key={status} className="inline-flex items-center gap-1.5">
              <span className={cn('h-2 w-2 rounded-[2px]', PROOF_FILL[status])} aria-hidden />
              {PROOF_LABEL[status]} {count(data.proofs[status])}
            </span>
          ))}
          {data.gaps > 0 ? <span className="text-alert-soft">{data.gaps === 1 ? '1 gap' : `${count(data.gaps)} gaps`}</span> : null}
        </div>
        <div className="mt-1.5 flex h-1.5 gap-px overflow-hidden rounded-full bg-sunken" aria-hidden>
          {shown.map((status) => (
            <span key={status} className={cn('min-w-[3px]', PROOF_FILL[status])} style={{ flexGrow: data.proofs[status] }} />
          ))}
        </div>
      </div>
    </section>
  )
}

type LanesProps = {
  lanes: Lane[]
  histogram: EventHistogram | undefined
  frame: Period
  range: Range
  enabled: ReadonlySet<Category>
  period: Period | null
  onToggle: (category: Category) => void
  onRange: (range: Range) => void
  onPeriod: (period: Period | null) => void
}

// Lanes the list leaves out until they are asked for: an endpoint beats every 30 seconds, and those rows would bury everything else
const QUIET: ReadonlySet<string> = new Set(['heartbeat'])

function Lanes({ lanes, histogram, frame, range, enabled, period, onToggle, onRange, onPeriod }: LanesProps) {
  const [tracks, { width }] = useSize<HTMLDivElement>()
  const [hover, setHover] = useState<number | null>(null)
  const [drag, setDrag] = useState<[number, number] | null>(null)
  const buckets = histogram?.buckets ?? LANE_BUCKETS
  const seconds = frame[1] - frame[0]
  const picked = drag ?? (period && histogram ? bucketsOf(histogram, period) : null)
  const [first, last] = picked ? [Math.min(...picked), Math.max(...picked)] : [0, buckets - 1]
  const shown = hover !== null && !drag ? [hover, hover] : [first, last]
  const total = lanes.reduce((sum, lane) => (enabled.has(lane.id) ? sum + countIn(lane, shown[0]!, shown[1]!) : sum), 0)
  const spoken = (from: number, to: number) =>
    histogram ? periodOf(histogram, from, to).map((time) => (seconds > 86_400 ? tickLabel(time, seconds) : clock(time))).join(' to ') : ''
  const said = hover !== null && !drag ? spoken(hover, hover) : picked ? spoken(first, last) : `last ${RANGES.find((option) => option.id === range)!.label}`

  const bucketAt = (event: PointerEvent<HTMLDivElement>) => {
    const x = event.clientX - event.currentTarget.getBoundingClientRect().left
    return Math.min(buckets - 1, Math.max(0, Math.floor((x / Math.max(1, width)) * buckets)))
  }

  return (
    <section aria-label="Events over time" className="shrink-0 rounded-card border border-line bg-surface px-3 pb-2 pt-2.5">
      <div className="mb-2 flex min-h-8 flex-wrap items-center gap-x-3 gap-y-1.5">
        <span className="font-mono text-xs text-soft" aria-live="polite">
          {total.toLocaleString('en-US')} {total === 1 ? 'event' : 'events'}
          <span className="text-muted"> · {said}</span>
        </span>
        {period ? (
          <button
            type="button"
            aria-label="Clear period"
            onClick={() => onPeriod(null)}
            className="inline-flex h-7 items-center gap-1.5 rounded-control border border-accent/50 bg-selected px-2 font-mono text-[11px] text-accent hover:border-accent"
          >
            {spoken(first, last)}
            <X size={12} strokeWidth={2} aria-hidden />
          </button>
        ) : null}
        <Segmented label="Period" value={range} options={RANGES} onChange={onRange} className="ml-auto" />
      </div>
      <div className="grid grid-cols-[minmax(92px,150px)_minmax(0,1fr)] gap-x-3">
        <div className="flex flex-col gap-[3px]" role="group" aria-label="Show events by category">
          {lanes.map((lane) => {
            const on = enabled.has(lane.id)
            return (
              <button
                key={lane.id}
                type="button"
                aria-pressed={on}
                onClick={() => onToggle(lane.id)}
                className={cn('flex items-center gap-1.5 rounded-[3px] px-1 text-left text-xs transition-colors hover:bg-raised', on ? 'text-text' : 'text-muted opacity-45')}
                style={{ height: LANE }}
              >
                <span className="h-2 w-2 shrink-0 rounded-[2px]" style={{ background: lane.color }} aria-hidden />
                <span className="min-w-0 flex-1 truncate">{lane.label}</span>
                <span className="shrink-0 font-mono text-[11px] text-muted">{countIn(lane, shown[0]!, shown[1]!).toLocaleString('en-US')}</span>
              </button>
            )
          })}
        </div>
        <div
          ref={tracks}
          role="group"
          aria-label="Lanes, drag to pick a period"
          data-testid="event-lanes"
          className="relative flex cursor-crosshair touch-none select-none flex-col gap-[3px]"
          onPointerDown={(event) => {
            if (event.button !== 0 || !histogram) return
            event.currentTarget.setPointerCapture(event.pointerId)
            const at = bucketAt(event)
            setDrag([at, at])
          }}
          onPointerMove={(event) => {
            const at = bucketAt(event)
            setHover(at)
            if (drag) setDrag([drag[0], at])
          }}
          onPointerUp={() => {
            if (drag && histogram) onPeriod(periodOf(histogram, drag[0], drag[1]))
            setDrag(null)
          }}
          onPointerCancel={() => setDrag(null)}
          onPointerLeave={() => setHover(null)}
        >
          {lanes.map((lane) => (
            <div
              key={lane.id}
              data-lane={lane.id}
              className={cn('relative overflow-hidden rounded-[3px] bg-sunken transition-opacity', !enabled.has(lane.id) && 'opacity-30')}
              style={{ height: LANE }}
            >
              {lane.counts.map((count, index) =>
                count > 0 ? (
                  <span
                    key={index}
                    className="absolute bottom-0 rounded-t-[1px]"
                    style={{
                      left: `${(index / buckets) * 100}%`,
                      width: `calc(${100 / buckets}% - 1px)`,
                      height: `${Math.max(14, Math.sqrt(count / lane.peak) * 100)}%`,
                      background: lane.color,
                    }}
                  />
                ) : null,
              )}
            </div>
          ))}
          {picked ? (
            <div
              className="pointer-events-none absolute inset-y-0 border-x border-accent bg-accent/15"
              style={{ left: `${(first / buckets) * 100}%`, width: `${((last - first + 1) / buckets) * 100}%` }}
            />
          ) : null}
          {hover !== null ? (
            <div className="pointer-events-none absolute inset-y-0 w-px bg-line-hover" style={{ left: `${((hover + 0.5) / buckets) * 100}%` }} />
          ) : null}
        </div>
        <span />
        <div className="mt-1 flex justify-between font-mono text-[10px] text-muted">
          {Array.from({ length: TICKS - 1 }, (_, index) => (
            <span key={index}>{tickLabel(frame[0] + (seconds * index) / (TICKS - 1), seconds)}</span>
          ))}
          <span className="text-soft">now</span>
        </div>
      </div>
    </section>
  )
}

export function Events() {
  const search = route.useSearch()
  const navigate = route.useNavigate()
  const now = useNow(5000)
  const narrow = useMedia('(max-width: 860px)')
  const agents = useAgentIndex()
  const live = useLive((state) => state.events)
  const hostOf = (event: ApiEvent) => {
    if (event.event_type === 'audit') return String(eventData(event).actor ?? '')
    return event.agent_id ? (agents.get(event.agent_id)?.hostname ?? event.agent_id.slice(0, 8)) : 'server'
  }
  const admin = isAdmin(useSession((state) => state.session))
  const categories = useMemo(() => CATEGORIES.filter((category) => admin || category.id !== 'audit'), [admin])
  const enabled = useMemo(() => {
    const wanted = search.show?.split(',')
    return new Set(categories.map((category) => category.id).filter((id) => (wanted ? wanted.includes(id) : !QUIET.has(id))))
  }, [search.show, categories])
  const needle = (search.q ?? '').trim().toLowerCase()
  const range: Range = search.range ?? '1h'
  const period = parsePeriod(search.t)
  const frame = useMemo(() => laneWindow(range, now), [range, now])
  const [from, to] = frame
  const [paused, setPaused] = useState(false)
  const [frozen, setFrozen] = useState<ApiEvent[]>([])
  const openId = search.event ?? null
  const setOpenId = (id: string | null) =>
    void navigate({ search: (previous) => ({ ...previous, event: id ?? undefined }), replace: true })
  const scrollRef = useRef<HTMLDivElement>(null)

  const types = useMemo(() => typesOf(enabled), [enabled])
  const serverTypes = useMemo(() => types.filter((type) => type !== 'audit'), [types])
  const allOn = enabled.size === categories.length
  const withAudit = enabled.has('audit') && !search.agent
  const { data: histogram } = useQuery({
    queryKey: ['event-histogram', search.agent ?? null, from, to],
    queryFn: () => api.eventHistogram({ from, to, buckets: LANE_BUCKETS, agentId: search.agent }),
    refetchInterval: 15_000,
    placeholderData: keepPreviousData,
  })
  const lanes = useMemo(() => buildLanes(histogram, categories), [histogram, categories])

  const history = useInfiniteQuery({
    queryKey: ['events', search.agent ?? null, allOn ? 'all' : types.join(','), search.t ?? null],
    queryFn: ({ pageParam }) =>
      api.events({ agentId: search.agent, types: allOn ? undefined : serverTypes, limit: PAGE, offset: pageParam, from: period?.[0], to: period?.[1] }),
    initialPageParam: 0,
    getNextPageParam: (last, pages) => (last.length < PAGE ? undefined : pages.length * PAGE),
    enabled: serverTypes.length > 0,
  })
  const audit = useInfiniteQuery({
    queryKey: ['audit', 'events'],
    queryFn: ({ pageParam }) => api.audit(AUDIT_PAGE, pageParam),
    initialPageParam: 0,
    getNextPageParam: (last, pages) => (last.entries.length < AUDIT_PAGE ? undefined : pages.length * AUDIT_PAGE),
    enabled: withAudit,
    refetchInterval: 30_000,
  })
  const brokenAt = audit.data?.pages[0]?.first_broken_seq ?? null

  const stream = paused ? frozen : live
  const rows = useMemo(() => {
    const wanted = new Set(types)
    const seen = new Set<string>()
    const merged: ApiEvent[] = []
    const push = (event: ApiEvent) => {
      if (seen.has(event.id) || !wanted.has(event.event_type)) return
      if (search.agent && event.agent_id !== search.agent) return
      if (period && (event.timestamp < period[0] || event.timestamp > period[1])) return
      seen.add(event.id)
      merged.push(event)
    }
    stream.forEach(push)
    history.data?.pages.forEach((page) => page.forEach(push))
    if (withAudit) audit.data?.pages.forEach((page) => page.entries.forEach((entry) => push(auditEvent(entry))))
    const matching = needle
      ? merged.filter((event) =>
          `${hostOf(event)} ${event.event_type} ${summarize(event)} ${event.event_type === 'audit' ? event.data : ''}`.toLowerCase().includes(needle),
        )
      : merged
    return matching.sort((a, b) => b.timestamp - a.timestamp)
    // hostOf reads the agent index, which is stable between refetches
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [stream, history.data, audit.data, withAudit, types, search.agent, search.t, needle, agents])

  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 36,
    overscan: 14,
  })
  const items = virtual.getVirtualItems()
  const lastIndex = items[items.length - 1]?.index ?? 0

  useEffect(() => {
    if (lastIndex < rows.length - 30) return
    if (history.hasNextPage && !history.isFetchingNextPage) void history.fetchNextPage()
    if (withAudit && audit.hasNextPage && !audit.isFetchingNextPage) void audit.fetchNextPage()
  }, [lastIndex, rows.length, history, audit, withAudit])

  const opened = openId ? rows.find((event) => event.id === openId) : undefined
  const openedData = opened ? eventData(opened) : {}
  const openedFinding = opened?.agent_id
    ? findingOf(opened.event_type === 'detection' ? openedData : openedData.evidence && typeof openedData.evidence === 'object' ? (openedData.evidence as Record<string, unknown>) : {})
    : null
  const filteredHost = search.agent ? (agents.get(search.agent)?.hostname ?? search.agent.slice(0, 8)) : null

  return (
    <div className="absolute inset-0 flex flex-col gap-3 overflow-hidden px-6 pb-5 pt-4 max-md:static max-md:overflow-visible">
      <PageHeader title="Events" meta={`${rows.length} loaded${history.hasNextPage ? '+' : ''}`}>
        {filteredHost ? (
          <button
            type="button"
            onClick={() => void navigate({ search: {}, replace: true })}
            className="inline-flex h-8 items-center gap-1.5 rounded-control border border-accent/50 bg-selected px-2.5 font-mono text-xs text-accent hover:border-accent"
          >
            {filteredHost}
            <X size={13} strokeWidth={2} aria-label="Clear host filter" />
          </button>
        ) : null}
        {brokenAt !== null ? <Chip tone="alert">audit chain broken at #{brokenAt}</Chip> : null}
        <input
          value={search.q ?? ''}
          onChange={(event) => void navigate({ search: (previous) => ({ ...previous, q: event.target.value || undefined }), replace: true })}
          placeholder="host, event, detail"
          aria-label="Filter events"
          className={cn(inputClass, 'h-9 w-[220px] font-mono text-xs')}
        />
        <Button
          size="icon"
          aria-label={paused ? 'Resume live events' : 'Pause live events'}
          aria-pressed={paused}
          onClick={() => {
            setFrozen(live)
            setPaused((value) => !value)
          }}
        >
          {paused ? <Play size={16} strokeWidth={1.5} /> : <Pause size={16} strokeWidth={1.5} />}
        </Button>
      </PageHeader>

      <FleetChain />

      <Lanes
        lanes={lanes}
        histogram={histogram}
        frame={frame}
        range={range}
        enabled={enabled}
        period={period}
        onToggle={(category) => {
          const next = new Set(enabled)
          if (next.has(category)) next.delete(category)
          else next.add(category)
          const usual = categories.every((one) => next.has(one.id) !== QUIET.has(one.id))
          void navigate({
            search: (previous) => ({ ...previous, show: usual ? undefined : [...next].join(',') }),
            replace: true,
          })
        }}
        onRange={(next) => void navigate({ search: (previous) => ({ ...previous, range: next === '1h' ? undefined : next, t: undefined }), replace: true })}
        onPeriod={(next) => void navigate({ search: (previous) => ({ ...previous, t: next ? formatPeriod(next) : undefined }), replace: true })}
      />

      <div className="min-h-0 flex-1">
        <Split
          id={narrow ? 'events-narrow' : 'events'}
          orientation={narrow ? 'vertical' : 'horizontal'}
          panelIds={opened ? ['rows', 'event'] : ['rows']}
        >
          <Panel id="rows" minSize={narrow ? 160 : 360}>
        <div ref={scrollRef} className="h-full overflow-y-auto rounded-card border border-line bg-surface">
          <div className="sticky top-0 z-10 flex h-8 items-center gap-3 border-b border-line bg-surface px-4 text-[11px] uppercase tracking-wider text-muted">
            <span className="w-[66px] shrink-0">Time</span>
            <span className="w-[150px] shrink-0">Host</span>
            <span className="w-[200px] shrink-0">Event</span>
            <span>Detail</span>
          </div>
          <div style={{ height: virtual.getTotalSize(), position: 'relative' }}>
            {items.map((item) => {
              const event = rows[item.index]!
              const category = categoryOf(event.event_type)
              return (
                <button
                  key={event.id}
                  type="button"
                  onClick={() => setOpenId(event.id === openId ? null : event.id)}
                  data-event={event.event_type}
                  className={cn(
                    'absolute left-0 flex h-9 w-full items-center gap-3 border-b border-hairline px-4 text-left font-mono text-xs hover:bg-raised',
                    category.id === 'incident' && 'bg-alert-surface/40',
                    event.id === openId && 'bg-selected',
                  )}
                  style={{ transform: `translateY(${item.start}px)` }}
                >
                  <span className="w-[66px] shrink-0 text-muted">{clock(event.timestamp)}</span>
                  <span className={cn('w-[150px] shrink-0 truncate', category.id === 'heartbeat' ? 'text-muted' : 'text-text')}>{hostOf(event)}</span>
                  <span className={cn('flex w-[200px] shrink-0 items-center gap-2 truncate', category.id === 'heartbeat' ? 'text-faint' : 'text-soft')}>
                    <span className="h-2 w-2 shrink-0 rounded-[2px]" style={{ background: category.color }} aria-hidden />
                    {event.event_type}
                  </span>
                  <span className="min-w-0 truncate text-muted">{summarize(event)}</span>
                </button>
              )
            })}
          </div>
        </div>

          </Panel>
        {opened ? (
          <>
          <Handle orientation={narrow ? 'vertical' : 'horizontal'} />
          <Panel id="event" defaultSize={narrow ? 260 : 380} minSize={narrow ? 140 : 280} maxSize={720}>
          <aside className="flex h-full flex-col gap-3 overflow-y-auto rounded-card border border-line bg-surface p-4">
            <div className="flex items-center justify-between">
              <span className="font-mono text-sm" style={{ color: categoryOf(opened.event_type).color }}>
                {opened.event_type}
              </span>
              <button type="button" aria-label="Close" onClick={() => setOpenId(null)} className="rounded-md p-1 text-muted hover:text-text">
                <X size={16} strokeWidth={1.5} />
              </button>
            </div>
            <dl className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3 gap-y-1.5 font-mono text-xs">
              <dt className="text-muted">time</dt>
              <dd>{dateTime(opened.timestamp)}</dd>
              <dt className="text-muted">received</dt>
              <dd>{opened.received_at ? dateTime(opened.received_at) : '-'}</dd>
              <dt className="text-muted">{opened.event_type === 'audit' ? 'actor' : 'host'}</dt>
              <dd className="truncate">
                {opened.event_type === 'audit' ? (
                  hostOf(opened)
                ) : opened.agent_id ? (
                  <Link to="/endpoints" search={{ host: opened.agent_id }} className="text-accent hover:underline">
                    {agents.get(opened.agent_id)?.hostname ?? opened.agent_id}
                  </Link>
                ) : (
                  'server'
                )}
              </dd>
              <dt className="text-muted">id</dt>
              <dd className="flex items-center gap-1">
                <span className="truncate">{opened.id}</span>
                <CopyButton value={opened.id} label="Copy event id" className="h-5 w-5" />
              </dd>
            </dl>
            {opened.event_type === 'audit' ? (
              <Chip tone={brokenAt === null ? 'neutral' : 'alert'} className="w-fit">
                {brokenAt === null ? 'hash chain intact' : `hash chain broken at #${brokenAt}`}
              </Chip>
            ) : null}
            {openedFinding && opened.agent_id ? <FindingProof agentId={opened.agent_id} finding={openedFinding} /> : null}
            <div className="relative">
              <JsonView value={opened.data} />
              <CopyButton value={opened.data} label="Copy JSON" className="absolute right-1.5 top-1.5" />
            </div>
          </aside>
          </Panel>
          </>
        ) : null}
        </Split>
      </div>
    </div>
  )
}
