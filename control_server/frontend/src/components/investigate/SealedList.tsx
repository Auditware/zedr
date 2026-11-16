import { Link } from '@tanstack/react-router'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Lock } from 'lucide-react'
import { useEffect, useMemo, useRef } from 'react'
import { CopyButton } from '@/components/ui/bits'
import type { SealedRow } from '@/lib/api'
import { count, PROOF_FILL, PROOF_LABEL, PROOF_SAID, proofStatus } from '@/lib/chain'
import { cn } from '@/lib/cn'
import { categoryOf } from '@/lib/events'
import { clock, dateTime, shortHash } from '@/lib/format'
import { useChain, useSealed } from '@/lib/queries'
import { openedDetail, sealedSize } from '@/lib/sealed'

type Props = { agentId: string; lead?: string }

const ROW = 32
const GRID =
  'grid items-center gap-x-2.5 px-3 grid-cols-[50px_64px_minmax(0,1fr)_78px] @[600px]:grid-cols-[64px_70px_84px_minmax(0,1fr)_176px] @[600px]:gap-x-3'
const WIDE = 'hidden @[600px]:block'

function Chained({ agentId, row }: { agentId: string; row: SealedRow }) {
  const status = proofStatus(row.proof)
  return (
    <span role="cell" className="flex min-w-0 items-center justify-end gap-2">
      <Link to="/endpoints" search={{ host: agentId, view: 'agent', win: row.window }} className="truncate text-steel hover:underline" title={`Window ${row.window} in the commitment chain`}>
        <span className="hidden @[600px]:inline">window </span>
        <span className="@[600px]:hidden">w</span>
        {row.window}
      </Link>
      <span className="inline-flex shrink-0 items-center gap-1.5 text-muted" title={PROOF_SAID[status]}>
        <span className={cn('h-2 w-2 rounded-[2px]', PROOF_FILL[status])} aria-hidden />
        <span className="hidden w-[66px] @[600px]:inline">{PROOF_LABEL[status]}</span>
        <span className="sr-only @[600px]:hidden">{PROOF_LABEL[status]}</span>
      </span>
    </span>
  )
}

function Row({ agentId, row, top }: { agentId: string; row: SealedRow; top: number }) {
  const place = { height: ROW, transform: `translateY(${top}px)` }
  const index = (
    <span role="cell" className={row.opened ? 'text-soft' : 'text-faint'}>
      #{row.index}
    </span>
  )
  const sealedAt = (
    <span role="cell" className={cn(WIDE, 'text-muted')} title={dateTime(row.received_at)}>
      {clock(row.received_at)}
    </span>
  )

  if (row.opened && row.event_id && row.event_type) {
    return (
      <div role="row" data-sealed-row="opened" data-index={row.index} className={cn(GRID, 'absolute left-0 w-full border-b border-hairline hover:bg-raised')} style={place}>
        {index}
        {sealedAt}
        <span role="cell" className="flex min-w-0 items-center gap-2 text-soft">
          <span className="h-2 w-2 shrink-0 rounded-[2px]" style={{ background: categoryOf(row.event_type).color }} aria-hidden />
          <span className="truncate">{row.event_type}</span>
        </span>
        <span role="cell" className="min-w-0 truncate">
          <Link to="/events" search={{ agent: agentId, show: 'telemetry', event: row.event_id }} title={openedDetail(row)} className="text-text hover:underline">
            {openedDetail(row)}
          </Link>
        </span>
        <Chained agentId={agentId} row={row} />
      </div>
    )
  }

  return (
    <div role="row" data-sealed-row="sealed" data-index={row.index} className={cn(GRID, 'absolute left-0 w-full border-b border-hairline')} style={place}>
      {index}
      {sealedAt}
      <span role="cell" className="flex items-center gap-1.5 text-steel">
        <Lock size={12} strokeWidth={1.75} className="shrink-0" aria-hidden />
        sealed
      </span>
      <span role="cell" className="flex min-w-0 items-center gap-1 text-muted">
        <span className="truncate" title={row.leaf}>
          <span className="hidden @[600px]:inline">leaf </span>
          {shortHash(row.leaf)}
        </span>
        <CopyButton value={row.leaf} label={`Copy leaf of event ${row.index}`} className="h-5 w-5" />
        <span className={cn(WIDE, 'shrink-0 text-faint')}>· {sealedSize(row.ciphertext_bytes)}</span>
      </span>
      <Chained agentId={agentId} row={row} />
    </div>
  )
}

export function SealedList({ agentId, lead }: Props) {
  const { data: chain } = useChain(agentId)
  const sealed = useSealed(agentId)
  const rows = useMemo(() => sealed.data?.pages.flat() ?? [], [sealed.data])
  const scrollRef = useRef<HTMLDivElement>(null)
  const virtual = useVirtualizer({ count: rows.length, getScrollElement: () => scrollRef.current, estimateSize: () => ROW, overscan: 16 })
  const items = virtual.getVirtualItems()
  const lastShown = items[items.length - 1]?.index ?? 0
  const { hasNextPage, isFetchingNextPage, fetchNextPage } = sealed

  useEffect(() => {
    if (lastShown >= rows.length - 30 && hasNextPage && !isFetchingNextPage) void fetchNextPage()
  }, [lastShown, rows.length, hasNextPage, isFetchingNextPage, fetchNextPage])

  const committed = chain?.totals.events
  return (
    <div data-sealed-list className="@container absolute inset-0 flex flex-col px-4 pb-3">
      <div className="flex shrink-0 flex-wrap items-baseline gap-x-4 gap-y-1 pb-2">
        <p className="min-w-[240px] flex-1 text-xs leading-relaxed text-muted">
          <Lock size={12} strokeWidth={1.75} className="mr-1.5 inline align-[-1px] text-steel" aria-hidden />
          {lead ? `${lead} ` : ''}
          This is what the server holds of the endpoint. It cannot read the sealed rows, only a rule that fires on the endpoint opens what it read.{' '}
          <Link to="/rules" className="text-accent hover:underline">
            What can open them
          </Link>
        </p>
        <span className="font-mono text-xs text-muted" aria-live="polite">
          {committed === undefined ? '' : `${count(rows.length)} of ${count(committed)} committed events, newest first`}
        </span>
      </div>
      <div ref={scrollRef} role="table" aria-label="Committed events" className="min-h-0 flex-1 overflow-y-auto rounded-card border border-line bg-surface font-mono text-xs">
        <div role="row" className={cn(GRID, 'sticky top-0 z-10 h-8 border-b border-line bg-surface font-sans text-[11px] uppercase tracking-wider text-muted')}>
          <span role="columnheader">Index</span>
          <span role="columnheader" className={WIDE}>
            Sealed
          </span>
          <span role="columnheader">Event</span>
          <span role="columnheader">Detail</span>
          <span role="columnheader" className="text-right">
            Window
          </span>
        </div>
        {sealed.isError ? <div className="px-3 py-3 text-muted">The server did not list what it holds of this endpoint.</div> : null}
        {sealed.isSuccess && rows.length === 0 ? <div className="px-3 py-3 text-muted">This endpoint has not committed an event yet.</div> : null}
        <div style={{ height: virtual.getTotalSize(), position: 'relative' }}>
          {items.map((item) => (
            <Row key={rows[item.index]!.index} agentId={agentId} row={rows[item.index]!} top={item.start} />
          ))}
        </div>
      </div>
    </div>
  )
}
