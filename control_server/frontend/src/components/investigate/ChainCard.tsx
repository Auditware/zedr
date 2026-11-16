import { Link } from '@tanstack/react-router'
import { Lock, LockOpen, X } from 'lucide-react'
import type { ReactNode } from 'react'
import { ProofChip } from '@/components/common/Proof'
import { Chip, CopyButton } from '@/components/ui/bits'
import type { ReleaseView, WindowSummary } from '@/lib/api'
import { count, eventRange, indices, PROOF_FILL, PROOF_LABEL, PROOF_ORDER, PROOF_SAID, proofCounts, proofStatus, share } from '@/lib/chain'
import { cn } from '@/lib/cn'
import { bytes, dateTime, shortHash } from '@/lib/format'
import { useChain, useWindow } from '@/lib/queries'

type Props = { agentId: string; selected: number | null; onSelect: (window: number | null) => void }

const EVENT_GRID = 'grid grid-cols-[46px_minmax(84px,1fr)_60px_72px] items-center gap-x-2.5 px-3'
const LEVEL_DOT: Record<string, string> = { high: 'bg-alert', medium: 'bg-warn' }

function Fact({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="font-display text-[10px] uppercase tracking-wider text-muted">{label}</dt>
      <dd className="mt-0.5 flex min-w-0 items-center gap-1 font-mono text-[13px] text-text">{children}</dd>
    </div>
  )
}

function Hash({ label, value, copy }: { label: string; value: string; copy: string }) {
  return (
    <>
      <dt className="text-muted">{label}</dt>
      <dd className="flex min-w-0 items-center gap-1">
        <span className="truncate" title={value}>
          {shortHash(value)}
        </span>
        <CopyButton value={value} label={copy} className="h-5 w-5" />
      </dd>
    </>
  )
}

function said(window: WindowSummary): string {
  const marks = `${window.fresh ? ', opens an epoch' : ''}${window.gap ? ', events are missing before it' : ''}`
  return `Window ${window.window}, proof ${PROOF_LABEL[proofStatus(window.proof)]}, ${window.count} events, ${window.opened} opened${marks}`
}

function Strip({ windows, selected, onSelect }: { windows: WindowSummary[]; selected: number | null; onSelect: (window: number | null) => void }) {
  return (
    <div role="group" aria-label="Recent windows, oldest first" className="flex flex-wrap gap-x-[3px] gap-y-1.5">
      {windows.map((window) => {
        const status = proofStatus(window.proof)
        const picked = window.window === selected
        return (
          <button
            key={window.window}
            type="button"
            data-window={window.window}
            data-proof={status}
            aria-pressed={picked}
            aria-label={said(window)}
            title={said(window)}
            onClick={() => onSelect(picked ? null : window.window)}
            className="group flex w-[15px] shrink-0 flex-col items-center gap-0.5 rounded-[3px] outline-offset-2"
          >
            <span className={cn('h-3 font-mono text-[9px] font-semibold leading-3', window.gap ? 'text-alert-soft' : 'text-muted')} aria-hidden>
              {window.gap ? 'G' : window.fresh ? 'F' : ''}
            </span>
            <span
              className={cn(
                'relative flex h-7 w-full items-end justify-center rounded-[3px] pb-[3px] transition-transform group-hover:scale-y-110',
                PROOF_FILL[status],
                picked && 'ring-2 ring-accent ring-offset-2 ring-offset-surface',
              )}
            >
              {window.opened > 0 ? <span className="h-[5px] w-[5px] rounded-full bg-ink" aria-hidden /> : null}
            </span>
          </button>
        )
      })}
    </div>
  )
}

function Release({ release, windowProof }: { release: ReleaseView; windowProof: string }) {
  const followUp = release.level === 'info'
  return (
    <li data-release={release.rule} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-hairline px-3 py-2 last:border-b-0">
      <span className={cn('h-2 w-2 shrink-0 rounded-full', LEVEL_DOT[release.level] ?? 'bg-node')} aria-hidden />
      <span className="min-w-0 text-[13px] text-text">{release.title || release.rule}</span>
      <span className="font-mono text-[11px] text-muted">
        {followUp ? 'follow-up' : release.level}
        {release.technique ? ` · ${release.technique}` : ''}
      </span>
      <span className="font-mono text-[11px] text-soft">opened {indices([release.trigger, ...release.context])}</span>
      <ProofChip status={release.proven ? 'verified' : proofStatus(windowProof)} className="ml-auto" />
    </li>
  )
}

function WindowDetail({ agentId, window, onClose }: { agentId: string; window: number; onClose: () => void }) {
  const { data, isLoading, isError } = useWindow(agentId, window)
  const status = data ? proofStatus(data.proof) : 'pending'

  return (
    <section aria-label={`Window ${window}`} className="mt-3 rounded-xl border border-line bg-row">
      <div className="flex min-h-10 flex-wrap items-center gap-x-2.5 gap-y-1 px-3 py-1.5">
        <h4 className="font-mono text-sm text-text">window {window}</h4>
        {data ? <ProofChip status={status} /> : null}
        {data?.header.fresh ? <Chip>opens epoch {data.header.epoch}</Chip> : null}
        {data?.header.gap ? <Chip tone="alert">events missing before it</Chip> : null}
        <button type="button" aria-label="Close window" onClick={onClose} className="ml-auto rounded-md p-1 text-muted hover:bg-raised hover:text-text">
          <X size={15} strokeWidth={1.5} aria-hidden />
        </button>
      </div>
      {isError ? <div className="px-3 pb-3 font-mono text-xs text-muted">The server holds no such window of this endpoint.</div> : null}
      {isLoading ? <div className="px-3 pb-3 font-mono text-xs text-muted">Loading window</div> : null}
      {data ? (
        <>
          <p className="px-3 pb-2 text-xs text-muted">{PROOF_SAID[status]}</p>
          <dl className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3 gap-y-1 px-3 pb-3 font-mono text-xs @[620px]:grid-cols-[64px_minmax(0,1fr)_64px_minmax(0,1fr)]">
            <dt className="text-muted">holds</dt>
            <dd>{eventRange(data.header.first_index, data.header.count)}</dd>
            <dt className="text-muted">epoch</dt>
            <dd>{data.header.epoch}</dd>
            <dt className="text-muted">received</dt>
            <dd>{dateTime(data.received_at)}</dd>
            <Hash label="follows" value={data.header.prev_head} copy="Copy the head this window follows" />
            <Hash label="root" value={data.header.root} copy="Copy window root" />
            <Hash label="head" value={data.header.head} copy="Copy window head" />
          </dl>

          {data.releases.length > 0 ? (
            <>
              <h5 className="border-t border-line px-3 pb-1 pt-2 font-display text-[11px] uppercase tracking-wider text-muted">Released in this window</h5>
              <ul aria-label="Releases">
                {data.releases.map((release) => (
                  <Release key={`${release.rule}:${release.trigger}`} release={release} windowProof={data.proof} />
                ))}
              </ul>
            </>
          ) : null}

          <h5 className="border-t border-line px-3 pb-1 pt-2 font-display text-[11px] uppercase tracking-wider text-muted">Sealed events</h5>
          {data.events.length === 0 ? (
            <div className="px-3 pb-3 text-xs text-muted">No events. A window is sealed every minute, also when the sensor saw nothing.</div>
          ) : (
            <div role="table" aria-label="Sealed events" className="max-h-[320px] overflow-y-auto pb-1 font-mono text-xs">
              <div role="row" className={cn(EVENT_GRID, 'sticky top-0 h-7 bg-row text-[10px] uppercase tracking-wider text-muted')}>
                <span role="columnheader">Event</span>
                <span role="columnheader">Leaf</span>
                <span role="columnheader" className="text-right">
                  Sealed
                </span>
                <span role="columnheader">State</span>
              </div>
              {data.events.map((event) => (
                <div key={event.index} role="row" data-sealed-event={event.opened ? 'opened' : 'sealed'} className={cn(EVENT_GRID, 'h-7 border-t border-hairline')}>
                  <span role="cell" className="text-soft">
                    #{event.index}
                  </span>
                  <span role="cell" className="truncate text-muted" title={event.leaf}>
                    {shortHash(event.leaf)}
                  </span>
                  <span role="cell" className="text-right text-muted">
                    {bytes(event.ciphertext_bytes)}
                  </span>
                  <span role="cell" className="min-w-0">
                    {event.opened && event.event_id ? (
                      <Link
                        to="/events"
                        search={{ agent: agentId, show: 'telemetry', event: event.event_id }}
                        className="inline-flex items-center gap-1.5 text-accent hover:underline"
                      >
                        <LockOpen size={12} strokeWidth={1.75} aria-hidden />
                        opened
                      </Link>
                    ) : (
                      <span className="inline-flex items-center gap-1.5 text-steel">
                        <Lock size={12} strokeWidth={1.75} aria-hidden />
                        sealed
                      </span>
                    )}
                  </span>
                </div>
              ))}
            </div>
          )}
        </>
      ) : null}
    </section>
  )
}

export function ChainCard({ agentId, selected, onSelect }: Props) {
  const { data: chain } = useChain(agentId)
  if (!chain) return null

  const { totals } = chain
  const windows = [...chain.windows].reverse()
  const counts = proofCounts(windows)
  return (
    <section aria-label="Commitment chain" className="@container mt-3 rounded-card border border-line bg-surface px-3 pb-3 pt-2">
      <div className="flex h-6 items-center justify-between gap-3">
        <h3 className="font-display text-[11px] uppercase tracking-wider text-muted">Commitment chain</h3>
        <span className="truncate font-mono text-[11px] text-muted">
          {count(totals.windows)} {totals.windows === 1 ? 'window' : 'windows'}
          {totals.windows > windows.length ? `, the last ${windows.length} shown` : ''}
        </span>
      </div>
      {totals.windows === 0 ? (
        <p className="py-3 text-[13px] text-muted">This endpoint has not delivered a sealed window yet.</p>
      ) : (
        <>
          <dl className="mt-1.5 grid grid-cols-2 gap-x-4 gap-y-2.5 @[460px]:grid-cols-3 @[760px]:grid-cols-[max-content_repeat(5,minmax(0,1fr))]">
            <Fact label="Head">
              <span className="whitespace-nowrap" title={chain.head}>
                {shortHash(chain.head)}
              </span>
              <CopyButton value={chain.head} label="Copy head" className="h-5 w-5" />
            </Fact>
            <Fact label="Epoch">{chain.epoch}</Fact>
            <Fact label="Committed">{count(totals.events)}</Fact>
            <Fact label="Opened">
              {count(totals.opened)}
              <span className="text-[11px] text-muted">{share(totals.opened, totals.events)}</span>
            </Fact>
            <Fact label="Gaps">
              <span className={cn(totals.gaps > 0 && 'text-alert-soft')}>{totals.gaps}</span>
            </Fact>
            <Fact label="Last proven">{chain.proven_window == null ? <span className="text-muted">none</span> : `window ${chain.proven_window}`}</Fact>
          </dl>

          <div className="mt-3">
            <Strip windows={windows} selected={selected} onSelect={onSelect} />
            <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 font-mono text-[11px] text-muted">
              {PROOF_ORDER.filter((status) => counts[status] > 0).map((status) => (
                <span key={status} className="inline-flex items-center gap-1.5">
                  <span className={cn('h-2 w-2 rounded-[2px]', PROOF_FILL[status])} aria-hidden />
                  {PROOF_LABEL[status]} {counts[status]}
                </span>
              ))}
              <span>F opens an epoch</span>
              <span>G events missing before it</span>
              <span className="inline-flex items-center gap-1.5">
                <span className="h-[5px] w-[5px] rounded-full bg-soft" aria-hidden />
                has opened events
              </span>
            </div>
          </div>

          {selected !== null ? <WindowDetail agentId={agentId} window={selected} onClose={() => onSelect(null)} /> : null}
        </>
      )}
    </section>
  )
}
