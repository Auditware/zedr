import { useMutation, useQueryClient } from '@tanstack/react-query'
import { getRouteApi } from '@tanstack/react-router'
import { useVirtualizer } from '@tanstack/react-virtual'
import { Plus, X } from 'lucide-react'
import { useMemo, useRef, useState } from 'react'
import { Card, Chip, CopyButton, Empty, PageHeader } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { Segmented } from '@/components/ui/segmented'
import { ApiError, api, type InstallKey, type InstallKeyResponse } from '@/lib/api'
import { isAdmin, useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { ago, dateTime, shortId, span } from '@/lib/format'
import { fan, strandPath } from '@/lib/fan'
import { useAgentIndex, useInstallKeys, useNow, useSize } from '@/lib/queries'
import { tone } from '@/lib/palette'

type Target = 'windows' | 'linux' | 'macos'
const TARGETS: { id: Target; label: string }[] = [
  { id: 'windows', label: 'Windows' },
  { id: 'linux', label: 'Linux' },
  { id: 'macos', label: 'macOS' },
]

function commandFor(target: Target, key: InstallKeyResponse): string {
  switch (target) {
    case 'windows':
      return key.windows_command
    case 'linux':
      return key.linux_command
    case 'macos':
      return key.macos_command
  }
}

type Outcome = 'unused' | 'downloaded' | 'enrolled' | 'expired' | 'revoked'

function outcome(key: InstallKey, now: number): Outcome {
  if (key.enrolled_at != null) return 'enrolled'
  if (key.revoked_at != null) return 'revoked'
  if (key.expires_at <= now) return 'expired'
  return key.used_at != null ? 'downloaded' : 'unused'
}

const FILL: Record<Outcome, string> = {
  unused: tone('accent'),
  downloaded: tone('warn'),
  enrolled: tone('node'),
  expired: tone('line-strong'),
  revoked: tone('alert'),
}

const TONE: Record<Outcome, 'accent' | 'neutral' | 'alert' | 'warn'> = {
  unused: 'accent',
  downloaded: 'warn',
  enrolled: 'neutral',
  expired: 'neutral',
  revoked: 'alert',
}

const OUTCOMES: Outcome[] = ['enrolled', 'unused', 'downloaded', 'expired', 'revoked']
const SHOWN_FIRST: Outcome[] = ['unused', 'downloaded', 'expired', 'revoked']
const SAID: Record<Outcome, string> = {
  enrolled: 'became an endpoint',
  unused: 'not used yet',
  downloaded: 'installer fetched, not enrolled',
  expired: 'ran out unused',
  revoked: 'withdrawn',
}
const route = getRouteApi('/app/installers')
const THICK = 84
const SLOT = 24
const GAP = 4
const SOURCE = 10
const LABELS = 230

function Flow({ totals, shown, onToggle }: { totals: Record<Outcome, number>; shown: ReadonlySet<Outcome>; onToggle: (state: Outcome) => void }) {
  const [frame, { width }] = useSize<HTMLDivElement>()
  const issued = OUTCOMES.reduce((sum, state) => sum + totals[state], 0)
  const { strands, height } = useMemo(() => fan(OUTCOMES.map((state) => totals[state]), THICK, SLOT, GAP), [totals])
  const reach = Math.max(SOURCE + 40, width - Math.min(LABELS, width * 0.55))
  const source = strands.filter((strand) => strand.from[1] > strand.from[0])

  return (
    <section aria-label="Where the keys went" className="shrink-0 border-b border-line px-4 py-3">
      <div ref={frame} className="relative" style={{ height }}>
        {width > 0 ? (
          <svg width={width} height={height} className="absolute inset-0" aria-hidden>
            {source.length > 0 ? (
              <rect x={0} y={source[0]!.from[0]} width={SOURCE} height={source[source.length - 1]!.from[1] - source[0]!.from[0]} rx={2} fill={tone('soft')} />
            ) : null}
            {strands.map((strand, index) => {
              const state = OUTCOMES[index]!
              return totals[state] > 0 ? (
                <path key={state} d={strandPath(strand, SOURCE, reach)} fill={FILL[state]} opacity={shown.has(state) ? 0.85 : 0.28} />
              ) : (
                <line
                  key={state}
                  x1={reach - 26}
                  x2={reach}
                  y1={(strand.slot[0] + strand.slot[1]) / 2}
                  y2={(strand.slot[0] + strand.slot[1]) / 2}
                  stroke={tone('line-strong')}
                  strokeDasharray="2 4"
                />
              )
            })}
          </svg>
        ) : null}
        <span className="absolute left-[18px] font-mono text-[11px] leading-tight text-muted" style={{ top: Math.max(0, height / 2 - 14) }}>
          <span className="block text-sm text-text">{issued.toLocaleString('en-US')}</span>
          issued
        </span>
        <div role="group" aria-label="Show keys by outcome">
          {OUTCOMES.map((state, index) => (
            <button
              key={state}
              type="button"
              aria-pressed={shown.has(state)}
              onClick={() => onToggle(state)}
              className={cn(
                'absolute flex items-center gap-2 rounded-md px-2 text-left text-xs transition-colors hover:bg-raised',
                shown.has(state) ? 'text-text' : 'text-muted',
              )}
              style={{ left: reach + 6, right: 0, top: strands[index]!.slot[0], height: strands[index]!.slot[1] - strands[index]!.slot[0] }}
            >
              <span className={cn('h-2 w-2 shrink-0 rounded-[2px]', !shown.has(state) && 'opacity-40')} style={{ background: FILL[state] }} aria-hidden />
              <span className="shrink-0">{state}</span>
              <span className="shrink-0 font-mono text-[11px] text-soft">{totals[state].toLocaleString('en-US')}</span>
              <span className="hidden min-w-0 truncate text-[11px] text-faint @[720px]:inline">{SAID[state]}</span>
            </button>
          ))}
        </div>
      </div>
    </section>
  )
}

export function Installers() {
  const now = useNow()
  const queryClient = useQueryClient()
  const admin = isAdmin(useSession((state) => state.session))
  const { data } = useInstallKeys()
  const agents = useAgentIndex()
  const [target, setTarget] = useState<Target>('windows')
  const [fresh, setFresh] = useState<InstallKeyResponse | null>(null)
  const scrollRef = useRef<HTMLDivElement>(null)
  const search = route.useSearch()
  const navigate = route.useNavigate()
  const shown = useMemo(() => {
    const wanted = search.show?.split(',')
    return new Set(wanted ? OUTCOMES.filter((state) => wanted.includes(state)) : SHOWN_FIRST)
  }, [search.show])

  const issue = useMutation({
    mutationFn: () => api.generateInstallKey(),
    onSuccess: (key) => {
      setFresh(key)
      void queryClient.invalidateQueries({ queryKey: ['install-keys'] })
    },
  })

  const keys = useMemo(() => [...(data ?? [])].sort((a, b) => b.created_at - a.created_at), [data])
  const totals = useMemo(() => {
    const out: Record<Outcome, number> = { unused: 0, downloaded: 0, enrolled: 0, expired: 0, revoked: 0 }
    for (const key of keys) out[outcome(key, now)] += 1
    return out
    // totals follow the key list; expiry flips are picked up on the next refetch
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [keys])

  const rows = keys.filter((key) => shown.has(outcome(key, now)))
  const toggle = (state: Outcome) => {
    const next = OUTCOMES.filter((item) => (item === state ? !shown.has(item) : shown.has(item)))
    const same = next.length === SHOWN_FIRST.length && next.every((item) => SHOWN_FIRST.includes(item))
    void navigate({ search: { show: same ? undefined : next.join(',') }, replace: true })
  }

  const virtual = useVirtualizer({
    count: rows.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => 40,
    overscan: 12,
  })

  const command = fresh ? commandFor(target, fresh) : ''

  return (
    <div className="absolute inset-0 flex flex-col gap-3 overflow-hidden px-6 pb-5 pt-4">
      <PageHeader title="Installers" meta={`${keys.length} keys · ${totals.unused + totals.downloaded} outstanding`}>
        <Segmented label="Target" value={target} options={TARGETS} onChange={setTarget} />
        {admin ? (
          <Button variant="primary" onClick={() => issue.mutate()} disabled={issue.isPending}>
            <Plus size={16} strokeWidth={2} aria-hidden />
            Key
          </Button>
        ) : null}
      </PageHeader>

      {issue.error ? (
        <div role="alert" className="text-sm text-alert-soft">
          {issue.error instanceof ApiError ? issue.error.message : 'Key not issued'}
        </div>
      ) : null}

      {fresh ? (
        <Card className="shrink-0 border-accent/60 p-4">
          <div className="mb-2 flex items-center gap-3">
            <Chip tone="accent">single use</Chip>
            <span className="font-mono text-xs text-muted">
              {shortId(fresh.id)} · agent v{fresh.agent_version} · expires {span(fresh.expires_at - now)}
            </span>
            <button
              type="button"
              onClick={() => setFresh(null)}
              aria-label="Dismiss"
              className="ml-auto rounded-md p-1 text-muted hover:bg-raised hover:text-text"
            >
              <X size={16} strokeWidth={1.5} aria-hidden />
            </button>
          </div>
          <div className="flex items-start gap-2 rounded-control border border-line-strong bg-sunken p-3">
            <pre className="min-w-0 flex-1 overflow-x-auto whitespace-pre font-mono text-[13px] leading-relaxed text-text">{command}</pre>
            <CopyButton value={command} label="Copy command" />
          </div>
        </Card>
      ) : null}

      <Card className="@container flex min-h-0 flex-1 flex-col overflow-hidden">
        <Flow totals={totals} shown={shown} onToggle={toggle} />
        <div ref={scrollRef} className="min-h-0 flex-1 overflow-y-auto">
          {rows.length === 0 ? <Empty title={keys.length === 0 ? 'No keys issued yet' : 'No keys with these outcomes'} /> : null}
          <div style={{ height: virtual.getTotalSize(), position: 'relative' }}>
            {virtual.getVirtualItems().map((item) => {
              const key = rows[item.index]!
              const state = outcome(key, now)
              return (
                <div
                  key={key.id}
                  data-key={state}
                  className={cn(
                    'absolute left-0 flex h-10 w-full items-center gap-4 border-b border-hairline px-4 font-mono text-xs',
                    state === 'expired' && 'opacity-55',
                  )}
                  style={{ transform: `translateY(${item.start}px)` }}
                >
                  <span className="w-[76px] shrink-0 text-text">{shortId(key.id)}</span>
                  <span className="w-[150px] shrink-0 text-muted">{dateTime(key.created_at)}</span>
                  <span className="w-[90px] shrink-0 truncate text-soft">{key.created_by}</span>
                  <span className="w-[64px] shrink-0 text-muted">v{key.agent_version}</span>
                  <span className="w-[92px] shrink-0">
                    <Chip tone={TONE[state]}>{state}</Chip>
                  </span>
                  {state === 'unused' || state === 'downloaded' ? (
                    <span className="flex min-w-0 flex-1 items-center gap-3 text-muted">
                      <span className="shrink-0">expires in {span(key.expires_at - now)}</span>
                      <span
                        className="hidden h-1 min-w-[60px] max-w-[220px] flex-1 overflow-hidden rounded-full bg-sunken @[840px]:block"
                        role="img"
                        aria-label={`${Math.round((Math.max(0, key.expires_at - now) / Math.max(1, key.expires_at - key.created_at)) * 100)}% of its life left`}
                      >
                        <span
                          className={cn('block h-full rounded-full', state === 'downloaded' ? 'bg-warn' : 'bg-accent')}
                          style={{ width: `${(Math.max(0, key.expires_at - now) / Math.max(1, key.expires_at - key.created_at)) * 100}%` }}
                        />
                      </span>
                    </span>
                  ) : (
                    <span className="min-w-0 truncate text-muted">
                      {state === 'enrolled'
                        ? `${(key.enrolled_agent_id && agents.get(key.enrolled_agent_id)?.hostname) || shortId(key.enrolled_agent_id ?? '')} · ${span((key.enrolled_at ?? key.created_at) - key.created_at)} after issue`
                        : state === 'revoked'
                          ? `revoked ${ago(key.revoked_at ?? now, now)} ago`
                          : `expired ${ago(key.expires_at, now)} ago`}
                    </span>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      </Card>
    </div>
  )
}
