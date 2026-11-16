import { useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useRef } from 'react'
import { Empty } from '@/components/ui/bits'
import { FindBox } from '@/components/ui/find-box'
import { api, type Agent } from '@/lib/api'
import { cn } from '@/lib/cn'
import { clock } from '@/lib/format'
import {
  buildAutostart,
  itemState,
  KIND_LABEL,
  KIND_ORDER,
  matchesAutostart,
  momentOf,
  MOMENTS,
  type AutostartItem,
  type ItemState,
  type Moment,
} from '@/lib/persistence'
import { useAgentEvents } from '@/lib/queries'

type Props = {
  agent: Agent
  find: string
  onFind: (find: string) => void
  when: Moment | null
  onWhen: (when: Moment | null) => void
  openId: string | null
  onOpen: (id: string | null) => void
}

const ROW = 'grid w-full items-center gap-3 px-3 text-left font-mono text-xs grid-cols-[10px_minmax(110px,0.8fr)_minmax(140px,1.6fr)] @[760px]:grid-cols-[10px_minmax(150px,0.8fr)_minmax(220px,1.6fr)_72px_minmax(180px,1fr)]'
const WIDE = 'hidden truncate @[760px]:block'
const CHANGE_TONE = { Added: 'text-warn', Changed: 'text-warn', Removed: 'text-faint' }
const DOT: Record<ItemState, string> = {
  flagged: 'bg-alert',
  noted: 'bg-warn',
  changed: 'bg-warn',
  removed: 'border border-faint',
  plain: 'bg-node',
}
const DOTS = 36

function Chain({ items, when, onWhen }: { items: AutostartItem[]; when: Moment | null; onWhen: (when: Moment | null) => void }) {
  return (
    <section aria-label="When it runs" className="relative mx-4 mb-2 shrink-0 rounded-card border border-line bg-surface px-3 pb-2.5 pt-3">
      <span className="absolute inset-x-3 top-[21px] h-px bg-line-strong" aria-hidden />
      <div className="relative grid grid-cols-5 gap-x-2">
        {MOMENTS.map((moment) => {
          const members = items.filter((item) => momentOf(item.kind) === moment.id)
          const states = members.map(itemState)
          const flagged = states.includes('flagged')
          const noted = states.includes('noted') || states.includes('changed')
          const picked = when === moment.id
          return (
            <button
              key={moment.id}
              type="button"
              data-moment={moment.id}
              aria-pressed={picked}
              disabled={members.length === 0}
              onClick={() => onWhen(picked ? null : moment.id)}
              className={cn(
                'flex min-w-0 flex-col items-start rounded-lg px-1 pb-1.5 text-left transition-colors enabled:hover:bg-raised disabled:cursor-default',
                picked && 'bg-selected enabled:hover:bg-selected',
              )}
            >
              <span
                className={cn(
                  'flex h-[18px] min-w-[18px] items-center justify-center rounded-full border bg-surface px-1 font-mono text-[10px] leading-none',
                  flagged ? 'border-alert text-alert-soft' : noted ? 'border-warn text-warn' : members.length > 0 ? 'border-line-hover text-soft' : 'border-line text-faint',
                  picked && 'bg-text text-ink',
                )}
              >
                {members.length}
              </span>
              <span className={cn('mt-1.5 w-full truncate font-display text-[11px] uppercase @[560px]:tracking-wider', members.length > 0 ? 'text-muted' : 'text-faint', picked && 'text-text')}>
                <span className="@[560px]:hidden">{moment.short}</span>
                <span className="hidden @[560px]:inline">{moment.label}</span>
              </span>
              <span className="mt-1.5 flex min-h-[9px] flex-wrap gap-[3px]" aria-hidden>
                {states.slice(0, DOTS).map((state, index) => (
                  <span key={index} className={cn('h-[7px] w-[7px] rounded-full', DOT[state])} />
                ))}
                {states.length > DOTS ? <span className="font-mono text-[9px] leading-[7px] text-muted">+{states.length - DOTS}</span> : null}
              </span>
            </button>
          )
        })}
      </div>
    </section>
  )
}

function Row({ item, open, onToggle }: { item: AutostartItem; open: boolean; onToggle: () => void }) {
  const state = itemState(item)
  const removed = state === 'removed'
  return (
    <div data-autostart={item.name} data-autostart-id={item.key} className={cn('border-b border-hairline', state === 'flagged' && 'bg-alert-surface/50')}>
      <button type="button" aria-expanded={open} onClick={onToggle} className={cn(ROW, 'min-h-9 py-1.5 hover:bg-raised', removed && 'text-faint')}>
        <span className={cn('h-2 w-2 rounded-full', DOT[state])} aria-hidden />
        <span className="min-w-0">
          <span className={cn('block truncate', removed ? 'line-through' : 'text-text')}>{item.name}</span>
          {item.finding ? (
            <span className={cn('block truncate font-sans text-[11px]', item.finding.high ? 'text-alert-soft' : 'text-warn')}>
              {item.finding.title} · {item.finding.technique}
            </span>
          ) : item.change && item.changedAt != null ? (
            <span className={cn('block truncate font-sans text-[11px]', CHANGE_TONE[item.change])}>
              {item.change} {clock(item.changedAt)}
            </span>
          ) : null}
        </span>
        <span className={cn('truncate', removed ? 'text-faint' : 'text-soft')} title={item.command}>
          {item.command}
        </span>
        <span className={cn(WIDE, 'text-muted')}>{item.user}</span>
        <span className={cn(WIDE, 'text-muted')} title={item.path}>
          {item.path}
        </span>
      </button>
      {open ? (
        <dl className="grid grid-cols-[72px_minmax(0,1fr)] gap-x-3 gap-y-1 px-3 pb-3 pl-[34px] font-mono text-xs">
          {item.finding ? (
            <>
              <dt className="text-muted">finding</dt>
              <dd className={cn('font-sans', item.finding.high ? 'text-alert-soft' : 'text-warn')}>
                {item.finding.title} · {item.finding.technique}
              </dd>
            </>
          ) : null}
          <dt className="text-muted">command</dt>
          <dd className="break-all text-text">{item.command || 'none'}</dd>
          <dt className="text-muted">path</dt>
          <dd className="break-all text-soft">{item.path}</dd>
          <dt className="text-muted">user</dt>
          <dd className="text-soft">{item.user}</dd>
          <dt className="text-muted">state</dt>
          <dd className="text-soft">{removed ? 'removed' : item.enabled ? 'enabled' : 'disabled'}</dd>
          {item.hash ? (
            <>
              <dt className="text-muted">sha256</dt>
              <dd className="break-all text-soft">{item.hash}</dd>
            </>
          ) : null}
        </dl>
      ) : null}
    </div>
  )
}

export function PersistenceLens({ agent, find, onFind, when, onWhen, openId, onOpen }: Props) {
  const inventory = useQuery({
    queryKey: ['persistence', agent.id],
    queryFn: () => api.events({ agentId: agent.id, types: ['persistence'], limit: 2000 }),
    refetchInterval: 20_000,
  })
  const own = useAgentEvents(agent.id)
  const items = useMemo(() => buildAutostart(inventory.data ?? [], own.data ?? []), [inventory.data, own.data])
  const found = useMemo(() => items.filter((item) => matchesAutostart(item, find)), [items, find])
  const shown = useMemo(() => (when ? found.filter((item) => momentOf(item.kind) === when) : found), [found, when])
  const findRef = useRef<HTMLInputElement>(null)
  const list = useRef<HTMLDivElement>(null)

  const only = find.trim() && shown.length === 1 ? shown[0]!.key : null
  useEffect(() => {
    if (only) onOpen(only)
    // opens the single match once per find, so closing it again stays closed
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [only])
  useEffect(() => {
    if (!openId) return
    list.current?.querySelector(`[data-autostart-id="${CSS.escape(openId)}"]`)?.scrollIntoView({ block: 'nearest' })
  }, [openId, shown.length])

  if (items.length === 0) {
    return <Empty title={inventory.isLoading ? 'Loading autostart items' : 'This endpoint has not reported what starts by itself'} />
  }

  const notable = shown.filter((item) => item.finding || item.change)
  const notableKeys = new Set(notable.map((item) => item.key))
  const sections = [
    { id: 'notable', label: 'Flagged and changed', items: notable },
    ...KIND_ORDER.map((kind) => ({
      id: kind,
      label: KIND_LABEL[kind] ?? kind,
      items: shown.filter((item) => item.kind === kind && !notableKeys.has(item.key)).sort((a, b) => a.name.localeCompare(b.name)),
    })),
  ].filter((section) => section.items.length > 0)
  const changed = items.filter((item) => item.change).length

  return (
    <div
      className="@container absolute inset-0 flex flex-col"
      onKeyDown={(event) => {
        if (event.key === '/' && !(event.target instanceof HTMLInputElement)) {
          event.preventDefault()
          findRef.current?.focus()
        }
      }}
    >
      <div className="flex shrink-0 flex-wrap items-center gap-2 px-4 pb-2">
        <FindBox value={find} onChange={onFind} placeholder="Find item, command, path" label="Find in persistence" inputRef={findRef} />
        <span className="ml-auto font-mono text-xs text-muted">
          {shown.length === items.length ? `${items.length} items` : `${shown.length} of ${items.length} items`}
          {changed > 0 ? ` · ${changed} changed` : ''}
        </span>
      </div>
      <Chain items={found} when={when} onWhen={onWhen} />
      <div ref={list} className="@container mx-4 mb-3 min-h-0 flex-1 overflow-y-auto rounded-card border border-line bg-surface">
        {sections.length === 0 ? <div className="px-3 py-3 font-mono text-xs text-muted">Nothing matches.</div> : null}
        {sections.map((section) => (
          <section key={section.id} aria-label={section.label}>
            <h3 className="sticky top-0 z-10 flex h-8 items-center justify-between border-b border-line bg-surface px-3 font-display text-[11px] uppercase tracking-wider text-muted">
              <span>{section.label}</span>
              <span className="font-mono normal-case tracking-normal">{section.items.length}</span>
            </h3>
            {section.items.map((item) => (
              <Row key={item.key} item={item} open={openId === item.key} onToggle={() => onOpen(openId === item.key ? null : item.key)} />
            ))}
          </section>
        ))}
      </div>
    </div>
  )
}
