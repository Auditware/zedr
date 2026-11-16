import { useNavigate } from '@tanstack/react-router'
import { Command } from 'cmdk'
import { CornerDownLeft, Search, X } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { StateDot } from '@/components/ui/bits'
import { useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { span } from '@/lib/format'
import { useLive } from '@/lib/live'
import { nodeState } from '@/lib/map-layout'
import { useAgents, useIncidents, useInstallKeys, useNow, useShellSessions } from '@/lib/queries'
import { search, type SearchTarget } from '@/lib/search'

const key = 'rounded-md border border-line-strong px-1.5 py-px font-mono text-[10px] text-muted'

function AnythingSearch() {
  const navigate = useNavigate()
  const signOut = useSession((state) => state.signOut)
  const now = useNow(10_000)
  const { data: agents } = useAgents()
  const { data: incidents } = useIncidents()
  const { data: sessions } = useShellSessions()
  const { data: keys } = useInstallKeys()
  const inputRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState('')
  const [open, setOpen] = useState(false)

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault()
        inputRef.current?.focus()
        inputRef.current?.select()
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [])

  const groups = useMemo(
    () =>
      open
        ? search(query, { agents: agents ?? [], incidents: incidents ?? [], sessions: sessions ?? [], keys: keys ?? [], now })
        : [],
    [open, query, agents, incidents, sessions, keys, now],
  )

  const flagged = useMemo(
    () => new Set((incidents ?? []).filter((incident) => incident.closed_at == null).map((incident) => incident.agent_id)),
    [incidents],
  )
  const byId = useMemo(() => new Map((agents ?? []).map((agent) => [agent.id, agent])), [agents])

  const close = () => {
    setOpen(false)
    setQuery('')
    inputRef.current?.blur()
  }

  const go = (target: SearchTarget) => {
    close()
    switch (target.kind) {
      case 'endpoint':
        return void navigate({ to: '/endpoints', search: { host: target.agentId } })
      case 'subnet':
        return void navigate({ to: '/endpoints', search: { group: 'subnet', pick: target.key } })
      case 'shell':
        return void navigate({ to: '/shell', search: { agent: target.agentId } })
      case 'events':
        return void navigate({ to: '/events', search: { agent: target.agentId } })
      case 'session':
        return void navigate({ to: '/shell', search: { session: target.sessionId } })
      case 'page':
        return void navigate({ to: target.to })
      case 'sign-out':
        return signOut()
    }
  }

  return (
    <Command shouldFilter={false} loop label="Search anything" className="relative min-w-0 flex-[0_1_640px]">
      <div
        className={cn(
          'flex h-9 items-center gap-2.5 rounded-control border bg-surface px-3 transition-colors',
          open ? 'border-accent' : 'border-line hover:border-line-hover',
        )}
      >
        <Search size={16} strokeWidth={1.5} className="shrink-0 text-muted" aria-hidden />
        <Command.Input
          ref={inputRef}
          value={query}
          onValueChange={(value) => {
            setQuery(value)
            setOpen(true)
          }}
          onFocus={() => setOpen(true)}
          onBlur={() => setOpen(false)}
          onKeyDown={(event) => {
            if (event.key === 'Escape') {
              event.preventDefault()
              close()
            }
          }}
          placeholder="Search anything: host, address, subnet, incident, key, page"
          className="h-full min-w-0 flex-1 bg-transparent text-sm text-text outline-none placeholder:text-muted"
        />
        {query ? (
          <button
            type="button"
            aria-label="Clear search"
            onMouseDown={(event) => event.preventDefault()}
            onClick={() => setQuery('')}
            className="text-muted hover:text-text"
          >
            <X size={15} strokeWidth={1.75} aria-hidden />
          </button>
        ) : (
          <kbd className={key}>⌘K</kbd>
        )}
      </div>

      {open ? (
        <div
          onMouseDown={(event) => event.preventDefault()}
          className="absolute left-0 right-0 top-[calc(100%+6px)] z-40 overflow-hidden rounded-card border border-line-strong bg-raised shadow-2xl shadow-black/70"
        >
          <Command.List className="max-h-[min(60vh,520px)] overflow-y-auto p-2">
            <Command.Empty className="p-6 text-center text-sm text-muted">Nothing matches.</Command.Empty>
            {groups.map((group) => (
              <Command.Group
                key={group.heading}
                heading={group.heading}
                className="[&_[cmdk-group-heading]]:px-3 [&_[cmdk-group-heading]]:pb-1 [&_[cmdk-group-heading]]:pt-2.5 [&_[cmdk-group-heading]]:text-[11px] [&_[cmdk-group-heading]]:font-medium [&_[cmdk-group-heading]]:uppercase [&_[cmdk-group-heading]]:tracking-wider [&_[cmdk-group-heading]]:text-muted"
              >
                {group.results.map((result) => {
                  const agent = result.agentId ? byId.get(result.agentId) : undefined
                  return (
                    <Command.Item
                      key={result.id}
                      value={result.id}
                      onSelect={() => go(result.target)}
                      className="group flex h-10 cursor-pointer items-center gap-3 rounded-lg px-3 text-sm text-soft data-[selected=true]:bg-selected data-[selected=true]:text-accent-strong"
                    >
                      {agent ? <StateDot state={nodeState(agent, flagged.has(agent.id))} /> : null}
                      <span className={cn('shrink-0', result.mono && 'font-mono')}>{result.title}</span>
                      <span className="min-w-0 flex-1 truncate text-xs text-muted">{result.meta}</span>
                      <CornerDownLeft
                        size={14}
                        strokeWidth={1.5}
                        className="hidden shrink-0 text-muted group-data-[selected=true]:block"
                        aria-hidden
                      />
                    </Command.Item>
                  )
                })}
              </Command.Group>
            ))}
          </Command.List>
          <div className="flex items-center gap-4 border-t border-line px-4 py-2 text-[11px] text-muted">
            <span>
              <kbd className={key}>↑↓</kbd> move
            </span>
            <span>
              <kbd className={key}>↵</kbd> open
            </span>
            <span>
              <kbd className={key}>esc</kbd> close
            </span>
          </div>
        </div>
      ) : null}
    </Command>
  )
}

function Impersonation() {
  const session = useSession((state) => state.session)
  const stop = useSession((state) => state.stopImpersonating)
  const now = useNow(1000)
  const view = session?.view
  const left = view ? view.until - now : 0

  useEffect(() => {
    if (view && left <= 0) stop()
  }, [view, left, stop])

  if (!session || !view) return null
  return (
    <button
      type="button"
      onClick={stop}
      className="inline-flex h-8 shrink-0 items-center gap-2 rounded-control border border-warn/50 bg-warn-surface px-3 text-xs font-semibold text-warn hover:border-warn"
    >
      Viewing as {session.username}
      <span className="font-mono font-normal">{span(Math.max(0, left))}</span>
      <span className="font-normal text-text">Return</span>
    </button>
  )
}

export function TopBar() {
  const connected = useLive((state) => state.connected)

  return (
    <header className="flex h-12 shrink-0 items-center gap-3 border-b border-hairline px-3">
      <span className="min-w-0 flex-1 basis-0 max-md:hidden" />
      <AnythingSearch />
      <div className="flex min-w-max flex-1 basis-0 items-center justify-end gap-2 max-md:flex-none">
        <Impersonation />
        {connected ? null : (
          <span role="status" className="shrink-0 rounded-full bg-alert-surface px-2.5 py-0.5 text-xs font-semibold text-alert-soft">
            Offline
          </span>
        )}
      </div>
    </header>
  )
}
