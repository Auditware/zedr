import { useMutation, useQueryClient } from '@tanstack/react-query'
import { getRouteApi } from '@tanstack/react-router'
import { Command } from 'cmdk'
import { PanelLeft, Plus, Power } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { TerminalView } from '@/components/common/TerminalView'
import { Chip, CopyButton, Empty, Row, StateDot } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { Dialog } from '@/components/ui/dialog'
import { CollapseToggle, Handle, Panel, PaneStrip, Split, STRIP_SIZE, useCollapsible } from '@/components/ui/panes'
import { ApiError, api } from '@/lib/api'
import { isAdmin, useSession } from '@/lib/auth'
import { ago, shortId, span } from '@/lib/format'
import { nodeState } from '@/lib/map-layout'
import { useAgents, useMedia, useNow, useShellCommands, useShellSessions } from '@/lib/queries'

const route = getRouteApi('/app/shell')
const creating = new Set<string>()

export function Shell() {
  const search = route.useSearch()
  const navigate = route.useNavigate()
  const queryClient = useQueryClient()
  const now = useNow()
  const narrow = useMedia('(max-width: 860px)')
  const admin = isAdmin(useSession((state) => state.session))
  const { data: sessions } = useShellSessions()
  const { data: agents } = useAgents()
  const list = useCollapsible(STRIP_SIZE)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [error, setError] = useState('')
  const wanted = useRef(search.agent)

  const byId = useMemo(() => new Map((agents ?? []).map((agent) => [agent.id, agent])), [agents])
  const ordered = useMemo(
    () =>
      [...(sessions ?? [])].sort((a, b) => {
        const liveA = a.terminated_at == null && a.expires_at > now
        const liveB = b.terminated_at == null && b.expires_at > now
        return Number(liveB) - Number(liveA) || b.created_at - a.created_at
      }),
    // ordering only needs to follow the session list, not every clock tick
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sessions],
  )
  const current = ordered.find((session) => session.id === search.session) ?? (search.agent ? undefined : ordered[0])
  const active = !!current && current.terminated_at == null && current.expires_at > now
  const host = current ? (byId.get(current.agent_id)?.hostname ?? shortId(current.agent_id)) : ''

  const open = useMutation({
    mutationFn: (agentId: string) => api.createShellSession(agentId),
    onSuccess: async (created) => {
      await queryClient.invalidateQueries({ queryKey: ['shell'] })
      void navigate({ search: { session: created.session_id }, replace: true })
    },
    onError: (cause) => setError(cause instanceof ApiError ? cause.message : 'Session not opened'),
  })

  useEffect(() => {
    const agentId = wanted.current
    if (!agentId || !sessions) return
    wanted.current = undefined
    const existing = sessions.find(
      (session) => session.agent_id === agentId && session.terminated_at == null && session.expires_at > now,
    )
    if (existing) {
      void navigate({ search: { session: existing.id }, replace: true })
    } else if (admin && !creating.has(agentId)) {
      creating.add(agentId)
      open.mutate(agentId, { onSettled: () => creating.delete(agentId) })
    }
    // runs once when the session list first arrives for a requested host
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [sessions])

  const terminate = useMutation({
    mutationFn: (id: string) => api.terminateShellSession(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['shell'] }),
  })

  const { data: commands } = useShellCommands(admin ? current?.id : undefined, active)
  const pending = (commands ?? []).filter((command) => command.executed_at == null).length

  const run = async (command: string) => {
    if (!current) throw new Error('no session')
    const sent = await api.runShellCommand(current.id, command)
    void queryClient.invalidateQueries({ queryKey: ['shell', 'commands', current.id] })
    return sent.command_id
  }

  return (
    <div className="absolute inset-0 p-2">
      <Split id={narrow ? 'shell-narrow' : 'shell'} orientation={narrow ? 'vertical' : 'horizontal'}>
        <Panel
          id="sessions"
          defaultSize={narrow ? 220 : 290}
          minSize={narrow ? 120 : 220}
          maxSize={460}
          collapsible
          collapsedSize={STRIP_SIZE}
          panelRef={list.panelRef}
          onResize={list.onResize}
        >
          {list.collapsed ? (
            <PaneStrip
              label="Sessions"
              icon={<PanelLeft size={18} strokeWidth={1.5} aria-hidden />}
              onOpen={list.toggle}
              orientation={narrow ? 'vertical' : 'horizontal'}
            />
          ) : (
          <div className="flex h-full flex-col overflow-hidden p-2">
            <div className="mb-3 flex items-center gap-2">
              <h1 className="mr-auto font-display text-[22px] font-medium leading-tight tracking-tight">Shell</h1>
              {admin ? (
                <Button variant="primary" size="sm" onClick={() => setPickerOpen(true)}>
                  <Plus size={15} strokeWidth={2} aria-hidden />
                  Session
                </Button>
              ) : null}
              <CollapseToggle collapsed={false} onToggle={list.toggle} label="sessions" />
            </div>
            <div className="min-h-0 flex-1 overflow-y-auto pr-1">
              {ordered.map((session) => {
                const live = session.terminated_at == null && session.expires_at > now
                return (
                  <Row
                    key={session.id}
                    selected={current?.id === session.id}
                    dim={!live}
                    onClick={() => void navigate({ search: { session: session.id }, replace: true })}
                    className="mb-1.5"
                  >
                    <StateDot state={live ? 'shell' : 'stopped'} />
                    <span className="min-w-0 flex-1">
                      <span className="block truncate font-mono text-[13px]">
                        {byId.get(session.agent_id)?.hostname ?? shortId(session.agent_id)}
                      </span>
                      <span className="block truncate font-mono text-[11px] text-muted">
                        {live
                          ? `expires ${span(session.expires_at - now)}`
                          : `ended ${ago(session.terminated_at ?? session.expires_at, now)}`}
                      </span>
                    </span>
                  </Row>
                )
              })}
            </div>
          </div>
          )}
        </Panel>
        <Handle orientation={narrow ? 'vertical' : 'horizontal'} />
        <Panel id="terminal" minSize={narrow ? 240 : 380}>
          <div className="flex h-full flex-col overflow-hidden rounded-card border border-line-strong bg-sunken">
            <div className="flex shrink-0 flex-wrap items-center gap-x-3 gap-y-1 border-b border-line px-3 py-2">
              {current ? (
                <>
                  <span className="font-mono text-sm font-medium">{host}</span>
                  <Chip tone={active ? 'accent' : 'neutral'}>{active ? 'signed session' : 'ended'}</Chip>
                  <span className="inline-flex items-center gap-1 font-mono text-[11px] text-muted">
                    {shortId(current.id)}
                    <CopyButton value={current.id} label="Copy session id" className="h-5 w-5" />
                  </span>
                  {active && pending > 0 ? <Chip tone="warn">{pending} waiting for agent</Chip> : null}
                  <span className="ml-auto font-mono text-[11px] text-muted">
                    {active ? `expires ${span(current.expires_at - now)}` : ''}
                  </span>
                  {active && admin ? (
                    <Button variant="danger" size="sm" onClick={() => terminate.mutate(current.id)} disabled={terminate.isPending}>
                      <Power size={14} strokeWidth={1.75} aria-hidden />
                      End
                    </Button>
                  ) : null}
                </>
              ) : null}
            </div>
            <div className="min-h-0 flex-1 p-3">
              {current && !admin ? (
                <Empty title="Commands and their output are shown to admins" />
              ) : current ? (
                <TerminalView
                  key={current.id}
                  sessionId={current.id}
                  host={host}
                  commands={commands ?? []}
                  readOnly={!active}
                  onRun={run}
                />
              ) : (
                <Empty title={open.isPending ? 'Opening session' : 'No session'}>
                  {error ? <div className="text-sm text-alert-soft">{error}</div> : null}
                  {admin && !open.isPending ? (
                    <Button variant="primary" onClick={() => setPickerOpen(true)}>
                      <Plus size={16} strokeWidth={2} aria-hidden />
                      Session
                    </Button>
                  ) : null}
                </Empty>
              )}
            </div>
          </div>
        </Panel>
      </Split>

      <Dialog open={pickerOpen} onOpenChange={setPickerOpen} title="Open a shell on" className="p-0 [&>div:first-child]:px-5 [&>div:first-child]:pt-5">
        <Command label="Hosts" className="px-2 pb-2" filter={(value, typed) => (value.toLowerCase().includes(typed.trim().toLowerCase()) ? 1 : 0)}>
          <Command.Input
            autoFocus
            placeholder="Host or address"
            className="mb-1 h-10 w-full rounded-control border border-line-strong bg-ink px-3 font-mono text-sm text-text outline-none placeholder:font-sans placeholder:text-muted focus:border-accent"
          />
          <Command.List className="max-h-[46vh] overflow-y-auto">
            <Command.Empty className="p-4 text-center text-sm text-muted">Nothing matches.</Command.Empty>
            {(agents ?? []).map((agent) => (
              <Command.Item
                key={agent.id}
                value={`${agent.hostname} ${agent.ip_address ?? ''}`}
                onSelect={() => {
                  setPickerOpen(false)
                  setError('')
                  open.mutate(agent.id)
                }}
                className="flex h-10 cursor-pointer items-center gap-3 rounded-lg px-3 text-sm text-soft data-[selected=true]:bg-selected data-[selected=true]:text-accent-strong"
              >
                <StateDot state={nodeState(agent, false)} />
                <span className="font-mono">{agent.hostname}</span>
                <span className="ml-auto font-mono text-xs text-muted">{agent.ip_address}</span>
              </Command.Item>
            ))}
          </Command.List>
        </Command>
      </Dialog>
    </div>
  )
}
