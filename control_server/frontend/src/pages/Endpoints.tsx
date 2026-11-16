import { useQuery } from '@tanstack/react-query'
import { getRouteApi, Link } from '@tanstack/react-router'
import { ChevronLeft, ChevronRight, PanelBottom, PanelRight } from 'lucide-react'
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Dock } from '@/components/map/Dock'
import { EndpointMap, type MapNode } from '@/components/map/EndpointMap'
import { HostSheet } from '@/components/map/HostSheet'
import { ActivityDock } from '@/components/investigate/ActivityDock'
import { AgentLens } from '@/components/investigate/AgentLens'
import { PersistenceLens } from '@/components/investigate/PersistenceLens'
import type { InvestigationState, Lens } from '@/components/investigate/Investigation'
import { formatCam, formatPeriod, parseCam, parsePeriod } from '@/components/investigate/probe'
import { ProcessSheet } from '@/components/map/ProcessSheet'
import { Empty, Row, SectionTitle, StateDot } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { CollapseToggle, Handle, Panel, PaneStrip, Split, STRIP_SIZE, useCollapsible } from '@/components/ui/panes'
import { Segmented } from '@/components/ui/segmented'
import { api, type Agent, type Incident } from '@/lib/api'
import { incidentTitle } from '@/lib/events'
import { ago } from '@/lib/format'
import {
  GROUP_BY,
  groupKey,
  layoutMap,
  nodeState,
  type GroupBy,
  type NodeState,
} from '@/lib/map-layout'
import { buildProcessModel } from '@/lib/process-tree'
import { useAgents, useIncidents, useMedia, useNow, useShellSessions } from '@/lib/queries'

const route = getRouteApi('/app/endpoints')
const Investigation = lazy(() => import('@/components/investigate/Investigation'))

const LENSES: { id: Lens; label: string }[] = [
  { id: 'processes', label: 'Processes' },
  { id: 'network', label: 'Network' },
  { id: 'files', label: 'Files' },
  { id: 'apps', label: 'Apps' },
  { id: 'persistence', label: 'Persistence' },
  { id: 'agent', label: 'Agent' },
]

const SEVERITY: Record<NodeState, number> = { incident: 0, suspect: 1, stale: 2, stopped: 3, active: 4 }

export function Endpoints() {
  const search = route.useSearch()
  const navigate = route.useNavigate()
  const now = useNow()
  const narrow = useMedia('(max-width: 860px)')
  const { data: agents, isLoading } = useAgents()
  const { data: incidents } = useIncidents()
  const { data: sessions } = useShellSessions()
  const side = useCollapsible(STRIP_SIZE)
  const dock = useCollapsible(STRIP_SIZE)
  const stageRef = useRef<HTMLDivElement>(null)
  const [viewport, setViewport] = useState({ width: 1200, height: 800 })

  useEffect(() => {
    const stage = stageRef.current
    if (!stage) return
    const observer = new ResizeObserver(() => {
      const width = Math.max(200, Math.round(stage.clientWidth / 40) * 40)
      const height = Math.max(200, Math.round(stage.clientHeight / 40) * 40)
      setViewport((current) => (current.width === width && current.height === height ? current : { width, height }))
    })
    observer.observe(stage)
    return () => observer.disconnect()
  }, [])

  const groupBy: GroupBy = search.group ?? 'subnet'
  const allIncidents = useMemo(() => incidents ?? [], [incidents])
  const openIncidents = useMemo(() => allIncidents.filter((incident) => incident.closed_at == null), [allIncidents])
  const openByEndpoint = useMemo(() => {
    const groups = new Map<string, { agentId: string; latest: Incident; count: number }>()
    for (const incident of openIncidents) {
      const group = groups.get(incident.agent_id)
      if (!group) groups.set(incident.agent_id, { agentId: incident.agent_id, latest: incident, count: 1 })
      else {
        group.count += 1
        if (incident.opened_at > group.latest.opened_at) group.latest = incident
      }
    }
    return [...groups.values()].sort((a, b) => b.latest.opened_at - a.latest.opened_at)
  }, [openIncidents])

  const model = useMemo(() => {
    const flagged = new Set(openIncidents.map((incident) => incident.agent_id))
    const shells = new Set(
      (sessions ?? [])
        .filter((session) => session.terminated_at == null && session.expires_at > now)
        .map((session) => session.agent_id),
    )
    const states = new Map<string, NodeState>()
    const groups = new Map<string, Agent[]>()
    const nodes: MapNode[] = []
    const grouped: { id: string; group: string }[] = []
    for (const agent of agents ?? []) {
      const state = nodeState(agent, flagged.has(agent.id))
      const key = groupKey(agent, state, groupBy)
      states.set(agent.id, state)
      nodes.push({ id: agent.id, label: agent.hostname, state, shell: shells.has(agent.id) })
      grouped.push({ id: agent.id, group: key })
      const members = groups.get(key)
      if (members) members.push(agent)
      else groups.set(key, [agent])
    }
    return { nodes, states, groups, layout: layoutMap(grouped, viewport) }
    // `now` only matters for session expiry, which the session refetch already covers
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents, openIncidents, sessions, groupBy, viewport])

  const byId = useMemo(() => new Map((agents ?? []).map((agent) => [agent.id, agent])), [agents])
  const selected = search.host ? byId.get(search.host) : undefined
  const pickedMembers = useMemo(() => {
    if (selected || !search.pick) return undefined
    const members = model.groups.get(search.pick)
    if (!members) return undefined
    return [...members].sort(
      (a, b) =>
        SEVERITY[model.states.get(a.id) ?? 'active'] - SEVERITY[model.states.get(b.id) ?? 'active'] ||
        a.hostname.localeCompare(b.hostname),
    )
  }, [selected, search.pick, model])
  const total = agents?.length ?? 0

  const telemetry = useQuery({
    queryKey: ['telemetry', selected?.id],
    queryFn: () => api.events({ agentId: selected!.id, types: ['process', 'network', 'file'], limit: 4000 }),
    enabled: !!selected,
    refetchInterval: 15_000,
  })
  const processes = useMemo(() => buildProcessModel(telemetry.data ?? []), [telemetry.data])
  const hostIncidents = useMemo(() => allIncidents.filter((incident) => incident.agent_id === selected?.id), [allIncidents, selected?.id])
  const proc = selected && search.proc ? processes.byKey.get(search.proc) : undefined
  const investigation = useMemo<InvestigationState>(
    () => ({
      lens: search.view ?? 'processes',
      arrangement: search.layout ?? 'tree',
      focus: search.focus,
      find: search.find ?? '',
      proc: search.proc ?? null,
      item: search.item ?? null,
      when: search.when ?? null,
      cam: parseCam(search.cam),
      period: parsePeriod(search.t),
    }),
    [search.view, search.layout, search.focus, search.find, search.proc, search.item, search.when, search.cam, search.t],
  )

  const investigate = useCallback(
    (patch: Partial<InvestigationState>) =>
      void navigate({
        search: (previous) => {
          const next = { ...previous }
          const moved = 'lens' in patch || 'arrangement' in patch
          if ('lens' in patch) next.view = patch.lens === 'processes' ? undefined : patch.lens
          if ('arrangement' in patch) next.layout = patch.arrangement === 'list' ? 'list' : undefined
          if ('focus' in patch) next.focus = patch.focus
          if ('find' in patch) next.find = patch.find || undefined
          else if ('lens' in patch) next.find = undefined
          if ('proc' in patch) next.proc = patch.proc ?? undefined
          if ('item' in patch) next.item = patch.item ?? undefined
          else if ('lens' in patch) next.item = undefined
          if ('when' in patch) next.when = patch.when ?? undefined
          else if ('lens' in patch) next.when = undefined
          if ('period' in patch) next.t = patch.period ? formatPeriod(patch.period) : undefined
          if ('cam' in patch) next.cam = patch.cam ? formatCam(patch.cam) : undefined
          else if (moved) next.cam = undefined
          return next
        },
        replace: true,
      }),
    [navigate],
  )

  const selectHost = (id: string | null) =>
    void navigate({
      search: (previous) => ({
        group: previous.group,
        pick: id ? undefined : previous.pick,
        host: id ?? undefined,
        view: previous.view,
        layout: previous.layout,
      }),
    })
  const selectGroup = (key: string | null) =>
    void navigate({ search: (previous) => ({ group: previous.group, pick: key ?? undefined }), replace: true })
  const clear = useCallback(() => void navigate({ search: (previous) => ({ group: previous.group }) }), [navigate])

  const hostOpen = !!search.host
  const procOpen = !!search.proc
  useEffect(() => {
    if (!hostOpen) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented) return
      if (event.target instanceof HTMLInputElement || document.querySelector('[role="dialog"]')) return
      if (procOpen) investigate({ proc: null })
      else clear()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [hostOpen, procOpen, investigate, clear])

  const focusIds = pickedMembers ? pickedMembers.map((agent) => agent.id) : null
  const dockAgents = selected ? [selected] : pickedMembers ? pickedMembers.slice(0, 6) : []
  const hasDock = dockAgents.length > 0

  const { collapsed: sideCollapsed, toggle: toggleSide } = side
  useEffect(() => {
    if ((search.host || search.pick) && sideCollapsed) toggleSide()
    // open the panel when a selection arrives, not whenever it is collapsed afterwards
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [search.host, search.pick])

  if (!isLoading && total === 0) {
    return (
      <Empty title="No endpoints yet">
        <Link to="/installers">
          <Button variant="primary" tabIndex={-1}>
            Enroll the first one
          </Button>
        </Link>
      </Empty>
    )
  }

  return (
    <div className="absolute inset-0 p-2">
      <Split id={narrow ? 'endpoints-narrow' : 'endpoints'} orientation={narrow ? 'vertical' : 'horizontal'}>
        <Panel id="stage" minSize={narrow ? 280 : 320}>
          <Split id="endpoints-stage" orientation="vertical" panelIds={hasDock ? ['map', 'dock'] : ['map']}>
            <Panel id="map" minSize={180}>
              <div className="flex h-full flex-col">
                <div ref={stageRef} className="relative order-2 min-h-0 flex-1">
                  {selected && investigation.lens === 'agent' ? (
                    <AgentLens
                      agent={selected}
                      incidents={hostIncidents}
                      period={investigation.period}
                      now={now}
                      openId={investigation.item}
                      onOpen={(item) => investigate({ item })}
                    />
                  ) : selected && investigation.lens === 'persistence' ? (
                    <PersistenceLens
                      key={selected.id}
                      agent={selected}
                      find={investigation.find}
                      onFind={(find) => investigate({ find })}
                      when={investigation.when}
                      onWhen={(when) => investigate({ when })}
                      openId={investigation.item}
                      onOpen={(item) => investigate({ item })}
                    />
                  ) : selected ? (
                    <Suspense fallback={null}>
                      <Investigation
                        key={selected.id}
                        model={processes}
                        loading={telemetry.isLoading}
                        now={now}
                        state={investigation}
                        onChange={investigate}
                      />
                    </Suspense>
                  ) : (
                    <EndpointMap
                      nodes={model.nodes}
                      layout={model.layout}
                      selectedId={undefined}
                      selectedGroup={pickedMembers ? search.pick : undefined}
                      focusIds={focusIds}
                      onSelect={selectHost}
                      onSelectGroup={(key) => selectGroup(key === search.pick ? null : key)}
                    />
                  )}
                </div>

                <div className="@container/tabs order-1 flex min-h-[52px] shrink-0 flex-wrap items-center gap-x-4 gap-y-2 px-4 pb-2 pt-2">
                  {selected ? (
                    <>
                      <nav aria-label="Breadcrumb" className="mr-1 flex min-w-0 items-center gap-1.5 font-display text-[22px] font-medium leading-tight tracking-tight">
                        <button type="button" onClick={clear} className="text-muted hover:text-text">
                          Endpoints
                        </button>
                        <ChevronRight size={18} strokeWidth={1.5} className="shrink-0 text-faint" aria-hidden />
                        <h1 className="truncate font-mono text-[19px]">{selected.hostname}</h1>
                      </nav>
                      <Segmented label="Investigate" value={investigation.lens} options={LENSES} onChange={(lens) => investigate({ lens })} />
                    </>
                  ) : (
                    <>
                      <div className="mr-1">
                        <h1 className="font-display text-[22px] font-medium leading-tight tracking-tight">Endpoints</h1>
                        <div className="font-mono text-xs text-muted">{total}</div>
                      </div>
                      <Segmented
                        label="Group by"
                        value={groupBy}
                        options={GROUP_BY}
                        onChange={(group) => void navigate({ search: { group }, replace: true })}
                      />
                    </>
                  )}
                </div>

              </div>
            </Panel>
            {hasDock ? (
              <>
                <Handle orientation="vertical" />
                <Panel
                  id="dock"
                  defaultSize={selected ? 214 : 250}
                  minSize={120}
                  maxSize={520}
                  collapsible
                  collapsedSize={STRIP_SIZE}
                  panelRef={dock.panelRef}
                  onResize={dock.onResize}
                >
                  <div className="h-full pl-2">
                    {dock.collapsed ? (
                      <PaneStrip
                        label={selected ? 'Activity' : 'Timeline'}
                        icon={<PanelBottom size={18} strokeWidth={1.5} aria-hidden />}
                        onOpen={dock.toggle}
                        orientation="vertical"
                      />
                    ) : selected ? (
                      <ActivityDock
                        agent={selected}
                        model={processes}
                        incidents={hostIncidents}
                        selectedKey={search.proc ?? null}
                        period={investigation.period}
                        onSelect={(key) => investigate({ proc: key })}
                        onPeriod={(period) => investigate({ period })}
                        onIncident={(incident, at) =>
                          investigate({ lens: 'agent', proc: null, period: [incident.opened_at - 60, (incident.closed_at ?? at) + 60] })
                        }
                        onCollapse={dock.toggle}
                      />
                    ) : (
                      <Dock
                        title={search.pick ?? ''}
                        meta={`${dockAgents.length} of ${pickedMembers?.length ?? 0}, worst first`}
                        agents={dockAgents}
                        incidents={allIncidents}
                        onPick={selectHost}
                        onClose={clear}
                      />
                    )}
                  </div>
                </Panel>
              </>
            ) : null}
          </Split>
        </Panel>
        <Handle orientation={narrow ? 'vertical' : 'horizontal'} />
        <Panel
          id="side"
          defaultSize={narrow ? 320 : 372}
          minSize={narrow ? 200 : 280}
          maxSize={narrow ? 640 : 620}
          collapsible
          collapsedSize={STRIP_SIZE}
          panelRef={side.panelRef}
          onResize={side.onResize}
        >
          {sideCollapsed ? (
            <PaneStrip
              label="Details"
              icon={<PanelRight size={18} strokeWidth={1.5} aria-hidden />}
              onOpen={toggleSide}
              orientation={narrow ? 'vertical' : 'horizontal'}
            />
          ) : (
          <aside aria-label="Details" className="relative h-full overflow-y-auto overflow-x-hidden rounded-card border border-line bg-surface p-[18px]">
            <CollapseToggle collapsed={false} onToggle={toggleSide} label="details" flip className="absolute right-3 top-[18px] z-10" />
            {selected && proc ? (
              <ProcessSheet
                proc={proc}
                host={selected.hostname}
                now={now}
                onSelect={(key) => investigate({ proc: key })}
                onClose={() => investigate({ proc: null })}
              />
            ) : selected ? (
              <HostSheet
                agent={selected}
                state={model.states.get(selected.id) ?? 'active'}
                incidents={hostIncidents}
                onProcess={(key) => investigate({ proc: key })}
                onAutostart={(name) => investigate({ lens: 'persistence', proc: null, find: name })}
              />
            ) : pickedMembers ? (
              <>
                <button
                  type="button"
                  onClick={clear}
                  className="-ml-1.5 mb-3 inline-flex h-8 w-fit items-center gap-1 rounded-md pl-1 pr-2 text-muted hover:bg-raised hover:text-text"
                >
                  <ChevronLeft size={18} strokeWidth={1.5} aria-hidden />
                  All endpoints
                </button>
                <h2 className="truncate font-mono text-xl font-medium tracking-tight">{search.pick}</h2>
                <div className="mb-3 mt-1 font-mono text-xs text-muted">{pickedMembers.length} endpoints</div>
                <div>
                  {pickedMembers.slice(0, 300).map((agent) => {
                    const state = model.states.get(agent.id) ?? 'active'
                    return (
                      <Row key={agent.id} onClick={() => selectHost(agent.id)} className="mb-1.5 min-h-[44px]">
                        <StateDot state={state} />
                        <span className="min-w-0 flex-1 truncate font-mono text-[13px]">{agent.hostname}</span>
                        <span className="font-mono text-xs text-muted">{ago(agent.last_heartbeat, now)}</span>
                      </Row>
                    )
                  })}
                </div>
              </>
            ) : (
              <>
                <SectionTitle className="mb-2 flex h-8 items-center">Open incidents</SectionTitle>
                {openByEndpoint.length === 0 ? (
                  <div className="rounded-xl border border-line px-3.5 py-3 text-sm text-muted">None.</div>
                ) : (
                  openByEndpoint.map(({ agentId, latest, count }) => (
                    <Row key={agentId} onClick={() => selectHost(agentId)} className="mb-1.5">
                      <StateDot state="incident" />
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-mono text-[13px]">{byId.get(agentId)?.hostname ?? agentId.slice(0, 8)}</span>
                        <span className="block truncate text-xs text-muted">
                          {incidentTitle(latest)}
                          {count > 1 ? `, and ${count - 1} more` : ''}
                        </span>
                      </span>
                      <span className="font-mono text-xs text-muted">{ago(latest.opened_at, now)}</span>
                    </Row>
                  ))
                )}
              </>
            )}
          </aside>
          )}
        </Panel>
      </Split>
    </div>
  )
}
