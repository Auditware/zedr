import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from '@tanstack/react-router'
import { ArrowUpCircle, Rows3 } from 'lucide-react'
import { useState } from 'react'
import { CloseIncident, IncidentCard } from '@/components/common/IncidentCard'
import { FindingProof } from '@/components/common/Proof'
import { CopyButton, FindingLine, SectionTitle, StateChip } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { inputClass } from '@/components/ui/dialog'
import { ApiError, api, type Agent, type Incident } from '@/lib/api'
import { isAdmin, useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { detectionOf } from '@/lib/events'
import { baseName } from '@/lib/images'
import { ago, clock, dateTime, shortId } from '@/lib/format'
import { isGrave } from '@/lib/incidents'
import { STATE_LABEL, type NodeState } from '@/lib/map-layout'
import { useNow, useUpgrades } from '@/lib/queries'

const action = 'w-full min-w-0 px-2'
const actionLabel = 'hidden truncate @[310px]:inline'

type Props = {
  agent: Agent
  state: NodeState
  incidents: Incident[]
  onProcess: (key: string) => void
  onAutostart: (name: string) => void
}

export function HostSheet({ agent, state, incidents, onProcess, onAutostart }: Props) {
  const now = useNow()
  const session = useSession((store) => store.session)
  const queryClient = useQueryClient()
  const { data: upgrades } = useUpgrades()
  const [target, setTarget] = useState('')
  const [upgradeOpen, setUpgradeOpen] = useState(false)
  const lastUpgrade = upgrades?.find((upgrade) => upgrade.agent_id === agent.id)

  const upgrade = useMutation({
    mutationFn: async (version: string) => {
      const key = await api.generateInstallKey(version)
      return api.issueUpgrade({ agent_id: agent.id, install_key_id: key.id, target_version: version })
    },
    onSuccess: () => {
      setUpgradeOpen(false)
      setTarget('')
      void queryClient.invalidateQueries({ queryKey: ['upgrades'] })
    },
  })

  const facts: { label: string; value: string; shown: string; mono: boolean; copy: boolean }[] = [
    { label: 'ID', value: agent.id, shown: shortId(agent.id), mono: true, copy: true },
    { label: 'System', value: agent.os_version || agent.platform, shown: agent.os_version || agent.platform, mono: false, copy: false },
    { label: 'Arch', value: agent.architecture, shown: agent.architecture, mono: false, copy: false },
    { label: 'Address', value: agent.ip_address ?? '-', shown: agent.ip_address ?? '-', mono: true, copy: true },
    { label: 'Agent', value: agent.version, shown: `v${agent.version}`, mono: true, copy: false },
    { label: 'Enrolled', value: dateTime(agent.created_at), shown: dateTime(agent.created_at), mono: true, copy: false },
    { label: 'Last beat', value: dateTime(agent.last_heartbeat), shown: dateTime(agent.last_heartbeat), mono: true, copy: false },
  ]

  const detections = incidents
    .filter((incident) => incident.closed_at == null)
    .flatMap((incident) => {
      const detection = detectionOf(incident)
      return detection ? [{ incident, detection }] : []
    })
    .sort((a, b) => a.incident.opened_at - b.incident.opened_at)
  const ordered = incidents
    .filter((incident) => !incident.incident_type.startsWith('detection.'))
    .sort(
      (a, b) =>
        Number(a.closed_at != null) - Number(b.closed_at != null) ||
        Number(isGrave(b.incident_type)) - Number(isGrave(a.incident_type)) ||
        b.opened_at - a.opened_at,
    )

  return (
    <div className="flex min-h-full flex-col">
      <div className="flex h-8 items-center gap-1 pr-9">
        <h2 className="min-w-0 truncate font-mono text-xl font-medium tracking-tight">{agent.hostname}</h2>
        <CopyButton value={agent.hostname} label="Copy hostname" />
      </div>
      <div className="mt-2 flex items-center gap-3">
        <StateChip state={state}>{STATE_LABEL[state]}</StateChip>
        <span className="font-mono text-xs text-muted">beat {ago(agent.last_heartbeat, now)} ago</span>
      </div>

      {ordered.slice(0, 6).map((incident) => (
        <IncidentCard key={incident.id} incident={incident} now={now} />
      ))}

      {detections.length > 0 ? (
        <>
          <SectionTitle className="mb-2 mt-5">Findings</SectionTitle>
          {detections.map(({ incident, detection }) => (
            <div key={incident.id} data-finding={detection.rule} className="mb-1.5 rounded-xl border border-line bg-row transition-colors hover:border-line-hover">
              <div className="flex min-h-[48px] items-center gap-1 pr-1.5">
                <button
                  type="button"
                  onClick={() => (detection.autostart === null ? onProcess(detection.processKey) : onAutostart(detection.subject ?? ''))}
                  className="flex min-w-0 flex-1 px-3 py-2 text-left"
                >
                  <FindingLine
                    title={detection.title}
                    technique={detection.technique}
                    high
                    meta={`${detection.autostart === null ? baseName(detection.image) : (detection.subject ?? detection.autostart)} · ${clock(incident.opened_at)}`}
                  />
                </button>
                <CloseIncident incident={incident} />
              </div>
              <FindingProof agentId={agent.id} finding={detection} className="pb-2.5 pl-[30px] pr-3" />
            </div>
          ))}
        </>
      ) : null}

      <dl className="mt-4 grid grid-cols-[76px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-[13px]">
        {facts.map((fact) => (
          <div key={fact.label} className="contents">
            <dt className="text-muted">{fact.label}</dt>
            <dd className={cn('group flex min-w-0 items-center gap-1', fact.mono && 'font-mono text-xs')}>
              <span className="truncate">{fact.shown}</span>
              {fact.copy ? (
                <CopyButton value={fact.value} label={`Copy ${fact.label}`} className="h-5 w-5 opacity-0 group-hover:opacity-100" />
              ) : null}
            </dd>
          </div>
        ))}
      </dl>

      <div className="@container mt-auto pt-5">
        <div className="grid auto-cols-fr grid-flow-col gap-2">
          <Link to="/events" search={{ agent: agent.id }} aria-label="Events" title="Events" className="min-w-0">
            <Button tabIndex={-1} className={action}>
              <Rows3 size={16} strokeWidth={1.5} className="shrink-0" aria-hidden />
              <span className={actionLabel}>Events</span>
            </Button>
          </Link>
          {isAdmin(session) ? (
            <Button onClick={() => setUpgradeOpen((open) => !open)} aria-expanded={upgradeOpen} aria-label="Upgrade" title="Upgrade" className={action}>
              <ArrowUpCircle size={16} strokeWidth={1.5} className="shrink-0" aria-hidden />
              <span className={actionLabel}>Upgrade</span>
            </Button>
          ) : null}
        </div>
      </div>

      {upgradeOpen ? (
        <form
          className="mt-2 flex gap-2"
          onSubmit={(event) => {
            event.preventDefault()
            if (target.trim()) upgrade.mutate(target.trim())
          }}
        >
          <input
            autoFocus
            value={target}
            onChange={(event) => setTarget(event.target.value)}
            placeholder="target version"
            aria-label="Target version"
            className={`${inputClass} font-mono`}
          />
          <Button type="submit" variant="primary" disabled={upgrade.isPending || !target.trim()}>
            Send
          </Button>
        </form>
      ) : null}
      {upgrade.error ? (
        <div role="alert" className="mt-2 text-xs text-alert-soft">
          {upgrade.error instanceof ApiError ? upgrade.error.message : 'Upgrade failed'}
        </div>
      ) : null}
      {lastUpgrade ? (
        <div className="mt-2 font-mono text-[11px] text-muted">
          upgrade → v{lastUpgrade.target_version} · {lastUpgrade.status} · {ago(lastUpgrade.created_at, now)}
        </div>
      ) : null}
    </div>
  )
}
