import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Check } from 'lucide-react'
import { useState } from 'react'
import { JsonView } from '@/components/common/JsonView'
import { FindingProof } from '@/components/common/Proof'
import { Chip, Tip } from '@/components/ui/bits'
import { api, type Incident } from '@/lib/api'
import { isAdmin, useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { detectionOf, incidentTitle } from '@/lib/events'
import { ago, span } from '@/lib/format'
import { evidenceRows, INCIDENTS, isGrave } from '@/lib/incidents'
import { useRuleset } from '@/lib/queries'

export function CloseIncident({ incident, className }: { incident: Incident; className?: string }) {
  const queryClient = useQueryClient()
  const admin = isAdmin(useSession((state) => state.session))
  const close = useMutation({
    mutationFn: () => api.closeIncident(incident.id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['incidents'] }),
  })
  if (!admin || incident.closed_at != null) return null
  return (
    <Tip label="Close incident">
      <button
        type="button"
        aria-label={`Close incident: ${incidentTitle(incident)}`}
        disabled={close.isPending}
        onClick={() => close.mutate()}
        className={cn('inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-md text-muted hover:bg-raised hover:text-text', className)}
      >
        <Check size={15} strokeWidth={1.75} aria-hidden />
      </button>
    </Tip>
  )
}

export function IncidentEvidence({ incident, raw, className }: { incident: Incident; raw?: boolean; className?: string }) {
  const { data: ruleset } = useRuleset()
  const finding = detectionOf(incident)
  const said = INCIDENTS[incident.incident_type]?.said
  const rows = evidenceRows(incident, (rule) => ruleset?.rules.find((known) => known.id === rule)?.title ?? rule)
  return (
    <div data-evidence={incident.incident_type} className={cn('flex flex-col gap-2 px-3.5 py-2.5', className)}>
      {said ? <p className="text-xs leading-relaxed text-soft">{said}</p> : null}
      {finding ? <FindingProof agentId={incident.agent_id} finding={finding} /> : null}
      {rows.length > 0 ? (
        <dl className="grid grid-cols-[64px_minmax(0,1fr)] gap-x-3 gap-y-1 text-xs">
          {rows.map((row, index) => (
            <div key={index} className="contents">
              <dt className="font-mono text-muted">{row.label}</dt>
              <dd className={cn('min-w-0 break-words text-text', row.mono && 'break-all font-mono')}>{row.value}</dd>
            </div>
          ))}
        </dl>
      ) : null}
      {raw ? <JsonView value={incident.evidence} className="bg-transparent p-0" /> : null}
    </div>
  )
}

export function IncidentCard({ incident, now }: { incident: Incident; now: number }) {
  const [open, setOpen] = useState(incident.closed_at == null)
  const closed = incident.closed_at != null
  return (
    <div
      data-incident={incident.incident_type}
      className={cn(
        'mt-2 overflow-hidden rounded-xl border',
        closed ? 'border-line bg-row' : 'border-alert-line bg-alert-surface',
      )}
    >
      <div className="flex items-start gap-1 pr-2">
        <button type="button" onClick={() => setOpen((value) => !value)} aria-expanded={open} className="block min-w-0 flex-1 px-3.5 py-2.5 text-left">
          <div className={cn('font-mono text-[11px]', closed ? 'text-muted' : 'text-alert-soft')}>
            {incident.incident_type} ·{' '}
            {closed ? `closed after ${span(incident.closed_at! - incident.opened_at)}` : `open ${ago(incident.opened_at, now)}`}
          </div>
          <div className={cn('font-display text-[15px] font-medium', closed ? 'text-soft' : 'text-accent-strong')}>{incidentTitle(incident)}</div>
          {isGrave(incident.incident_type) && !closed ? (
            <Chip tone="alert" className="mt-1.5 border border-alert-line">
              this endpoint cannot be trusted
            </Chip>
          ) : null}
        </button>
        <CloseIncident incident={incident} className="mt-2" />
      </div>
      {open ? <IncidentEvidence incident={incident} className="border-t border-line/60" /> : null}
    </div>
  )
}
