import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Check } from 'lucide-react'
import { useState } from 'react'
import { JsonView } from '@/components/common/JsonView'
import { Tip } from '@/components/ui/bits'
import { api, type Incident } from '@/lib/api'
import { isAdmin, useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { incidentTitle } from '@/lib/events'
import { ago, span } from '@/lib/format'

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

export function IncidentCard({ incident, now }: { incident: Incident; now: number }) {
  const [open, setOpen] = useState(incident.closed_at == null)
  const closed = incident.closed_at != null
  return (
    <div
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
        </button>
        <CloseIncident incident={incident} className="mt-2" />
      </div>
      {open ? <JsonView value={incident.evidence} className="rounded-none border-t border-line/60 bg-transparent" /> : null}
    </div>
  )
}
