import { useQueries } from '@tanstack/react-query'
import { X } from 'lucide-react'
import { useState } from 'react'
import { Segmented } from '@/components/ui/segmented'
import { api, type Agent, type Incident } from '@/lib/api'
import { useNow } from '@/lib/queries'
import { Timeline, type Lane } from './Timeline'

type Range = '15m' | '1h' | '6h'
const RANGES: { id: Range; label: string; seconds: number }[] = [
  { id: '15m', label: '15m', seconds: 900 },
  { id: '1h', label: '1h', seconds: 3600 },
  { id: '6h', label: '6h', seconds: 21600 },
]

type Props = {
  title: string
  meta: string
  agents: Agent[]
  incidents: Incident[]
  onPick: (id: string) => void
  onClose: () => void
}

export function Dock({ title, meta, agents, incidents, onPick, onClose }: Props) {
  const now = useNow(5000)
  const [range, setRange] = useState<Range>('1h')
  const seconds = RANGES.find((option) => option.id === range)!.seconds

  const results = useQueries({
    queries: agents.map((agent) => ({
      queryKey: ['agent-events', agent.id, 500],
      queryFn: () => api.events({ agentId: agent.id, limit: 500 }),
      refetchInterval: 20_000,
    })),
  })

  const lanes: Lane[] = agents.map((agent, index) => ({
    id: agent.id,
    label: agent.hostname,
    events: results[index]?.data ?? [],
    incidents: incidents.filter((incident) => incident.agent_id === agent.id),
  }))

  return (
    <div className="flex h-full min-h-0 flex-col gap-2 rounded-card border border-line bg-surface px-4 pb-2.5 pt-3">
      <div className="flex shrink-0 items-center gap-3">
        <span className="truncate font-mono text-sm font-medium">{title}</span>
        <span className="truncate font-mono text-xs text-muted">{meta}</span>
        <Segmented label="Range" value={range} options={RANGES} onChange={setRange} className="ml-auto" />
        <button type="button" onClick={onClose} aria-label="Close timeline" className="rounded-md p-1.5 text-muted hover:bg-raised hover:text-text">
          <X size={16} strokeWidth={1.5} aria-hidden />
        </button>
      </div>
      <Timeline lanes={lanes} seconds={seconds} now={now} onPick={onPick} />
    </div>
  )
}
