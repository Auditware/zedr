import type { ApiEvent, AuditEntry } from './api'
import { tone } from '@/lib/palette'
import { baseName } from './images'

export type Category = 'heartbeat' | 'lifecycle' | 'incident' | 'upgrade' | 'identity' | 'telemetry' | 'audit'

export const CATEGORIES: { id: Category; label: string; color: string; types: string[] }[] = [
  { id: 'heartbeat', label: 'Heartbeat', color: tone('faint'), types: ['heartbeat'] },
  { id: 'incident', label: 'Incident', color: tone('alert'), types: ['incident_opened', 'incident_closed', 'detection'] },
  { id: 'lifecycle', label: 'Lifecycle', color: tone('soft'), types: ['install', 'agent_stopping'] },
  { id: 'identity', label: 'Identity', color: tone('warn'), types: ['enrollment_rejected', 'identity_rotated'] },
  { id: 'upgrade', label: 'Upgrade', color: tone('mauve'), types: ['upgrade'] },
  { id: 'telemetry', label: 'Telemetry', color: tone('sage'), types: ['process', 'file', 'network', 'persistence', 'package'] },
  { id: 'audit', label: 'Audit', color: tone('accent'), types: ['audit'] },
]

const BY_TYPE = new Map<string, (typeof CATEGORIES)[number]>()
for (const category of CATEGORIES) {
  for (const type of category.types) BY_TYPE.set(type, category)
}

export function categoryOf(eventType: string): (typeof CATEGORIES)[number] {
  return BY_TYPE.get(eventType) ?? CATEGORIES[2]!
}

export function typesOf(categories: Iterable<Category>): string[] {
  const wanted = new Set(categories)
  return CATEGORIES.filter((category) => wanted.has(category.id)).flatMap((category) => category.types)
}

export type EventData = Record<string, unknown>

export function eventData(event: Pick<ApiEvent, 'data'>): EventData {
  try {
    const parsed: unknown = JSON.parse(event.data)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as EventData) : {}
  } catch {
    return {}
  }
}

function text(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return ''
}

export function summarize(event: Pick<ApiEvent, 'event_type' | 'data'>): string {
  const data = eventData(event)
  switch (event.event_type) {
    case 'heartbeat':
      return ''
    case 'agent_stopping':
      return text(data.reason)
    case 'incident_opened':
    case 'incident_closed':
      return text(data.incident_type)
    case 'install':
      return [text(data.status), text(data.hostname), text(data.version)].filter(Boolean).join(' ')
    case 'enrollment_rejected':
      return text(data.reason)
    case 'identity_rotated':
      return text(data.hostname) || 'pinned key replaced'
    case 'upgrade':
      return [text(data.from_version), text(data.to_version) || text(data.target_version)].filter(Boolean).join(' → ') +
        (text(data.status) ? ` ${text(data.status)}` : '')
    case 'process':
      return text(data.executable_path)
    case 'file':
      return `${text(data.action)} ${text(data.path)}`.trim()
    case 'network':
      return `${text(data.action)} ${text(data.dest_ip)}:${text(data.dest_port)}`.trim()
    case 'persistence':
      return `${text(data.action)} ${text(data.kind)} ${text(data.name)}`.trim()
    case 'package':
      return `${text(data.action)} ${text(data.name)} ${text(data.version)}`.trim()
    case 'detection':
      return `${text(data.title)} · ${baseName(text(data.image))}`
    case 'audit':
      return text(data.target) ? `${text(data.action)} → ${text(data.target)}` : text(data.action)
    default:
      return ''
  }
}

const INCIDENT_LABEL: Record<string, string> = {
  silence: 'Silent while others report',
  service_stopped: 'Service stopped, system running',
  replay: 'Signed request replayed',
  identity_conflict: 'Key change without enrollment',
}

type IncidentLike = { incident_type: string; evidence: string }

export type Detection = { title: string; technique: string; image: string; processKey: string; autostart: string | null }

export function detectionOf(incident: IncidentLike): Detection | null {
  if (!incident.incident_type.startsWith('detection.')) return null
  const evidence = eventData({ data: incident.evidence })
  return {
    title: text(evidence.title),
    technique: text(evidence.technique),
    image: text(evidence.image),
    processKey: `${text(evidence.pid)}@${text(evidence.started_at)}`,
    autostart: typeof evidence.autostart === 'string' ? text(evidence.subject) : null,
  }
}

export function incidentTitle(incident: IncidentLike): string {
  return detectionOf(incident)?.title ?? INCIDENT_LABEL[incident.incident_type] ?? incident.incident_type
}

export function auditTone(action: string): string {
  if (action.includes('failed') || action.includes('rejected') || action.includes('delete') || action.includes('disable')) return tone('alert')
  if (action.startsWith('signing_key') || action.startsWith('mfa') || action.startsWith('user.') || action.startsWith('view.')) return tone('warn')
  if (action.startsWith('login')) return tone('node')
  return tone('soft')
}

export function auditEvent(entry: AuditEntry): ApiEvent {
  return {
    id: `audit:${entry.seq}`,
    agent_id: null,
    event_type: 'audit',
    timestamp: entry.timestamp,
    received_at: entry.timestamp,
    data: JSON.stringify({
      seq: entry.seq,
      actor: entry.actor,
      action: entry.action,
      target: entry.target,
      detail: eventData({ data: entry.detail }),
      hash: entry.hash,
      prev_hash: entry.prev_hash,
    }),
  }
}
