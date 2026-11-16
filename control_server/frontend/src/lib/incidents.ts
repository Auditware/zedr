import { indices } from './chain'
import { dateTime, shortHash, span } from './format'

export type IncidentInfo = { title: string; said: string; grave?: boolean }

export const INCIDENTS: Record<string, IncidentInfo> = {
  silence: { title: 'Silent while others report', said: 'No heartbeat arrived from this endpoint while the rest of the fleet kept reporting.' },
  service_stopped: { title: 'Service stopped, system running', said: 'The agent said its service was being stopped while the system stayed up.' },
  replay: { title: 'Signed request replayed', said: 'A signed request arrived a second time, or with a sequence number the server had already passed.' },
  identity_conflict: { title: 'Key change without enrollment', said: 'A registration came with another key than the one pinned for this endpoint.' },
  chain_gap: {
    title: 'Events missing from the chain',
    said: 'The endpoint sealed a window that says events before it are missing: its sensor lost them, one was too large to seal, or its ledger started over.',
  },
  chain_fork: {
    title: 'Window that does not continue the chain',
    said: 'The endpoint sent a window that does not follow the last one the server holds. The server kept its copy and answered with where it stands.',
  },
  window_malformed: { title: 'Malformed window', said: 'The endpoint sent a window that does not match its own header. Nothing of it was stored.' },
  release_invalid: {
    title: 'Release that opens nothing',
    said: 'A release named events its rule does not read, or secrets that do not open what was committed. No event was opened by it.',
  },
  proof_invalid: {
    title: 'Proof that does not hold',
    said: 'The endpoint sent a proof that does not verify against an accepted rule program, or that contradicts the windows the server holds.',
    grave: true,
  },
  proof_overdue: { title: 'Proof overdue', said: 'Windows of this endpoint have waited for a proof longer than the deadline allows.' },
  proving_stopped: {
    title: 'Stopped proving',
    said: 'The endpoint proved its windows and now sends them marked as not proven: its prover is gone or was switched off.',
  },
  match_not_released: {
    title: 'Proved a match it did not report',
    said: 'The proof shows a rule fired on this endpoint, and the endpoint never released the match. Its events stay sealed: the server was not given the secrets that open them.',
    grave: true,
  },
  release_not_proven: {
    title: 'Released a match its proof does not tell',
    said: 'The endpoint opened events for a match that the proof of the same windows does not contain.',
  },
}

export function isGrave(incidentType: string): boolean {
  return INCIDENTS[incidentType]?.grave === true
}

export type EvidenceRow = { label: string; value: string; mono?: boolean }

type Evidence = Record<string, unknown>

function parse(evidence: string): Evidence {
  try {
    const parsed: unknown = JSON.parse(evidence)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed) ? (parsed as Evidence) : {}
  } catch {
    return {}
  }
}

function text(value: unknown): string {
  if (typeof value === 'string') return value
  if (typeof value === 'number' || typeof value === 'boolean') return String(value)
  return value == null ? '' : JSON.stringify(value)
}

function number(value: unknown): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : 0
}

function list(value: unknown): number[] {
  return Array.isArray(value) ? value.filter((item): item is number => typeof item === 'number') : []
}

function windows(evidence: Evidence): string {
  const first = number(evidence.first_window)
  const last = number(evidence.last_window)
  return `${first === last ? `window ${first}` : `windows ${first} to ${last}`}, epoch ${number(evidence.epoch)}`
}

function claims(value: unknown, label: string, ruleTitle: (rule: string) => string): EvidenceRow[] {
  if (!Array.isArray(value)) return []
  return value.flatMap((claim: unknown) => {
    if (!claim || typeof claim !== 'object') return []
    const told = claim as Evidence
    const context = list(told.context)
    const read = context.length > 0 ? `, read ${indices(context)}` : ''
    const process = number(told.pid) > 0 ? `, process ${number(told.pid)}` : ''
    return [{ label, value: `${ruleTitle(text(told.rule))}: event #${number(told.trigger)}${read}${process}` }]
  })
}

function plain(evidence: Evidence): EvidenceRow[] {
  return Object.entries(evidence)
    .filter(([, value]) => value != null && value !== '')
    .map(([key, value]) => ({ label: key.replaceAll('_', ' '), value: text(value), mono: typeof value !== 'string' || !value.includes(' ') }))
}

export function evidenceRows(incident: { incident_type: string; evidence: string }, ruleTitle: (rule: string) => string): EvidenceRow[] {
  const evidence = parse(incident.evidence)
  const why: EvidenceRow[] = typeof evidence.reason === 'string' ? [{ label: 'why', value: evidence.reason }] : []
  if (incident.incident_type.startsWith('detection.')) {
    const told: [string, unknown][] = [['image', evidence.image], ['command', evidence.command], ['parent', evidence.parent], [typeof evidence.autostart === 'string' ? 'item' : 'touched', evidence.subject]]
    return told.filter(([, value]) => typeof value === 'string' && value !== '').map(([label, value]) => ({ label, value: text(value), mono: true }))
  }
  switch (incident.incident_type) {
    case 'proving_stopped':
      return [{ label: 'window', value: `${number(evidence.window)}, epoch ${number(evidence.epoch)}`, mono: true }]
    case 'chain_gap':
      return [
        { label: 'window', value: `${number(evidence.window)}, epoch ${number(evidence.epoch)}`, mono: true },
        { label: 'missing', value: `events before #${number(evidence.first_index)}`, mono: true },
      ]
    case 'chain_fork':
      return [
        ...why,
        {
          label: 'sent',
          value: `window ${number(evidence.window)}, epoch ${number(evidence.epoch)}, from event #${number(evidence.first_index)}${evidence.fresh === true ? ', opening an epoch' : ''}`,
          mono: true,
        },
        { label: 'follows', value: shortHash(text(evidence.prev_head)), mono: true },
        {
          label: 'server',
          value: `window ${number(evidence.stored_next_window)} next, epoch ${number(evidence.stored_epoch)}, event #${number(evidence.stored_next_index)} next`,
          mono: true,
        },
        { label: 'head', value: shortHash(text(evidence.stored_head)), mono: true },
      ]
    case 'window_malformed':
      return [
        ...why,
        { label: 'window', value: `${number(evidence.window)}, epoch ${number(evidence.epoch)}`, mono: true },
        { label: 'claims', value: `${number(evidence.count)} events from #${number(evidence.first_index)}`, mono: true },
        { label: 'carried', value: `${number(evidence.events)} events`, mono: true },
      ]
    case 'release_invalid':
      return [
        ...why,
        { label: 'rule', value: ruleTitle(text(evidence.rule)) },
        { label: 'window', value: String(number(evidence.window)), mono: true },
        { label: 'named', value: `event #${number(evidence.trigger)}${list(evidence.context).length > 0 ? `, read ${indices(list(evidence.context))}` : ''}`, mono: true },
        { label: 'secrets', value: indices(list(evidence.opened)) || 'none', mono: true },
      ]
    case 'proof_invalid':
      return why
    case 'proof_overdue':
      return [
        { label: 'waiting', value: `${number(evidence.windows)} ${number(evidence.windows) === 1 ? 'window' : 'windows'}, from window ${number(evidence.window)}`, mono: true },
        { label: 'since', value: `${dateTime(number(evidence.received_at))}, ${span(number(evidence.waiting_secs))} when raised`, mono: true },
      ]
    case 'match_not_released':
      return [{ label: 'proof', value: windows(evidence), mono: true }, ...claims(evidence.matches, 'match', ruleTitle)]
    case 'release_not_proven':
      return [{ label: 'proof', value: windows(evidence), mono: true }, ...claims(evidence.releases, 'release', ruleTitle)]
    default:
      return plain(evidence)
  }
}
