import type { ReleaseView, WindowView } from './api'

export type Level = 'high' | 'medium'
export type ProofStatus = 'pending' | 'verified' | 'mismatch' | 'none'

export type Finding = {
  rule: string
  title: string
  technique: string
  level: Level
  processKey: string
  image: string
  autostart: string | null
  subject: string | null
  trigger: number | null
  window: number | null
  proven: boolean
}

function text(value: unknown): string {
  if (typeof value === 'string') return value
  return typeof value === 'number' ? String(value) : ''
}

function index(value: unknown): number | null {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : null
}

export function findingOf(evidence: Record<string, unknown>): Finding | null {
  if (typeof evidence.rule !== 'string' || typeof evidence.title !== 'string') return null
  return {
    rule: evidence.rule,
    title: evidence.title,
    technique: text(evidence.technique),
    level: evidence.level === 'high' ? 'high' : 'medium',
    processKey: `${text(evidence.pid)}@${text(evidence.started_at)}`,
    image: text(evidence.image),
    autostart: typeof evidence.autostart === 'string' ? evidence.autostart : null,
    subject: typeof evidence.subject === 'string' ? evidence.subject : null,
    trigger: index(evidence.trigger),
    window: index(evidence.window),
    proven: evidence.proof === 'verified',
  }
}

export function findingsByProcess(findings: Finding[]): Map<string, Finding[]> {
  const byProcess = new Map<string, Finding[]>()
  for (const finding of findings) {
    if (finding.autostart !== null) continue
    const known = byProcess.get(finding.processKey)
    if (!known) byProcess.set(finding.processKey, [finding])
    else if (!known.some((other) => other.rule === finding.rule)) known.push(finding)
  }
  for (const known of byProcess.values()) known.sort((a, b) => Number(b.level === 'high') - Number(a.level === 'high'))
  return byProcess
}

export function releaseOf(finding: Pick<Finding, 'rule' | 'trigger'>, window: WindowView | undefined): ReleaseView | undefined {
  return window?.releases.find((release) => release.rule === finding.rule && release.trigger === finding.trigger)
}

export function proofOf(finding: Finding, window: WindowView | undefined): ProofStatus {
  if (finding.proven || releaseOf(finding, window)?.proven) return 'verified'
  if (window?.proof === 'none' || window?.proof === 'mismatch') return window.proof
  return 'pending'
}
