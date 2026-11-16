import type { ProofStatus } from './findings'

export const PROOF_ORDER: ProofStatus[] = ['verified', 'pending', 'mismatch', 'none']

export const PROOF_LABEL: Record<ProofStatus, string> = {
  verified: 'verified',
  pending: 'pending',
  mismatch: 'mismatch',
  none: 'no prover',
}

export const PROOF_CHIP: Record<ProofStatus, { label: string; tone: 'sage' | 'warn' | 'alert' | 'steel' }> = {
  verified: { label: 'proven', tone: 'sage' },
  pending: { label: 'proof pending', tone: 'warn' },
  mismatch: { label: 'proof mismatch', tone: 'alert' },
  none: { label: 'no prover', tone: 'steel' },
}

export const PROOF_SAID: Record<ProofStatus, string> = {
  verified: 'A proof shows the rules ran over every event of this window and fired exactly what the endpoint released.',
  pending: 'The endpoint has not proven this window yet.',
  mismatch: 'The proof of this window tells other matches than the endpoint released.',
  none: 'This endpoint has no prover. Its windows are sealed and chained, and nothing proves the rules ran over them.',
}

export const PROOF_FILL: Record<ProofStatus, string> = {
  verified: 'bg-sage',
  pending: 'bg-warn',
  mismatch: 'bg-alert',
  none: 'bg-steel/45',
}

export function proofStatus(value: string): ProofStatus {
  return PROOF_ORDER.find((status) => status === value) ?? 'pending'
}

export function proofCounts(windows: { proof: string }[]): Record<ProofStatus, number> {
  const counts: Record<ProofStatus, number> = { verified: 0, pending: 0, mismatch: 0, none: 0 }
  for (const window of windows) counts[proofStatus(window.proof)] += 1
  return counts
}

export function count(value: number): string {
  return value.toLocaleString('en-US')
}

export function share(part: number, whole: number): string {
  if (whole <= 0 || part <= 0) return '0%'
  const percent = (part / whole) * 100
  if (percent < 0.01) return 'under 0.01%'
  return `${percent >= 10 ? Math.round(percent) : percent.toFixed(percent >= 1 ? 1 : 2)}%`
}

export function eventRange(first: number, events: number): string {
  if (events === 0) return 'no events'
  return events === 1 ? `event #${first}` : `events #${first} to #${first + events - 1}`
}

export function indices(list: number[]): string {
  return list.map((index) => `#${index}`).join(', ')
}
