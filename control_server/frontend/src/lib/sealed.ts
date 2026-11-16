import type { SealedRow } from './api'
import { eventData, summarize } from './events'

export const SEALED_PAGE = 200
const TAG_BYTES = 16

export function sealedSize(ciphertextBytes: number): string {
  const bucket = Math.max(0, ciphertextBytes - TAG_BYTES)
  if (bucket < 1024) return `${bucket} B`
  const [value, unit] = bucket < 1024 * 1024 ? [bucket / 1024, 'KB'] : [bucket / (1024 * 1024), 'MB']
  return `${Number.isInteger(value) ? value : value.toFixed(1)} ${unit}`
}

export function openedDetail(row: Pick<SealedRow, 'event_type' | 'data'>): string {
  if (!row.event_type || !row.data) return ''
  const event = { event_type: row.event_type, data: row.data }
  if (row.event_type !== 'process') return summarize(event)
  const data = eventData(event)
  const command = Array.isArray(data.command_line) ? data.command_line.filter((part) => typeof part === 'string').join(' ') : ''
  return data.action === 'Terminate' ? `ended, pid ${String(data.pid)}` : command || summarize(event)
}
