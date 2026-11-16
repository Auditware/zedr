import type { Period } from './activity'
import type { EventHistogram } from './api'
import { CATEGORIES, type Category } from './events'
import { dateTime } from './format'

export type Range = '1h' | '24h' | '7d'
export type Lane = { id: Category; label: string; color: string; counts: number[]; total: number; peak: number }

export const LANE_BUCKETS = 60
export const RANGES: { id: Range; label: string; seconds: number }[] = [
  { id: '1h', label: '1h', seconds: 3600 },
  { id: '24h', label: '24h', seconds: 86_400 },
  { id: '7d', label: '7d', seconds: 604_800 },
]

export function laneWindow(range: Range, now: number): Period {
  const seconds = RANGES.find((option) => option.id === range)!.seconds
  const step = seconds / LANE_BUCKETS
  const to = (Math.floor(now / step) + 1) * step
  return [to - seconds, to]
}

export function buildLanes(histogram: EventHistogram | undefined, categories: readonly (typeof CATEGORIES)[number][]): Lane[] {
  const buckets = histogram?.buckets ?? LANE_BUCKETS
  return categories.map((category) => {
    const counts = new Array<number>(buckets).fill(0)
    for (const series of histogram?.series ?? []) {
      if (!category.types.includes(series.event_type)) continue
      series.counts.forEach((count, index) => {
        counts[index] = (counts[index] ?? 0) + count
      })
    }
    return {
      id: category.id,
      label: category.label,
      color: category.color,
      counts,
      total: counts.reduce((sum, count) => sum + count, 0),
      peak: Math.max(1, ...counts),
    }
  })
}

export function bucketsOf(histogram: EventHistogram, [from, to]: Period): [number, number] {
  const first = Math.max(0, Math.floor((from - histogram.from) / histogram.bucket_seconds))
  const last = Math.min(histogram.buckets - 1, Math.ceil((to - histogram.from) / histogram.bucket_seconds) - 1)
  return [first, last]
}

export function periodOf(histogram: EventHistogram, first: number, last: number): Period {
  const low = Math.min(first, last)
  const high = Math.max(first, last)
  return [histogram.from + low * histogram.bucket_seconds, histogram.from + (high + 1) * histogram.bucket_seconds]
}

export function countIn(lane: Lane, first: number, last: number): number {
  let sum = 0
  for (let index = first; index <= last; index++) sum += lane.counts[index] ?? 0
  return sum
}

export function tickLabel(time: number, seconds: number): string {
  const stamp = dateTime(time)
  return seconds > 86_400 ? stamp.slice(5, 16) : stamp.slice(11, 16)
}
