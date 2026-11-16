import { describe, expect, it } from 'vitest'
import type { EventHistogram } from './api'
import { CATEGORIES } from './events'
import { bucketsOf, buildLanes, countIn, laneWindow, periodOf } from './lanes'

const histogram: EventHistogram = {
  from: 6000,
  bucket_seconds: 60,
  buckets: 4,
  series: [
    { event_type: 'heartbeat', counts: [10, 10, 9, 10] },
    { event_type: 'process', counts: [0, 4, 0, 0] },
    { event_type: 'network', counts: [0, 2, 1, 0] },
    { event_type: 'incident_opened', counts: [0, 0, 1, 0] },
    { event_type: 'something_new', counts: [5, 0, 0, 0] },
  ],
}

describe('laneWindow', () => {
  it('ends on the bucket that holds now, so a refetch a few seconds later asks for the same period', () => {
    expect(laneWindow('1h', 7230)).toEqual([3660, 7260])
    expect(laneWindow('1h', 7259)).toEqual([3660, 7260])
    expect(laneWindow('1h', 7260)).toEqual([3720, 7320])
    expect(laneWindow('24h', 100_000)).toEqual([100_800 - 86_400, 100_800])
  })
})

describe('buildLanes', () => {
  const lanes = buildLanes(histogram, CATEGORIES)
  const lane = (id: string) => lanes.find((item) => item.id === id)!

  it('adds the types of a category together, bucket by bucket', () => {
    expect(lane('telemetry')).toMatchObject({ counts: [0, 6, 1, 0], total: 7, peak: 6 })
    expect(lane('heartbeat')).toMatchObject({ total: 39, peak: 10 })
    expect(lane('incident').counts).toEqual([0, 0, 1, 0])
  })

  it('keeps a lane for a category with nothing in the period', () => {
    expect(lane('upgrade')).toMatchObject({ counts: [0, 0, 0, 0], total: 0, peak: 1 })
    expect(lanes.map((item) => item.id)).toEqual(CATEGORIES.map((category) => category.id))
  })

  it('draws empty lanes before the counts arrive', () => {
    expect(buildLanes(undefined, CATEGORIES)[0]!.counts).toHaveLength(60)
  })
})

describe('picking a period on the lanes', () => {
  it('turns a drag between two buckets into whole buckets, whichever way it went', () => {
    expect(periodOf(histogram, 1, 2)).toEqual([6060, 6180])
    expect(periodOf(histogram, 2, 1)).toEqual([6060, 6180])
    expect(periodOf(histogram, 3, 3)).toEqual([6180, 6240])
  })

  it('finds the buckets a period covers and counts what a lane has in them', () => {
    expect(bucketsOf(histogram, [6060, 6180])).toEqual([1, 2])
    expect(bucketsOf(histogram, [0, 99_999])).toEqual([0, 3])
    const telemetry = buildLanes(histogram, CATEGORIES).find((item) => item.id === 'telemetry')!
    expect(countIn(telemetry, 1, 2)).toBe(7)
    expect(countIn(telemetry, 3, 3)).toBe(0)
  })
})
