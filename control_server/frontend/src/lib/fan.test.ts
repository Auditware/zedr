import { describe, expect, it } from 'vitest'
import { fan, strandPath } from './fan'

describe('fan', () => {
  it('gives each value a strand as thick as its share, leaving the source as one unbroken bar', () => {
    const { strands, height } = fan([150, 30, 20], 100, 20, 8)
    const thick = strands.map((strand) => strand.from[1] - strand.from[0])
    expect(thick.map((value) => Math.round(value))).toEqual([75, 15, 10])
    expect(strands[0]!.from[1]).toBeCloseTo(strands[1]!.from[0])
    expect(strands[1]!.from[1]).toBeCloseTo(strands[2]!.from[0])
    expect(height).toBe(75 + 20 + 20 + 16)
  })

  it('keeps room for a label beside a thin strand and centres the strand in it', () => {
    const { strands } = fan([190, 4], 100, 22, 6)
    const [, thin] = strands
    expect(thin!.slot[1] - thin!.slot[0]).toBe(22)
    expect((thin!.to[0] + thin!.to[1]) / 2).toBeCloseTo((thin!.slot[0] + thin!.slot[1]) / 2)
    expect(thin!.to[1] - thin!.to[0]).toBeCloseTo((4 / 194) * 100)
  })

  it('draws a hairline for one in thousands and nothing for none', () => {
    const { strands } = fan([5000, 1, 0], 100, 20, 8)
    expect(strands[1]!.to[1] - strands[1]!.to[0]).toBe(1.5)
    expect(strands[2]!.to[1] - strands[2]!.to[0]).toBe(0)
    expect(strands[2]!.slot[1] - strands[2]!.slot[0]).toBe(20)
  })

  it('still lays out the labels when nothing has been issued', () => {
    const { strands, height } = fan([0, 0], 100, 20, 8)
    expect(strands.map((strand) => strand.slot)).toEqual([
      [0, 20],
      [28, 48],
    ])
    expect(height).toBe(48)
  })
})

describe('strandPath', () => {
  it('closes a band from the source edge to the outcome edge', () => {
    expect(strandPath({ from: [10, 20], to: [40, 50], slot: [35, 55] }, 0, 100)).toBe('M0 10 C50 10 50 40 100 40 L100 50 C50 50 50 20 0 20 Z')
  })
})
