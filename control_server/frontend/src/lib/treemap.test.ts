import { describe, expect, it } from 'vitest'
import { squarify } from './treemap'

const entries = (values: number[]) => values.map((value, index) => ({ item: `t${index}`, value }))

describe('squarify', () => {
  it('fills the whole area with tiles in proportion to their value', () => {
    const tiles = squarify(entries([6, 6, 4, 3, 2, 2, 1]), 600, 400)
    const area = (item: string) => {
      const tile = tiles.find((candidate) => candidate.item === item)!
      return tile.width * tile.height
    }
    expect(tiles).toHaveLength(7)
    expect(tiles.reduce((sum, tile) => sum + tile.width * tile.height, 0)).toBeCloseTo(240000, 3)
    expect(area('t0') / area('t6')).toBeCloseTo(6, 6)
    expect(area('t2') / area('t4')).toBeCloseTo(2, 6)
  })

  it('keeps every tile inside the box without overlap', () => {
    const tiles = squarify(entries([9, 7, 5, 5, 3, 2, 2, 1, 1, 1]), 500, 300)
    for (const tile of tiles) {
      expect(tile.x).toBeGreaterThanOrEqual(-1e-9)
      expect(tile.y).toBeGreaterThanOrEqual(-1e-9)
      expect(tile.x + tile.width).toBeLessThanOrEqual(500 + 1e-6)
      expect(tile.y + tile.height).toBeLessThanOrEqual(300 + 1e-6)
    }
    for (const a of tiles) {
      for (const b of tiles) {
        if (a === b) continue
        const apart = a.x + a.width <= b.x + 1e-6 || b.x + b.width <= a.x + 1e-6 || a.y + a.height <= b.y + 1e-6 || b.y + b.height <= a.y + 1e-6
        expect(apart).toBe(true)
      }
    }
  })

  it('keeps tiles close to square', () => {
    const tiles = squarify(entries([6, 6, 4, 3, 2, 2, 1]), 600, 400)
    const ratios = tiles.map((tile) => Math.max(tile.width / tile.height, tile.height / tile.width))
    expect(Math.max(...ratios)).toBeLessThan(3)
  })

  it('puts the largest value first and leaves out what has no value', () => {
    const tiles = squarify([{ item: 'small', value: 1 }, { item: 'none', value: 0 }, { item: 'big', value: 5 }], 300, 200)
    expect(tiles.map((tile) => tile.item)).toEqual(['big', 'small'])
    expect(tiles[0]).toMatchObject({ x: 0, y: 0 })
  })

  it('returns nothing for an empty box or no values', () => {
    expect(squarify(entries([1, 2]), 0, 100)).toEqual([])
    expect(squarify(entries([0, 0]), 100, 100)).toEqual([])
  })
})
