import { describe, expect, it } from 'vitest'
import { wheelIntent, zoomAt } from './pan-zoom'

describe('zoomAt', () => {
  it('keeps the point under the cursor still', () => {
    const before = { scale: 1, x: 40, y: -20 }
    const cursor = { x: 300, y: 200 }
    const worldBefore = { x: (cursor.x - before.x) / before.scale, y: (cursor.y - before.y) / before.scale }
    const after = zoomAt(before, cursor.x, cursor.y, 1.6, 0.1, 8)
    expect((cursor.x - after.x) / after.scale).toBeCloseTo(worldBefore.x)
    expect((cursor.y - after.y) / after.scale).toBeCloseTo(worldBefore.y)
  })

  it('stops at the scale limits', () => {
    expect(zoomAt({ scale: 1, x: 0, y: 0 }, 0, 0, 1000, 0.1, 8).scale).toBe(8)
    expect(zoomAt({ scale: 1, x: 0, y: 0 }, 0, 0, 0.0001, 0.1, 8).scale).toBe(0.1)
  })
})

describe('wheelIntent', () => {
  const plain = { deltaX: 0, deltaY: 0, deltaMode: 0, ctrlKey: false, metaKey: false }

  it('pans on a two-finger scroll', () => {
    expect(wheelIntent({ ...plain, deltaX: 12, deltaY: -30 })).toEqual({ kind: 'pan', dx: -12, dy: 30 })
  })

  it('zooms on a pinch, which arrives as a wheel with the control key', () => {
    const zoomIn = wheelIntent({ ...plain, deltaY: -8, ctrlKey: true })
    const zoomOut = wheelIntent({ ...plain, deltaY: 8, ctrlKey: true })
    expect(zoomIn.kind === 'zoom' && zoomIn.factor).toBeGreaterThan(1)
    expect(zoomOut.kind === 'zoom' && zoomOut.factor).toBeLessThan(1)
  })

  it('tames a mouse wheel notch so one click is not a jump', () => {
    const notch = wheelIntent({ ...plain, deltaY: -120, metaKey: true })
    expect(notch.kind === 'zoom' && notch.factor).toBeLessThan(1.7)
  })
})
