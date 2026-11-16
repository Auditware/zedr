import { describe, expect, it } from 'vitest'
import type { Agent } from './api'
import { fitView, groupKey, layoutMap, nodeState } from './map-layout'

function agent(overrides: Partial<Agent>): Agent {
  return {
    id: 'a',
    hostname: 'HOST',
    platform: 'windows',
    os_version: 'Windows 11 Pro 24H2',
    architecture: 'x86_64',
    version: '0.1.0',
    ip_address: '10.20.3.44',
    last_heartbeat: 0,
    created_at: 0,
    liveness_state: 'active',
    status: 'online',
    ...overrides,
  }
}

function fleet(sizes: number[]): { id: string; group: string }[] {
  return sizes.flatMap((size, group) =>
    Array.from({ length: size }, (_, index) => ({ id: `g${group}-${String(index).padStart(3, '0')}`, group: `group-${group}` })),
  )
}

describe('nodeState', () => {
  it('lets an open incident outrank the liveness state', () => {
    expect(nodeState(agent({ liveness_state: 'active' }), true)).toBe('incident')
    expect(nodeState(agent({ liveness_state: 'stopped' }), true)).toBe('incident')
  })

  it('passes known liveness states through and treats anything else as active', () => {
    expect(nodeState(agent({ liveness_state: 'suspect' }), false)).toBe('suspect')
    expect(nodeState(agent({ liveness_state: 'stopped' }), false)).toBe('stopped')
    expect(nodeState(agent({ liveness_state: 'something-new' }), false)).toBe('active')
  })
})

describe('groupKey', () => {
  it('groups by /24, system, version and liveness', () => {
    const subject = agent({})
    expect(groupKey(subject, 'active', 'subnet')).toBe('10.20.3.0/24')
    expect(groupKey(subject, 'active', 'os')).toBe('Windows 11 Pro 24H2')
    expect(groupKey(subject, 'active', 'version')).toBe('v0.1.0')
    expect(groupKey(subject, 'suspect', 'liveness')).toBe('Suspect')
  })

  it('keeps endpoints without an address together', () => {
    expect(groupKey(agent({ ip_address: null }), 'active', 'subnet')).toBe('no address')
  })
})

describe('layoutMap', () => {
  const nodes = fleet([60, 40, 34, 20, 16, 12])
  const viewport = { width: 1000, height: 760 }
  const layout = layoutMap(nodes, viewport)

  it('places every endpoint exactly once', () => {
    expect(layout.points.size).toBe(nodes.length)
    expect(layout.groups.map((group) => group.count)).toEqual([60, 40, 34, 20, 16, 12])
  })

  it('keeps each endpoint inside its own group', () => {
    for (const node of nodes) {
      const point = layout.points.get(node.id)!
      const group = layout.groups.find((candidate) => candidate.key === node.group)!
      expect(Math.hypot(point.x - group.x, point.y - group.y)).toBeLessThanOrEqual(group.r)
    }
  })

  it('never lets two groups touch', () => {
    for (const a of layout.groups) {
      for (const b of layout.groups) {
        if (a === b) continue
        expect(Math.hypot(a.x - b.x, a.y - b.y)).toBeGreaterThan(a.r + b.r)
      }
    }
  })

  it('is stable for the same input in any order', () => {
    const shuffled = [...nodes].reverse()
    const again = layoutMap(shuffled, viewport)
    for (const node of nodes) expect(again.points.get(node.id)).toEqual(layout.points.get(node.id))
  })

  it('follows the shape of the space it is given', () => {
    const wide = layoutMap(nodes, { width: 1600, height: 500 }).bounds
    const tall = layoutMap(nodes, { width: 500, height: 1600 }).bounds
    const ratio = (bounds: typeof wide) => (bounds.maxX - bounds.minX) / (bounds.maxY - bounds.minY)
    expect(ratio(wide)).toBeGreaterThan(ratio(tall))
  })

  it('fits the whole layout inside the view', () => {
    const view = fitView(layout.bounds, viewport.width, viewport.height)
    for (const point of layout.points.values()) {
      const x = point.x * view.scale + view.x
      const y = point.y * view.scale + view.y
      expect(x).toBeGreaterThanOrEqual(0)
      expect(x).toBeLessThanOrEqual(viewport.width)
      expect(y).toBeGreaterThanOrEqual(0)
      expect(y).toBeLessThanOrEqual(viewport.height)
    }
  })

  it('handles an empty fleet', () => {
    const empty = layoutMap([], viewport)
    expect(empty.points.size).toBe(0)
    expect(Number.isFinite(fitView(empty.bounds, 800, 600).scale)).toBe(true)
  })
})
