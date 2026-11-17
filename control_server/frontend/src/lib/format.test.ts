import { describe, expect, it } from 'vitest'
import { ago, countdown, shortHash, shortId, span, subnet } from './format'

describe('span', () => {
  it('uses the largest unit that fits', () => {
    expect(span(0)).toBe('0s')
    expect(span(59)).toBe('59s')
    expect(span(60)).toBe('1m')
    expect(span(3600)).toBe('1h')
    expect(span(3600 + 23 * 60)).toBe('1h 23m')
    expect(span(3 * 86400 + 5)).toBe('3d')
  })

  it('never goes negative when clocks disagree', () => {
    expect(span(-30)).toBe('0s')
    expect(ago(1000, 990)).toBe('0s')
  })
})

describe('countdown', () => {
  it('shows minutes and seconds left, never below zero', () => {
    expect(countdown(900)).toBe('15:00')
    expect(countdown(61)).toBe('1:01')
    expect(countdown(9.2)).toBe('0:10')
    expect(countdown(-4)).toBe('0:00')
  })
})

describe('identifiers', () => {
  it('shortens ids and hashes without losing both ends of a hash', () => {
    expect(shortId('4491b297-4bf5-48b7-931c-e6f3ffe68baf')).toBe('4491b297')
    expect(shortHash('15cf646e89ceacf08c102b4bb5cd5867769ca082555ca2a28fe9f16287eb51dc')).toBe('15cf646e…51dc')
    expect(shortHash('short')).toBe('short')
  })
})

describe('subnet', () => {
  it('reduces an IPv4 address to its /24 and leaves anything else alone', () => {
    expect(subnet('10.20.3.44')).toBe('10.20.3.0/24')
    expect(subnet('fe80::1')).toBe('fe80::1')
    expect(subnet(null)).toBe('no address')
  })
})
