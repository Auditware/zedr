import { describe, expect, it } from 'vitest'
import { eventRange, indices, PROOF_CHIP, PROOF_FILL, PROOF_LABEL, PROOF_ORDER, PROOF_SAID, proofCounts, proofStatus, share } from './chain'

describe('proof status', () => {
  it('has a label, a chip, a fill and a sentence for every status the server knows', () => {
    for (const status of ['pending', 'verified', 'mismatch', 'none'] as const) {
      expect(PROOF_ORDER).toContain(status)
      expect(PROOF_LABEL[status]).not.toBe('')
      expect(PROOF_CHIP[status].label).not.toBe('')
      expect(PROOF_FILL[status]).toMatch(/^bg-/)
      expect(PROOF_SAID[status]).toMatch(/\.$/)
    }
    expect(new Set(Object.values(PROOF_CHIP).map((chip) => chip.label)).size).toBe(4)
  })

  it('reads a status it does not know as one that still waits', () => {
    expect(proofStatus('verified')).toBe('verified')
    expect(proofStatus('none')).toBe('none')
    expect(proofStatus('something new')).toBe('pending')
  })

  it('counts windows by where their proof stands', () => {
    expect(proofCounts([{ proof: 'none' }, { proof: 'verified' }, { proof: 'none' }, { proof: 'mismatch' }])).toEqual({ verified: 1, pending: 0, mismatch: 1, none: 2 })
    expect(proofCounts([])).toEqual({ verified: 0, pending: 0, mismatch: 0, none: 0 })
  })
})

describe('chain wording', () => {
  it('says how small the opened part is without rounding it away', () => {
    expect(share(27, 8043)).toBe('0.34%')
    expect(share(1, 1_000_000)).toBe('under 0.01%')
    expect(share(0, 8043)).toBe('0%')
    expect(share(3, 0)).toBe('0%')
    expect(share(15, 100)).toBe('15%')
    expect(share(5, 100)).toBe('5.0%')
  })

  it('names the committed events of a window and of a release', () => {
    expect(eventRange(45, 8)).toBe('events #45 to #52')
    expect(eventRange(45, 1)).toBe('event #45')
    expect(eventRange(45, 0)).toBe('no events')
    expect(indices([52, 45, 12])).toBe('#52, #45, #12')
    expect(indices([])).toBe('')
  })
})
