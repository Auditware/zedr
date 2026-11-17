import { describe, expect, it } from 'vitest'
import type { EnrollmentToken } from './api'
import { tokenState } from './tokens'

const NOW = 1_800_000_000

function token(overrides: Partial<EnrollmentToken>): EnrollmentToken {
  return {
    id: 't',
    label: 'prod-web',
    created_at: NOW - 3600,
    created_by: 'admin',
    expires_at: NOW + 3600,
    max_uses: null,
    use_count: 0,
    last_used_at: null,
    revoked_at: null,
    revoked_by: null,
    ...overrides,
  }
}

describe('tokenState', () => {
  it('tells a token that still enrolls from one that no longer does, revocation first', () => {
    expect(tokenState(token({}), NOW)).toBe('active')
    expect(tokenState(token({ max_uses: 3, use_count: 2 }), NOW)).toBe('active')
    expect(tokenState(token({ max_uses: 3, use_count: 3 }), NOW)).toBe('used up')
    expect(tokenState(token({ expires_at: NOW }), NOW)).toBe('expired')
    expect(tokenState(token({ expires_at: NOW - 1, revoked_at: NOW - 10 }), NOW)).toBe('revoked')
  })
})
