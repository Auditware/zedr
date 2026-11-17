import type { EnrollmentToken } from './api'

export type TokenState = 'active' | 'used up' | 'expired' | 'revoked'

/** Whether a fleet token still enrolls machines, and if not, why. A revoked token says so even after it expired */
export function tokenState(token: EnrollmentToken, now: number): TokenState {
  if (token.revoked_at != null) return 'revoked'
  if (token.expires_at <= now) return 'expired'
  if (token.max_uses != null && token.use_count >= token.max_uses) return 'used up'
  return 'active'
}
