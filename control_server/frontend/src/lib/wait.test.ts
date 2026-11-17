import { describe, expect, it } from 'vitest'
import { ApiError } from './errors'
import { retryAfterOf, waitMessage } from './wait'

describe('retryAfterOf', () => {
  it('reads the wait of a refused attempt and nothing else', () => {
    expect(retryAfterOf(new ApiError(429, 'Too many failed attempts', null, 42))).toBe(42)
    expect(retryAfterOf(new ApiError(429, 'Too many failed attempts'))).toBeNull()
    expect(retryAfterOf(new ApiError(503, 'Unavailable', null, 30))).toBeNull()
    expect(retryAfterOf(new Error('offline'))).toBeNull()
  })
})

describe('waitMessage', () => {
  it('says how long to wait', () => {
    expect(waitMessage(842)).toBe('Too many failed attempts. Try again in 14:02.')
  })
})
