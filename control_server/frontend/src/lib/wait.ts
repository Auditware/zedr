import { useEffect, useState } from 'react'
import { ApiError } from './errors'
import { countdown, nowSeconds } from './format'

export function retryAfterOf(cause: unknown): number | null {
  return cause instanceof ApiError && cause.status === 429 ? cause.retryAfter : null
}

export function waitMessage(seconds: number): string {
  return `Too many failed attempts. Try again in ${countdown(seconds)}.`
}

/** Seconds left of a wait the server asked for, counted down once a second */
export function useRetryWait() {
  const [until, setUntil] = useState(0)
  const [now, setNow] = useState(nowSeconds)

  useEffect(() => {
    if (now >= until) return
    const timer = setTimeout(() => setNow(nowSeconds()), 1000)
    return () => clearTimeout(timer)
  }, [now, until])

  const hold = (cause: unknown): boolean => {
    const retryAfter = retryAfterOf(cause)
    if (retryAfter === null) return false
    const start = nowSeconds()
    setNow(start)
    setUntil(start + retryAfter)
    return true
  }

  return { left: Math.max(0, until - now), hold }
}
