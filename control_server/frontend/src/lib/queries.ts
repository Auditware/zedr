import { useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import { api, type Agent } from './api'
import { nowSeconds } from './format'
import { CATEGORIES } from './events'

export function useAgents() {
  return useQuery({ queryKey: ['agents'], queryFn: api.agents, refetchInterval: 15_000 })
}

export function useAgentIndex(): Map<string, Agent> {
  const { data } = useAgents()
  return useMemo(() => new Map((data ?? []).map((agent) => [agent.id, agent])), [data])
}

export function useIncidents() {
  return useQuery({ queryKey: ['incidents'], queryFn: () => api.incidents(), refetchInterval: 15_000 })
}

export function useShellSessions() {
  return useQuery({ queryKey: ['shell', 'sessions'], queryFn: api.shellSessions, refetchInterval: 20_000 })
}

export function useShellCommands(sessionId: string | undefined, fast: boolean) {
  return useQuery({
    queryKey: ['shell', 'commands', sessionId],
    queryFn: () => api.shellCommands(sessionId!),
    enabled: !!sessionId,
    refetchInterval: fast ? 2_000 : 15_000,
  })
}

export function useInstallKeys() {
  return useQuery({ queryKey: ['install-keys'], queryFn: api.installKeys, refetchInterval: 30_000 })
}

const AGENT_EVENT_TYPES = CATEGORIES.filter((category) => category.id !== 'telemetry').flatMap((category) => category.types)

export function useAgentEvents(agentId: string) {
  return useQuery({
    queryKey: ['agent-events', agentId, 'own'],
    queryFn: () => api.events({ agentId, types: AGENT_EVENT_TYPES, limit: 1000 }),
    refetchInterval: 20_000,
  })
}

export function useUpgrades() {
  return useQuery({ queryKey: ['upgrades'], queryFn: api.upgrades, refetchInterval: 30_000 })
}

export function useNow(intervalMs = 1000): number {
  const [now, setNow] = useState(nowSeconds)
  useEffect(() => {
    const timer = setInterval(() => setNow(nowSeconds()), intervalMs)
    return () => clearInterval(timer)
  }, [intervalMs])
  return now
}

export function useMedia(query: string): boolean {
  const [matches, setMatches] = useState(() => window.matchMedia(query).matches)
  useEffect(() => {
    const media = window.matchMedia(query)
    const update = () => setMatches(media.matches)
    update()
    media.addEventListener('change', update)
    return () => media.removeEventListener('change', update)
  }, [query])
  return matches
}

export function useSize<T extends HTMLElement>(): [RefObject<T | null>, { width: number; height: number }] {
  const ref = useRef<T>(null)
  const [size, setSize] = useState({ width: 0, height: 0 })
  useEffect(() => {
    const element = ref.current
    if (!element) return
    const observer = new ResizeObserver(([entry]) => {
      const width = Math.floor(entry!.contentRect.width)
      const height = Math.floor(entry!.contentRect.height)
      setSize((current) => (current.width === width && current.height === height ? current : { width, height }))
    })
    observer.observe(element)
    return () => observer.disconnect()
  }, [])
  return [ref, size]
}
