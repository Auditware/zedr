import { useInfiniteQuery, useQuery } from '@tanstack/react-query'
import { useEffect, useMemo, useRef, useState, type RefObject } from 'react'
import { api, type Agent } from './api'
import { nowSeconds } from './format'
import { CATEGORIES } from './events'
import { SEALED_PAGE } from './sealed'

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

export function useDetections(agentId: string | undefined) {
  return useQuery({
    queryKey: ['agent-events', agentId, 'detections'],
    queryFn: () => api.events({ agentId, types: ['detection'], limit: 1000 }),
    enabled: !!agentId,
    refetchInterval: 15_000,
  })
}

export function useChain(agentId: string | undefined) {
  return useQuery({ queryKey: ['chain', agentId], queryFn: () => api.chain(agentId!), enabled: !!agentId, refetchInterval: 15_000 })
}

export function useWindow(agentId: string | undefined, window: number | null | undefined) {
  return useQuery({
    queryKey: ['chain', agentId, 'window', window],
    queryFn: () => api.window(agentId!, window!),
    enabled: !!agentId && window != null,
    refetchInterval: 15_000,
  })
}

export function useSealed(agentId: string) {
  return useInfiniteQuery({
    queryKey: ['chain', agentId, 'sealed'],
    queryFn: ({ pageParam }) => api.sealed(agentId, { before: pageParam, limit: SEALED_PAGE }),
    initialPageParam: undefined as number | undefined,
    getNextPageParam: (last) => (last.length < SEALED_PAGE ? undefined : last[last.length - 1]!.index),
    refetchInterval: (query) => ((query.state.data?.pages.length ?? 0) > 1 ? false : 20_000),
  })
}

export function useChainSummary() {
  return useQuery({ queryKey: ['chain-summary'], queryFn: api.chainSummary, refetchInterval: 15_000 })
}

export function useRuleset() {
  return useQuery({ queryKey: ['ruleset'], queryFn: api.ruleset, refetchInterval: 30_000 })
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
