import type { QueryClient } from '@tanstack/react-query'
import { create } from 'zustand'
import { streamUrl, type Agent, type ApiEvent } from './api'

const BUFFER = 600

type LiveStore = {
  connected: boolean
  events: ApiEvent[]
  setConnected: (connected: boolean) => void
  push: (event: ApiEvent) => void
}

export const useLive = create<LiveStore>((set) => ({
  connected: false,
  events: [],
  setConnected: (connected) => set({ connected }),
  push: (event) => set((state) => ({ events: [event, ...state.events].slice(0, BUFFER) })),
}))

type AgentSignal = { agent_id: string; event_type: 'Registered' | 'Heartbeat' | 'Offline'; timestamp: number }

function parse<T>(raw: string): T | null {
  try {
    return JSON.parse(raw) as T
  } catch {
    return null
  }
}

const RECONNECT_GRACE_MS = 4000

export function connectLive(queryClient: QueryClient): () => void {
  const eventsUrl = streamUrl('/api/admin/events/stream')
  const agentsUrl = streamUrl('/api/admin/agents/stream')
  if (!eventsUrl || !agentsUrl) return () => undefined

  const { setConnected, push } = useLive.getState()
  const events = new EventSource(eventsUrl)
  const agents = new EventSource(agentsUrl)
  let refetch: ReturnType<typeof setTimeout> | undefined

  const refetchAgentsSoon = () => {
    if (refetch) return
    refetch = setTimeout(() => {
      refetch = undefined
      void queryClient.invalidateQueries({ queryKey: ['agents'] })
    }, 1500)
  }

  let outage: ReturnType<typeof setTimeout> | undefined
  events.onopen = () => {
    clearTimeout(outage)
    outage = undefined
    setConnected(true)
  }
  events.onerror = () => {
    outage ??= setTimeout(() => {
      outage = undefined
      if (events.readyState !== EventSource.OPEN) setConnected(false)
    }, RECONNECT_GRACE_MS)
  }
  events.onmessage = (message) => {
    const event = parse<ApiEvent>(message.data as string)
    if (!event) return
    push(event)

    const type = event.event_type
    if (type.startsWith('incident_')) {
      void queryClient.invalidateQueries({ queryKey: ['incidents'] })
      refetchAgentsSoon()
    } else if (type.startsWith('shell_')) {
      void queryClient.invalidateQueries({ queryKey: ['shell'] })
    } else if (type === 'install' || type === 'identity_rotated') {
      void queryClient.invalidateQueries({ queryKey: ['install-keys'] })
      refetchAgentsSoon()
    } else if (type === 'upgrade') {
      void queryClient.invalidateQueries({ queryKey: ['upgrades'] })
      refetchAgentsSoon()
    } else if (type === 'agent_stopping') {
      refetchAgentsSoon()
    }
  }

  agents.onmessage = (message) => {
    const signal = parse<AgentSignal>(message.data as string)
    if (!signal) return
    let known = false
    queryClient.setQueryData<Agent[]>(['agents'], (current) =>
      current?.map((agent) => {
        if (agent.id !== signal.agent_id) return agent
        known = true
        return signal.event_type === 'Offline'
          ? { ...agent, status: 'offline' }
          : { ...agent, status: 'online', last_heartbeat: Math.max(agent.last_heartbeat, signal.timestamp) }
      }),
    )
    if (!known || signal.event_type !== 'Heartbeat') refetchAgentsSoon()
  }

  return () => {
    if (refetch) clearTimeout(refetch)
    clearTimeout(outage)
    events.close()
    agents.close()
    setConnected(false)
  }
}
