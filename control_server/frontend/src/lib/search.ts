import type { Agent, Incident, InstallKey } from './api'
import { incidentTitle } from './events'
import { shortId, subnet } from './format'

export type SearchTarget =
  | { kind: 'endpoint'; agentId: string }
  | { kind: 'subnet'; key: string }
  | { kind: 'events'; agentId: string }
  | { kind: 'page'; to: '/endpoints' | '/hunt' | '/events' | '/rules' | '/installers' | '/users' | '/settings' }
  | { kind: 'sign-out' }

export type SearchResult = {
  id: string
  title: string
  meta: string
  mono: boolean
  agentId?: string
  target: SearchTarget
}

export type SearchGroup = { heading: string; results: SearchResult[] }

export type SearchSource = {
  agents: Agent[]
  incidents: Incident[]
  keys: InstallKey[]
}

const PAGES: { to: Extract<SearchTarget, { kind: 'page' }>['to']; label: string; words: string }[] = [
  { to: '/endpoints', label: 'Endpoints', words: 'endpoints map hosts incidents' },
  { to: '/hunt', label: 'Hunt', words: 'hunt query search threat' },
  { to: '/events', label: 'Events', words: 'events stream log audit sealed opened' },
  { to: '/rules', label: 'Rules', words: 'rules detections proof image release open' },
  { to: '/installers', label: 'Installers', words: 'installers install keys enroll' },
  { to: '/users', label: 'Users', words: 'users accounts roles impersonate' },
  { to: '/settings', label: 'Settings', words: 'settings users two-factor api keys' },
]

export function matchScore(haystack: string, needle: string): number {
  const index = haystack.toLowerCase().indexOf(needle)
  if (index < 0) return -1
  const start = index === 0 ? 100 : /[\s.\-_/:]/.test(haystack[index - 1] ?? '') ? 70 : 40
  return start - Math.min(30, haystack.length - needle.length) * 0.5
}

function best(fields: (string | null | undefined)[], needle: string): number {
  let top = -1
  for (const field of fields) {
    if (field) top = Math.max(top, matchScore(field, needle))
  }
  return top
}

function ranked<T>(items: T[], score: (item: T) => number, limit: number): T[] {
  return items
    .map((item) => ({ item, value: score(item) }))
    .filter((entry) => entry.value >= 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, limit)
    .map((entry) => entry.item)
}

export function search(query: string, source: SearchSource): SearchGroup[] {
  const needle = query.trim().toLowerCase()
  const byId = new Map(source.agents.map((agent) => [agent.id, agent]))
  const hostOf = (agentId: string) => byId.get(agentId)?.hostname ?? shortId(agentId)
  const open = source.incidents.filter((incident) => incident.closed_at == null)
  const groups: SearchGroup[] = []
  const add = (heading: string, results: SearchResult[]) => {
    if (results.length > 0) groups.push({ heading, results })
  }

  const incidentResult = (incident: Incident): SearchResult => ({
    id: `incident:${incident.id}`,
    title: hostOf(incident.agent_id),
    meta: incidentTitle(incident),
    mono: true,
    agentId: incident.agent_id,
    target: { kind: 'endpoint', agentId: incident.agent_id },
  })
  const pageResult = (page: (typeof PAGES)[number]): SearchResult => ({
    id: `page:${page.to}`,
    title: page.label,
    meta: '',
    mono: false,
    target: { kind: 'page', to: page.to },
  })

  if (!needle) {
    add('Open incidents', open.slice(0, 5).map(incidentResult))
    add('Go to', PAGES.map(pageResult))
    return groups
  }

  const endpoints = ranked(
    source.agents,
    (agent) => best([agent.hostname, agent.ip_address, agent.id, agent.os_version, `v${agent.version}`], needle),
    6,
  )
  add(
    'Endpoints',
    endpoints.map((agent) => ({
      id: `endpoint:${agent.id}`,
      title: agent.hostname,
      meta: [agent.ip_address, agent.os_version].filter(Boolean).join(' · '),
      mono: true,
      agentId: agent.id,
      target: { kind: 'endpoint', agentId: agent.id },
    })),
  )

  const top = endpoints[0]
  if (top && (endpoints.length === 1 || top.hostname.toLowerCase() === needle)) {
    add(`On ${top.hostname}`, [
      { id: `events:${top.id}`, title: 'Show its events', meta: '', mono: false, target: { kind: 'events', agentId: top.id } },
    ])
  }

  const subnets = new Map<string, number>()
  for (const agent of source.agents) {
    const key = subnet(agent.ip_address)
    subnets.set(key, (subnets.get(key) ?? 0) + 1)
  }
  add(
    'Subnets',
    ranked([...subnets.entries()], ([key]) => matchScore(key, needle), 3).map(([key, count]) => ({
      id: `subnet:${key}`,
      title: key,
      meta: `${count} endpoints`,
      mono: true,
      target: { kind: 'subnet', key },
    })),
  )

  add(
    'Open incidents',
    ranked(
      open,
      (incident) =>
        best([hostOf(incident.agent_id), incident.incident_type, incidentTitle(incident)], needle),
      4,
    ).map(incidentResult),
  )

  add(
    'Install keys',
    ranked(source.keys, (key) => (key.id.toLowerCase().startsWith(needle) && needle.length >= 3 ? 100 : -1), 3).map(
      (key) => ({
        id: `key:${key.id}`,
        title: shortId(key.id),
        meta: key.enrolled_agent_id ? `enrolled ${hostOf(key.enrolled_agent_id)}` : `issued by ${key.created_by}`,
        mono: true,
        target: { kind: 'page', to: '/installers' },
      }),
    ),
  )

  add('Go to', ranked(PAGES, (page) => best([page.label, ...page.words.split(' ')], needle), 3).map(pageResult))

  if (matchScore('sign out log out', needle) >= 0) {
    add('Session', [{ id: 'sign-out', title: 'Sign out', meta: '', mono: false, target: { kind: 'sign-out' } }])
  }

  return groups
}
