import { describe, expect, it } from 'vitest'
import type { Agent, Incident, ShellSession } from './api'
import { matchScore, search, type SearchSource } from './search'

function agent(id: string, hostname: string, ip: string): Agent {
  return {
    id,
    hostname,
    platform: 'windows',
    os_version: 'Windows 11 Pro 24H2',
    architecture: 'x86_64',
    version: '0.1.0',
    ip_address: ip,
    last_heartbeat: 0,
    created_at: 0,
    liveness_state: 'active',
    status: 'online',
  }
}

const incident: Incident = {
  id: 'i1',
  agent_id: 'a2',
  incident_type: 'service_stopped',
  evidence: '{}',
  opened_at: 10,
  closed_at: null,
}

const session: ShellSession = {
  id: 'sess-0001',
  agent_id: 'a1',
  created_at: 0,
  last_activity_at: 0,
  expires_at: 500,
  terminated_at: null,
  created_by_user_id: null,
}

const source: SearchSource = {
  agents: [agent('a1', 'ENG-WS-12', '10.20.3.22'), agent('a2', 'HR-DESKTOP-03', '10.20.2.13'), agent('a3', 'ENG-WS-28', '10.20.3.38')],
  incidents: [incident],
  sessions: [session],
  keys: [],
  now: 100,
}

function headings(query: string): string[] {
  return search(query, source).map((group) => group.heading)
}

describe('matchScore', () => {
  it('ranks a prefix above a word start above a match inside a word', () => {
    const prefix = matchScore('ENG-WS-12', 'eng')
    const word = matchScore('ENG-WS-12', 'ws')
    const inside = matchScore('ENG-WS-12', 'ng')
    expect(prefix).toBeGreaterThan(word)
    expect(word).toBeGreaterThan(inside)
    expect(matchScore('ENG-WS-12', 'zzz')).toBe(-1)
  })
})

describe('search', () => {
  it('offers open incidents and pages before anything is typed', () => {
    expect(headings('')).toEqual(['Open incidents', 'Go to'])
  })

  it('finds endpoints by hostname, address and id', () => {
    const byName = search('hr-desk', source)[0]!
    expect(byName.heading).toBe('Endpoints')
    expect(byName.results[0]!.title).toBe('HR-DESKTOP-03')
    expect(search('10.20.2.13', source)[0]!.results[0]!.title).toBe('HR-DESKTOP-03')
    expect(search('a3', source)[0]!.results[0]!.title).toBe('ENG-WS-28')
  })

  it('offers actions on the endpoint that clearly matches', () => {
    const groups = search('eng-ws-12', source)
    const actions = groups.find((group) => group.heading === 'On ENG-WS-12')!
    expect(actions.results.map((result) => result.target.kind)).toEqual(['shell', 'events'])
  })

  it('matches a subnet and reports how many endpoints it holds', () => {
    const subnets = search('10.20.3', source).find((group) => group.heading === 'Subnets')!
    expect(subnets.results[0]).toMatchObject({ title: '10.20.3.0/24', meta: '2 endpoints' })
  })

  it('finds an open incident by its type and a live shell session by host', () => {
    expect(headings('stopped')).toContain('Open incidents')
    const sessions = search('eng-ws-12', source).find((group) => group.heading === 'Shell sessions')!
    expect(sessions.results[0]!.target).toEqual({ kind: 'session', sessionId: 'sess-0001' })
  })

  it('leaves expired sessions out', () => {
    const later = search('eng-ws-12', { ...source, now: 900 })
    expect(later.some((group) => group.heading === 'Shell sessions')).toBe(false)
  })

  it('reaches pages and sign out by name', () => {
    expect(search('audit', source).some((group) => group.results.some((result) => result.id === 'page:/events'))).toBe(true)
    expect(search('users', source).some((group) => group.results.some((result) => result.id === 'page:/users'))).toBe(true)
    expect(headings('sign')).toContain('Session')
  })

  it('returns nothing for a query that matches nothing', () => {
    expect(search('qqqqqq', source)).toEqual([])
  })
})
