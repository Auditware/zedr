import { currentToken, useSession } from './auth'
import type { components } from './schema'

type Schemas = components['schemas']

export type Agent = Omit<Schemas['Agent'], '_db_status'> & { status: string }
export type ApiEvent = Schemas['Event']
export type Incident = Schemas['Incident']
export type EventHistogram = Schemas['EventHistogram']
export type AuditEntry = Schemas['AuditEntry']
export type AuditResponse = Schemas['AuditResponse']
export type UserSummary = Schemas['UserSummary']
export type HuntResult = Schemas['HuntResult']
export type HuntEntity = Schemas['HuntEntity']
export type ApiKeyListItem = Schemas['ApiKeyListItem']
export type ApiKeyResponse = Schemas['ApiKeyResponse']
export type LoginResponse = Schemas['LoginResponse']
export type InstallKeyResponse = Schemas['InstallKeyResponse']
export type MfaSetupResponse = Schemas['MfaSetupResponse']
export type HealthResponse = Schemas['HealthResponse']
export type ChainView = Schemas['ChainView']
export type ChainSummary = Schemas['ChainSummary']
export type WindowSummary = Schemas['WindowSummary']
export type WindowView = Schemas['WindowView']
export type SealedEventView = Schemas['SealedEventView']
export type SealedRow = Schemas['SealedRow']
export type ReleaseView = Schemas['ReleaseView']
export type RulesetView = Schemas['RulesetView']
export type RuleView = Schemas['RuleView']

export type InstallKey = {
  id: string
  created_at: number
  expires_at: number
  created_by: string
  agent_version: string
  used_at: number | null
  revoked_at: number | null
  enrolled_at: number | null
  enrolled_agent_id: string | null
}

export type UpgradeCommand = {
  id: string
  agent_id: string
  target_version: string
  status: string
  created_at: number
}

export class ApiError extends Error {
  readonly status: number
  readonly column: number | null

  constructor(status: number, message: string, column: number | null = null) {
    super(message)
    this.status = status
    this.column = column
  }
}

export const API_BASE: string = import.meta.env.DEV ? '' : (import.meta.env.VITE_API_URL ?? '')

async function request<T>(method: string, path: string, body?: unknown, authenticated = true): Promise<T> {
  const headers: Record<string, string> = {}
  if (authenticated) {
    const token = currentToken()
    if (token) headers.Authorization = `Bearer ${token}`
  }
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const response = await fetch(API_BASE + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  })

  if (response.status === 401 && authenticated) {
    const { session, signOut, stopImpersonating } = useSession.getState()
    if (session?.view) stopImpersonating()
    else signOut()
    throw new ApiError(401, 'Signed out')
  }

  const text = await response.text()
  let parsed: unknown = undefined
  if (text) {
    try {
      parsed = JSON.parse(text)
    } catch {
      parsed = text
    }
  }

  if (!response.ok) {
    const message =
      parsed && typeof parsed === 'object' && 'error' in parsed && typeof parsed.error === 'string'
        ? parsed.error
        : response.statusText
    const column = parsed && typeof parsed === 'object' && 'column' in parsed && typeof parsed.column === 'number' ? parsed.column : null
    throw new ApiError(response.status, message, column)
  }

  return parsed as T
}

function query(params: Record<string, string | number | boolean | undefined>): string {
  const search = new URLSearchParams()
  for (const [key, value] of Object.entries(params)) {
    if (value !== undefined && value !== '') search.set(key, String(value))
  }
  const encoded = search.toString()
  return encoded ? `?${encoded}` : ''
}

export const testTenantLogin = () => request<LoginResponse>('POST', '/__dev/login', undefined, false)

export const api = {
  login: (username: string, password: string) =>
    request<LoginResponse>('POST', '/api/auth/login', { username, password }, false),
  loginMfa: (mfa_token: string, code: string) =>
    request<LoginResponse>('POST', '/api/auth/login/mfa', { mfa_token, code }, false),

  health: () => request<HealthResponse>('GET', '/health', undefined, false),

  agents: async () => (await request<{ agents: Agent[] }>('GET', '/api/admin/agents' + query({ limit: 5000 }))).agents,

  incidents: (open?: boolean) => request<Incident[]>('GET', '/api/admin/incidents' + query({ open, limit: 500 })),

  events: (params: { agentId?: string; types?: string[]; limit?: number; offset?: number; from?: number; to?: number }) =>
    request<ApiEvent[]>(
      'GET',
      '/api/admin/events' +
        query({
          agent_id: params.agentId,
          event_types: params.types?.join(','),
          limit: params.limit,
          offset: params.offset,
          from: params.from,
          to: params.to,
        }),
    ),
  eventHistogram: (params: { from: number; to: number; buckets: number; agentId?: string }) =>
    request<EventHistogram>(
      'GET',
      '/api/admin/events/histogram' + query({ from: params.from, to: params.to, buckets: params.buckets, agent_id: params.agentId }),
    ),

  chain: (agentId: string, limit?: number) => request<ChainView>('GET', `/api/admin/agents/${agentId}/chain` + query({ limit })),
  window: (agentId: string, window: number) => request<WindowView>('GET', `/api/admin/agents/${agentId}/windows/${window}`),
  sealed: (agentId: string, params: { before?: number; limit: number }) =>
    request<SealedRow[]>('GET', `/api/admin/agents/${agentId}/sealed` + query({ before: params.before, limit: params.limit })),
  chainSummary: () => request<ChainSummary>('GET', '/api/admin/chain/summary'),
  ruleset: () => request<RulesetView>('GET', '/api/admin/ruleset'),

  installKeys: async () => (await request<{ keys: InstallKey[] }>('GET', '/api/admin/installers')).keys,
  generateInstallKey: (agent_version?: string) =>
    request<InstallKeyResponse>('POST', '/api/admin/installers/generate', agent_version ? { agent_version } : {}),

  upgrades: () => request<UpgradeCommand[]>('GET', '/api/admin/upgrades'),
  issueUpgrade: (body: { agent_id: string; install_key_id: string; target_version: string }) =>
    request<UpgradeCommand>('POST', '/api/admin/upgrades', body),

  audit: (limit: number, offset: number) =>
    request<AuditResponse>('GET', '/api/admin/audit' + query({ limit, offset })),

  closeIncident: (id: string) => request<Incident>('POST', `/api/admin/incidents/${id}/close`),
  hunt: (query: string) => request<HuntResult>('POST', '/api/admin/hunt', { query }),
  huntFields: () => request<HuntEntity[]>('GET', '/api/admin/hunt/fields'),
  users: () => request<UserSummary[]>('GET', '/api/admin/users'),
  createUser: (body: { username: string; password: string; role: string }) =>
    request<UserSummary>('POST', '/api/admin/users', body),
  deleteUser: (id: string) => request<void>('DELETE', `/api/admin/users/${id}`),
  updateUser: (id: string, body: { role?: string; disabled?: boolean }) =>
    request<UserSummary>('PATCH', `/api/admin/users/${id}`, body),
  resetPassword: (id: string, password: string, current_password?: string) =>
    request<void>('POST', `/api/admin/users/${id}/password`, { password, current_password }),
  resetMfa: (id: string) => request<void>('POST', `/api/admin/users/${id}/mfa/reset`),
  signOutUser: (id: string) => request<void>('POST', `/api/admin/users/${id}/sign-out`),
  impersonate: (id: string) => request<Schemas['ImpersonationResponse']>('POST', `/api/admin/users/${id}/impersonate`),

  apiKeys: () => request<ApiKeyListItem[]>('GET', '/api/admin/api-keys'),
  createApiKey: (name: string) => request<ApiKeyResponse>('POST', '/api/admin/api-keys', { name }),
  revokeApiKey: (id: string) => request<unknown>('DELETE', `/api/admin/api-keys/${id}`),

  mfaStatus: () => request<{ enabled: boolean }>('GET', '/api/auth/mfa'),
  mfaSetup: () => request<MfaSetupResponse>('POST', '/api/auth/mfa/setup'),
  mfaEnable: (code: string) => request<{ recovery_codes: string[] }>('POST', '/api/auth/mfa/enable', { code }),
  mfaDisable: (code: string) => request<{ enabled: boolean }>('POST', '/api/auth/mfa/disable', { code }),
}

export function streamUrl(path: '/api/admin/events/stream' | '/api/admin/agents/stream'): string | null {
  const token = currentToken()
  return token ? `${API_BASE}${path}?token=${encodeURIComponent(token)}` : null
}
