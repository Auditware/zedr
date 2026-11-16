import { create } from 'zustand'

type Identity = { token: string; username: string; role: string }

export type Session = Identity & { view?: { until: number; admin: Identity } }

const STORAGE_KEY = 'zedr.session'

function identity(value: unknown): Identity | null {
  if (!value || typeof value !== 'object') return null
  const { token, username, role } = value as Partial<Identity>
  return typeof token === 'string' && typeof username === 'string' && typeof role === 'string' ? { token, username, role } : null
}

function stored(): Session | null {
  const raw = localStorage.getItem(STORAGE_KEY)
  if (!raw) return null
  try {
    const parsed = JSON.parse(raw) as { view?: { until?: unknown; admin?: unknown } }
    const session = identity(parsed)
    if (!session) return null
    const admin = identity(parsed.view?.admin)
    return admin && typeof parsed.view?.until === 'number' ? { ...session, view: { until: parsed.view.until, admin } } : session
  } catch {
    localStorage.removeItem(STORAGE_KEY)
  }
  return null
}

type SessionStore = {
  session: Session | null
  signIn: (session: Identity) => void
  signOut: () => void
  impersonate: (as: Identity, until: number) => void
  stopImpersonating: () => void
}

function keep(session: Session): { session: Session } {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(session))
  return { session }
}

export const useSession = create<SessionStore>((set) => ({
  session: stored(),
  signIn: (session) => set(keep(session)),
  signOut: () => {
    localStorage.removeItem(STORAGE_KEY)
    set({ session: null })
  },
  impersonate: (as, until) =>
    set(({ session }) => {
      if (!session || session.view) return {}
      const admin = { token: session.token, username: session.username, role: session.role }
      return keep({ ...as, view: { until, admin } })
    }),
  stopImpersonating: () => set(({ session }) => (session?.view ? keep(session.view.admin) : {})),
}))

export function currentToken(): string | null {
  return useSession.getState().session?.token ?? null
}

export function isAdmin(session: Session | null): boolean {
  return session?.role === 'admin'
}
