import { useNavigate, useRouter } from '@tanstack/react-router'
import { useState, type FormEvent, type ReactNode } from 'react'
import { Logo } from '@/components/shell/Logo'
import { Button } from '@/components/ui/button'
import { inputClass } from '@/components/ui/input'
import { ApiError, api, testTenantLogin, type LoginResponse } from '@/lib/api'
import { useSession } from '@/lib/auth'

export function Login() {
  return import.meta.env.DEV ? <TestTenantLogin /> : <CredentialLogin />
}

function useEnter() {
  const navigate = useNavigate()
  const signIn = useSession((state) => state.signIn)
  return (response: LoginResponse) => {
    if (!response.token) throw new ApiError(500, 'No token returned')
    signIn({ token: response.token, username: response.username, role: response.role })
    void navigate({ to: '/endpoints' })
  }
}

function Frame({ children }: { children: ReactNode }) {
  return (
    <main className="flex h-full items-center justify-center bg-ink p-4">
      <div className="w-[min(360px,100%)] rounded-card border border-line bg-surface p-7">
        <div className="mb-7">
          <Logo size={34} />
        </div>
        {children}
      </div>
    </main>
  )
}

function TestTenantLogin() {
  const enter = useEnter()
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const open = async () => {
    setBusy(true)
    setError('')
    try {
      enter(await testTenantLogin())
    } catch {
      setError('Test tenant unreachable')
      setBusy(false)
    }
  }

  return (
    <Frame>
      <Button variant="primary" disabled={busy} onClick={open} className="w-full">
        Enter test tenant
      </Button>
      <div role="alert" className="mt-3 min-h-5 text-sm text-alert-soft">
        {error}
      </div>
    </Frame>
  )
}

function CredentialLogin() {
  const enter = useEnter()
  const router = useRouter()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [code, setCode] = useState('')
  const [challenge, setChallenge] = useState<string | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const submit = async (event: FormEvent) => {
    event.preventDefault()
    setBusy(true)
    setError('')
    // The console downloads while the server checks the password
    void router.loadRouteChunk(router.routesById['/app'])
    try {
      const response = challenge ? await api.loginMfa(challenge, code.trim()) : await api.login(username, password)
      if (response.mfa_required && response.mfa_token) setChallenge(response.mfa_token)
      else enter(response)
    } catch (cause) {
      setError(cause instanceof ApiError && cause.status === 401 ? 'Not accepted' : 'Server unreachable')
    } finally {
      setBusy(false)
    }
  }

  return (
    <Frame>
      <form onSubmit={submit}>
        {challenge ? (
          <label className="block">
            <span className="mb-1 block text-xs text-muted">Authenticator or recovery code</span>
            <input
              autoFocus
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              className={`${inputClass} text-center font-mono text-lg tracking-[0.3em]`}
            />
          </label>
        ) : (
          <>
            <label className="mb-3 block">
              <span className="mb-1 block text-xs text-muted">Username</span>
              <input
                autoFocus
                value={username}
                onChange={(event) => setUsername(event.target.value)}
                autoComplete="username"
                className={inputClass}
              />
            </label>
            <label className="block">
              <span className="mb-1 block text-xs text-muted">Password</span>
              <input
                type="password"
                value={password}
                onChange={(event) => setPassword(event.target.value)}
                autoComplete="current-password"
                className={inputClass}
              />
            </label>
          </>
        )}
        <div role="alert" className="mt-3 min-h-5 text-sm text-alert-soft">
          {error}
        </div>
        <Button type="submit" variant="primary" disabled={busy} className="mt-2 w-full">
          {challenge ? 'Verify' : 'Sign in'}
        </Button>
      </form>
    </Frame>
  )
}
