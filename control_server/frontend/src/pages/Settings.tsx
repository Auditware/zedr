import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { Database, ExternalLink, KeyRound, Monitor, Plus, Server as ServerIcon, ShieldCheck, ShieldOff, Trash2 } from 'lucide-react'
import { useEffect, useState, type FormEvent, type ReactNode } from 'react'
import { Card, CopyButton, PageHeader, SectionTitle } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { Dialog, Field } from '@/components/ui/dialog'
import { inputClass } from '@/components/ui/input'
import { ApiError, api, type ApiKeyResponse, type MfaSetupResponse } from '@/lib/api'
import { isAdmin, useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { ago, span } from '@/lib/format'
import { useLive } from '@/lib/live'
import { useNow } from '@/lib/queries'
import { resolveTone } from '@/lib/palette'
import { useRetryWait, waitMessage } from '@/lib/wait'

function message(cause: unknown, fallback: string): string {
  return cause instanceof ApiError ? cause.message : fallback
}

function Password() {
  const signIn = useSession((state) => state.signIn)
  const [current, setCurrent] = useState('')
  const [next, setNext] = useState('')
  const [again, setAgain] = useState('')
  const [error, setError] = useState('')
  const [changed, setChanged] = useState(false)
  const wait = useRetryWait()

  const change = useMutation({
    mutationFn: () => api.changePassword(current, next),
    onSuccess: (signedIn) => {
      if (signedIn.token) signIn({ token: signedIn.token, username: signedIn.username, role: signedIn.role })
      setCurrent('')
      setNext('')
      setAgain('')
      setChanged(true)
    },
    onError: (cause) => {
      if (!wait.hold(cause)) setError(message(cause, 'Password not changed'))
    },
  })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    setChanged(false)
    if (next !== again) {
      setError('The new password and its repetition differ')
      return
    }
    setError('')
    change.mutate()
  }

  return (
    <Card className="p-5">
      <SectionTitle>Password</SectionTitle>
      <form onSubmit={submit} aria-label="Change password" className="mt-3 max-w-[360px]">
        <Field label="Current password">
          <input type="password" autoComplete="current-password" required value={current} onChange={(event) => setCurrent(event.target.value)} className={inputClass} />
        </Field>
        <Field label="New password, 12 characters with upper and lower case, a number and a symbol">
          <input type="password" autoComplete="new-password" required value={next} onChange={(event) => setNext(event.target.value)} className={inputClass} />
        </Field>
        <Field label="New password again">
          <input type="password" autoComplete="new-password" required value={again} onChange={(event) => setAgain(event.target.value)} className={inputClass} />
        </Field>
        {wait.left > 0 || error ? (
          <p role="alert" className="mb-3 text-sm text-alert-soft">
            {wait.left > 0 ? waitMessage(wait.left) : error}
          </p>
        ) : null}
        {changed ? (
          <p role="status" className="mb-3 text-sm text-sage">
            Changed. Every other session of this account has ended.
          </p>
        ) : null}
        <Button type="submit" disabled={change.isPending || wait.left > 0}>
          <KeyRound size={15} strokeWidth={1.75} aria-hidden />
          Change password
        </Button>
      </form>
    </Card>
  )
}

function TwoFactor() {
  const queryClient = useQueryClient()
  const { data } = useQuery({ queryKey: ['mfa'], queryFn: api.mfaStatus })
  const enabled = data?.enabled ?? false
  const [setup, setSetup] = useState<MfaSetupResponse | null>(null)
  const [qr, setQr] = useState('')
  const [code, setCode] = useState('')
  const [recovery, setRecovery] = useState<string[] | null>(null)
  const [disabling, setDisabling] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    if (!setup) return
    let live = true
    void import('qrcode')
      .then(({ default: QRCode }) =>
        QRCode.toDataURL(setup.provisioning_uri, { margin: 1, width: 220, color: { dark: resolveTone('text'), light: '#00000000' } }),
      )
      .then((url) => {
        if (live) setQr(url)
      })
    return () => {
      live = false
    }
  }, [setup])

  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['mfa'] })
    void queryClient.invalidateQueries({ queryKey: ['users'] })
  }
  const start = useMutation({
    mutationFn: api.mfaSetup,
    onSuccess: (response) => {
      setError('')
      setCode('')
      setRecovery(null)
      setSetup(response)
    },
    onError: (cause) => setError(message(cause, 'Setup failed')),
  })
  const enable = useMutation({
    mutationFn: () => api.mfaEnable(code.trim()),
    onSuccess: (response) => {
      setRecovery(response.recovery_codes)
      refresh()
    },
    onError: (cause) => setError(message(cause, 'Code not accepted')),
  })
  const disable = useMutation({
    mutationFn: () => api.mfaDisable(code.trim()),
    onSuccess: () => {
      setDisabling(false)
      setCode('')
      refresh()
    },
    onError: (cause) => setError(message(cause, 'Code not accepted')),
  })

  const close = () => {
    setSetup(null)
    setQr('')
    setRecovery(null)
    setCode('')
    setError('')
  }

  return (
    <Card className="flex flex-col p-5">
      <SectionTitle>Two-factor</SectionTitle>
      <div className="mt-4 flex items-center gap-4">
        <span
          className={`flex h-14 w-14 items-center justify-center rounded-full border-2 ${enabled ? 'border-accent text-accent' : 'border-line-strong text-muted'}`}
          aria-hidden
        >
          {enabled ? <ShieldCheck size={26} strokeWidth={1.5} /> : <ShieldOff size={26} strokeWidth={1.5} />}
        </span>
        <div>
          <div className="font-display text-2xl font-medium">{enabled ? 'On' : 'Off'}</div>
          <div className="font-mono text-xs text-muted">TOTP · 6 digits · 30 s</div>
        </div>
      </div>
      <p className="mt-4 max-w-[46ch] text-[13px] text-muted">
        {enabled ? 'Signing in asks for a code from your authenticator after the password.' : 'Signing in asks for the password only.'}
      </p>
      <div className="mt-auto pt-5">
        {enabled ? (
          <Button
            onClick={() => {
              setError('')
              setCode('')
              setDisabling(true)
            }}
          >
            Turn off
          </Button>
        ) : (
          <Button variant="primary" onClick={() => start.mutate()} disabled={start.isPending}>
            Set up
          </Button>
        )}
        {!setup && !disabling && error ? <div className="mt-2 text-sm text-alert-soft">{error}</div> : null}
      </div>

      <Dialog open={!!setup} onOpenChange={(open) => (open ? undefined : close())} title={recovery ? 'Recovery codes' : 'Scan, then enter the code'}>
        {recovery ? (
          <>
            <div className="grid grid-cols-2 gap-2 rounded-control bg-sunken p-3 font-mono text-sm">
              {recovery.map((item) => (
                <span key={item}>{item}</span>
              ))}
            </div>
            <div className="mt-4 flex items-center justify-between">
              <span className="inline-flex items-center gap-1 text-xs text-muted">
                Shown once <CopyButton value={recovery.join('\n')} label="Copy recovery codes" />
              </span>
              <Button variant="primary" onClick={close}>
                Done
              </Button>
            </div>
          </>
        ) : setup ? (
          <form
            onSubmit={(event: FormEvent) => {
              event.preventDefault()
              setError('')
              enable.mutate()
            }}
          >
            <div className="flex justify-center rounded-control bg-sunken p-3">
              {qr ? <img src={qr} alt="Authenticator QR code" width={220} height={220} /> : <div className="h-[220px] w-[220px]" />}
            </div>
            <div className="my-3 flex items-center gap-1 font-mono text-xs text-muted">
              <span className="min-w-0 truncate">{setup.secret}</span>
              <CopyButton value={setup.secret} label="Copy secret" />
            </div>
            <input
              autoFocus
              value={code}
              onChange={(event) => setCode(event.target.value)}
              inputMode="numeric"
              autoComplete="one-time-code"
              aria-label="Authenticator code"
              placeholder="000000"
              className={`${inputClass} text-center font-mono text-lg tracking-[0.3em]`}
            />
            <div role="alert" className="mt-2 min-h-5 text-sm text-alert-soft">
              {error}
            </div>
            <Button type="submit" variant="primary" className="mt-1 w-full" disabled={enable.isPending || code.trim().length < 6}>
              Turn on
            </Button>
          </form>
        ) : null}
      </Dialog>

      <Dialog open={disabling} onOpenChange={setDisabling} title="Turn off two-factor">
        <form
          onSubmit={(event: FormEvent) => {
            event.preventDefault()
            setError('')
            disable.mutate()
          }}
        >
          <input
            autoFocus
            value={code}
            onChange={(event) => setCode(event.target.value)}
            aria-label="Authenticator or recovery code"
            placeholder="code"
            className={`${inputClass} text-center font-mono text-lg tracking-[0.2em]`}
          />
          <div role="alert" className="mt-2 min-h-5 text-sm text-alert-soft">
            {error}
          </div>
          <Button type="submit" variant="danger" className="mt-1 w-full" disabled={disable.isPending || !code.trim()}>
            Turn off
          </Button>
        </form>
      </Dialog>
    </Card>
  )
}

function ApiKeys() {
  const queryClient = useQueryClient()
  const now = useNow(10_000)
  const { data } = useQuery({ queryKey: ['api-keys'], queryFn: api.apiKeys })
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [fresh, setFresh] = useState<ApiKeyResponse | null>(null)
  const [error, setError] = useState('')

  const create = useMutation({
    mutationFn: () => api.createApiKey(name.trim()),
    onSuccess: (key) => {
      setFresh(key)
      setName('')
      void queryClient.invalidateQueries({ queryKey: ['api-keys'] })
    },
    onError: (cause) => setError(message(cause, 'Key not created')),
  })
  const revoke = useMutation({
    mutationFn: (id: string) => api.revokeApiKey(id),
    onSuccess: () => void queryClient.invalidateQueries({ queryKey: ['api-keys'] }),
  })

  return (
    <Card className="flex min-h-0 flex-col p-5">
      <div className="flex items-center justify-between">
        <SectionTitle>API keys</SectionTitle>
        <Button
          size="sm"
          onClick={() => {
            setError('')
            setFresh(null)
            setOpen(true)
          }}
        >
          <Plus size={14} strokeWidth={2} aria-hidden />
          Key
        </Button>
      </div>
      <div className="mt-3 min-h-0 flex-1 overflow-y-auto">
        {(data ?? []).length === 0 ? <div className="font-mono text-xs text-muted">none</div> : null}
        {(data ?? []).map((key) => (
          <div key={key.id} className="flex h-11 items-center gap-3 border-b border-hairline font-mono text-xs">
            <span className="min-w-0 flex-1 truncate text-[13px] text-text">{key.name}</span>
            <span className="text-muted">{key.last_used_at ? `used ${ago(key.last_used_at, now)} ago` : 'never used'}</span>
            <span
              className="h-1 w-16 shrink-0 overflow-hidden rounded-full bg-sunken"
              role="img"
              aria-label={`Expires in ${span(key.expires_at - now)}`}
              title={`Expires in ${span(key.expires_at - now)}`}
            >
              <span
                className="block h-full rounded-full bg-accent"
                style={{ width: `${(Math.max(0, key.expires_at - now) / Math.max(1, key.expires_at - key.created_at)) * 100}%` }}
              />
            </span>
            <span className="w-9 text-right text-muted">{span(key.expires_at - now)}</span>
            <button
              type="button"
              aria-label={`Revoke ${key.name}`}
              onClick={() => revoke.mutate(key.id)}
              className="rounded-md p-1.5 text-muted hover:bg-raised hover:text-alert-soft"
            >
              <Trash2 size={15} strokeWidth={1.5} aria-hidden />
            </button>
          </div>
        ))}
      </div>

      <Dialog open={open} onOpenChange={setOpen} title={fresh ? 'Copy it now' : 'New API key'}>
        {fresh ? (
          <>
            <div className="flex items-start gap-2 rounded-control bg-sunken p-3">
              <span className="min-w-0 flex-1 break-all font-mono text-xs">{fresh.api_key}</span>
              <CopyButton value={fresh.api_key} label="Copy API key" />
            </div>
            <Button variant="primary" className="mt-4 w-full" onClick={() => setOpen(false)}>
              Done
            </Button>
          </>
        ) : (
          <form
            onSubmit={(event: FormEvent) => {
              event.preventDefault()
              setError('')
              create.mutate()
            }}
          >
            <Field label="Name">
              <input autoFocus value={name} onChange={(event) => setName(event.target.value)} className={`${inputClass} font-mono`} />
            </Field>
            <div role="alert" className="min-h-5 text-sm text-alert-soft">
              {error}
            </div>
            <Button type="submit" variant="primary" className="mt-1 w-full" disabled={create.isPending || !name.trim()}>
              Create
            </Button>
          </form>
        )}
      </Dialog>
    </Card>
  )
}

function Hop({ label, value, ok }: { label: string; value: string; ok: boolean }) {
  return (
    <span className="flex min-w-[56px] flex-1 flex-col items-center gap-1" data-hop={label} data-ok={ok}>
      <span className={cn('font-mono text-[10px]', ok ? 'text-muted' : 'text-alert-soft')}>{label}</span>
      <span className={cn('h-px w-full', ok ? 'bg-line-hover' : 'border-t border-dashed border-alert')} />
      <span className={cn('font-mono text-[11px]', ok ? 'text-soft' : 'text-alert-soft')}>{value}</span>
    </span>
  )
}

function Stop({ icon, label, detail, ok }: { icon: ReactNode; label: string; detail: string; ok: boolean }) {
  return (
    <span className="flex w-[92px] shrink-0 flex-col items-center gap-1.5 text-center">
      <span className={cn('flex h-11 w-11 items-center justify-center rounded-full border', ok ? 'border-line-hover text-text' : 'border-alert text-alert-soft')}>{icon}</span>
      <span className="text-xs text-text">{label}</span>
      <span className="font-mono text-[10px] text-muted">{detail}</span>
    </span>
  )
}

function Server() {
  const { data, isError } = useQuery({
    queryKey: ['health'],
    queryFn: async () => {
      const started = performance.now()
      const health = await api.health()
      return { ...health, took: Math.round(performance.now() - started) }
    },
    refetchInterval: 15_000,
  })
  const connected = useLive((state) => state.connected)
  const reached = !isError && data?.status === 'ok'
  const stored = data?.database === 'connected'
  return (
    <Card className="flex flex-col p-5">
      <SectionTitle>Server</SectionTitle>
      <div role="img" aria-label="Path from this browser to the database" className="mt-5 flex items-start justify-between gap-1">
        <Stop icon={<Monitor size={19} strokeWidth={1.5} aria-hidden />} label="This browser" detail={connected ? 'live' : 'not live'} ok={connected} />
        <span className="flex min-w-0 flex-1 flex-col gap-2 pt-1">
          <Hop label="requests" value={isError ? 'unreachable' : data ? `${data.took} ms` : '…'} ok={reached} />
          <Hop label="live stream" value={connected ? 'connected' : 'disconnected'} ok={connected} />
        </span>
        <Stop icon={<ServerIcon size={19} strokeWidth={1.5} aria-hidden />} label="Control server" detail={`v${data?.version ?? '…'}`} ok={reached} />
        <span className="flex min-w-0 flex-1 flex-col gap-2 pt-1">
          <Hop label="storage" value={data?.database ?? '…'} ok={stored} />
        </span>
        <Stop icon={<Database size={19} strokeWidth={1.5} aria-hidden />} label="Database" detail="SQLite" ok={stored} />
      </div>
      <a
        href="/api-docs/swagger-ui"
        target="_blank"
        rel="noreferrer"
        className="mt-auto inline-flex items-center gap-1.5 pt-5 font-mono text-xs text-accent hover:underline"
      >
        API reference <ExternalLink size={13} strokeWidth={1.5} aria-hidden />
      </a>
    </Card>
  )
}

export function Settings() {
  const session = useSession((state) => state.session)
  const admin = isAdmin(session)
  return (
    <div className="absolute inset-0 flex flex-col gap-4 overflow-y-auto px-6 pb-5 pt-4">
      <PageHeader title="Settings" meta={session ? `${session.username} · ${session.role}` : undefined} />
      <div className="grid auto-rows-[minmax(232px,auto)] grid-cols-2 gap-4 max-lg:grid-cols-1">
        <TwoFactor />
        <Server />
        {session?.view ? null : <Password />}
        {admin ? <ApiKeys /> : null}
      </div>
    </div>
  )
}
