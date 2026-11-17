import { useMutation, useQueryClient } from '@tanstack/react-query'
import { Ban, Plus } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Card, Chip, CopyButton, SectionTitle } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { Dialog, Field } from '@/components/ui/dialog'
import { inputClass } from '@/components/ui/input'
import { ApiError, api, type EnrollmentTokenCreated } from '@/lib/api'
import { ago, dateTime, span } from '@/lib/format'
import { useEnrollmentTokens } from '@/lib/queries'
import { tokenState } from '@/lib/tokens'

const TONE = { active: 'accent', 'used up': 'neutral', expired: 'neutral', revoked: 'alert' } as const

function Created({ token, onDismiss }: { token: EnrollmentTokenCreated; onDismiss: () => void }) {
  const commands = [
    { label: 'Linux and macOS', command: token.linux_command },
    { label: 'Windows', command: token.windows_command },
  ]
  return (
    <div className="mb-3 rounded-control border border-accent/60 p-3" role="status">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs text-muted">
        <Chip tone="accent">shown once</Chip>
        <span>Every machine that runs one of these enrolls into {token.label}. Keep it where only your provisioning reads it.</span>
        <button type="button" onClick={onDismiss} className="ml-auto rounded-md px-2 py-1 text-muted hover:bg-raised hover:text-text">
          Done
        </button>
      </div>
      {commands.map(({ label, command }) => (
        <div key={label} className="mt-2">
          <div className="mb-1 text-[11px] uppercase tracking-wider text-muted">{label}</div>
          <div className="flex items-start gap-2 rounded-control border border-line-strong bg-sunken p-2.5">
            <pre className="min-w-0 flex-1 overflow-x-auto whitespace-pre font-mono text-xs leading-relaxed text-text">{command}</pre>
            <CopyButton value={command} label={`Copy the ${label} command`} />
          </div>
        </div>
      ))}
    </div>
  )
}

export function FleetTokens({ admin, now }: { admin: boolean; now: number }) {
  const queryClient = useQueryClient()
  const { data } = useEnrollmentTokens()
  const [open, setOpen] = useState(false)
  const [label, setLabel] = useState('')
  const [days, setDays] = useState('30')
  const [cap, setCap] = useState('')
  const [error, setError] = useState('')
  const [created, setCreated] = useState<EnrollmentTokenCreated | null>(null)

  const refresh = () => void queryClient.invalidateQueries({ queryKey: ['enrollment-tokens'] })
  const create = useMutation({
    mutationFn: () => api.createEnrollmentToken(label.trim(), Number(days), cap.trim() ? Number(cap) : null),
    onSuccess: (token) => {
      setCreated(token)
      setOpen(false)
      setLabel('')
      setCap('')
      refresh()
    },
    onError: (cause) => setError(cause instanceof ApiError ? cause.message : 'Token not created'),
  })
  const revoke = useMutation({ mutationFn: (id: string) => api.revokeEnrollmentToken(id), onSuccess: refresh })

  const submit = (event: FormEvent) => {
    event.preventDefault()
    setError('')
    create.mutate()
  }

  const tokens = [...(data ?? [])].sort((a, b) => b.created_at - a.created_at)

  return (
    <Card role="region" className="shrink-0 p-4" aria-label="Fleet tokens">
      <div className="mb-2 flex items-center gap-3">
        <SectionTitle>Fleet tokens</SectionTitle>
        <span className="text-xs text-muted">One token enrolls many machines, for images, autoscaling groups and device management</span>
        {admin ? (
          <Button size="sm" className="ml-auto" onClick={() => setOpen(true)}>
            <Plus size={14} strokeWidth={2} aria-hidden />
            Token
          </Button>
        ) : null}
      </div>
      {created ? <Created token={created} onDismiss={() => setCreated(null)} /> : null}
      {tokens.length === 0 ? <p className="font-mono text-xs text-muted">none</p> : null}
      <div className="max-h-[220px] overflow-y-auto">
        {tokens.map((token) => {
          const state = tokenState(token, now)
          return (
            <div key={token.id} data-token={state} className="flex min-h-10 flex-wrap items-center gap-x-4 gap-y-1 border-b border-hairline py-1.5 font-mono text-xs last:border-b-0">
              <span className="w-[160px] min-w-0 truncate text-[13px] text-text" title={token.label}>
                {token.label}
              </span>
              <span className="w-[84px] shrink-0">
                <Chip tone={TONE[state]}>{state}</Chip>
              </span>
              <span className="w-[120px] shrink-0 text-soft">
                {token.use_count} {token.max_uses == null ? 'enrolled' : `of ${token.max_uses} enrolled`}
              </span>
              <span className="min-w-0 flex-1 truncate text-muted">
                {state === 'revoked'
                  ? `revoked ${ago(token.revoked_at ?? now, now)} ago by ${token.revoked_by ?? 'an admin'}`
                  : state === 'expired'
                    ? `expired ${ago(token.expires_at, now)} ago`
                    : `expires in ${span(token.expires_at - now)}, issued ${dateTime(token.created_at)} by ${token.created_by}`}
              </span>
              {admin && state !== 'revoked' && state !== 'expired' ? (
                <button
                  type="button"
                  aria-label={`Revoke fleet token ${token.label}`}
                  title="Revoke: no new machine enrolls with it, the ones it enrolled keep working"
                  disabled={revoke.isPending}
                  onClick={() => revoke.mutate(token.id)}
                  className="shrink-0 rounded-md p-1.5 text-muted hover:bg-raised hover:text-alert-soft disabled:opacity-40"
                >
                  <Ban size={15} strokeWidth={1.5} aria-hidden />
                </button>
              ) : null}
            </div>
          )
        })}
      </div>

      <Dialog open={open} onOpenChange={setOpen} title="New fleet token">
        <form onSubmit={submit} aria-label="New fleet token">
          <Field label="Group, the label its machines carry">
            <input required value={label} onChange={(event) => setLabel(event.target.value)} placeholder="prod-web" className={inputClass} />
          </Field>
          <Field label="Expires in days, 1 to 365">
            <input required type="number" min={1} max={365} value={days} onChange={(event) => setDays(event.target.value)} className={inputClass} />
          </Field>
          <Field label="At most this many machines, empty for no cap">
            <input type="number" min={1} value={cap} onChange={(event) => setCap(event.target.value)} className={inputClass} />
          </Field>
          {error ? (
            <p role="alert" className="mb-3 text-sm text-alert-soft">
              {error}
            </p>
          ) : null}
          <Button type="submit" variant="primary" disabled={create.isPending}>
            Create token
          </Button>
        </form>
      </Dialog>
    </Card>
  )
}
