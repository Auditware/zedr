import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { getRouteApi, Link, useNavigate } from '@tanstack/react-router'
import { Eye, KeyRound, LogOut, PanelRight, Plus, ShieldOff, Trash2, UserCheck, UserX } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { Chip, Empty, PageHeader, SectionTitle, StateDot } from '@/components/ui/bits'
import { Button } from '@/components/ui/button'
import { Dialog, Field, inputClass } from '@/components/ui/dialog'
import { CollapseToggle, Handle, Panel, PaneStrip, Split, STRIP_SIZE, useCollapsible } from '@/components/ui/panes'
import { Segmented } from '@/components/ui/segmented'
import { ApiError, api, type AuditEntry, type UserSummary } from '@/lib/api'
import { isAdmin, useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { auditTone } from '@/lib/events'
import { ago, clock, dateTime, span } from '@/lib/format'
import { tone } from '@/lib/palette'
import { useMedia, useNow } from '@/lib/queries'

const route = getRouteApi('/app/users')

type Range = '24h' | '7d'
const RANGES: { id: Range; label: string; seconds: number }[] = [
  { id: '24h', label: '24h', seconds: 86_400 },
  { id: '7d', label: '7d', seconds: 604_800 },
]
const TICKS = [0, 0.25, 0.5, 0.75]
const GRID =
  'grid items-center gap-x-3 grid-cols-[32px_minmax(96px,1fr)_minmax(90px,1.4fr)_30px] @[620px]:grid-cols-[32px_minmax(120px,170px)_84px_46px_minmax(120px,1fr)_30px]'
const WIDE = 'hidden @[620px]:block'
type Role = 'user' | 'admin'
const ROLES: { id: Role; label: string }[] = [
  { id: 'user', label: 'Read only' },
  { id: 'admin', label: 'Admin' },
]

function message(cause: unknown, fallback: string): string {
  return cause instanceof ApiError ? cause.message : fallback
}

function Avatar({ user }: { user: UserSummary }) {
  return (
    <span
      className="flex h-8 w-8 shrink-0 items-center justify-center rounded-full bg-selected font-display text-xs font-semibold uppercase text-text"
      aria-hidden
    >
      {user.username.slice(0, 1)}
    </span>
  )
}

function Lane({ entries, from, to }: { entries: AuditEntry[]; from: number; to: number }) {
  const width = Math.max(1, to - from)
  return (
    <span className="relative block h-7 min-w-0" role="img" aria-label={`${entries.length} actions`}>
      {TICKS.map((tick) => (
        <span key={tick} className="absolute inset-y-0 w-px bg-hairline" style={{ left: `${tick * 100}%` }} />
      ))}
      <span className="absolute inset-x-0 top-1/2 h-px bg-line" />
      {entries.map((entry) => {
        const failed = auditTone(entry.action) === tone('alert')
        return (
          <span
            key={entry.seq}
            className={cn('absolute top-1/2 w-[3px] -translate-x-1/2 -translate-y-1/2 rounded-full', failed ? 'h-5' : 'h-3.5')}
            style={{ left: `${((entry.timestamp - from) / width) * 100}%`, background: auditTone(entry.action) }}
            title={`${clock(entry.timestamp)} ${entry.action}`}
          />
        )
      })}
    </span>
  )
}

function NewUser({ open, onOpenChange }: { open: boolean; onOpenChange: (open: boolean) => void }) {
  const queryClient = useQueryClient()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [role, setRole] = useState<Role>('user')
  const create = useMutation({
    mutationFn: () => api.createUser({ username: username.trim(), password, role }),
    onSuccess: () => {
      onOpenChange(false)
      setUsername('')
      setPassword('')
      setRole('user')
      void queryClient.invalidateQueries({ queryKey: ['users'] })
    },
  })

  return (
    <Dialog open={open} onOpenChange={onOpenChange} title="New user">
      <form
        onSubmit={(event: FormEvent) => {
          event.preventDefault()
          create.mutate()
        }}
      >
        <Field label="Username">
          <input autoFocus value={username} onChange={(event) => setUsername(event.target.value)} autoComplete="off" className={`${inputClass} font-mono`} />
        </Field>
        <Field label="Password, 12+ characters with mixed classes">
          <input type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" className={inputClass} />
        </Field>
        <Segmented label="Role" value={role} options={ROLES} onChange={setRole} />
        <div role="alert" className="mt-2 min-h-5 text-sm text-alert-soft">
          {create.error ? message(create.error, 'User not created') : ''}
        </div>
        <Button type="submit" variant="primary" className="mt-1 w-full" disabled={create.isPending || !username.trim() || !password}>
          Create
        </Button>
      </form>
    </Dialog>
  )
}

function NewPassword({ user, self, onClose }: { user: UserSummary; self: boolean; onClose: () => void }) {
  const [password, setPassword] = useState('')
  const [current, setCurrent] = useState('')
  const reset = useMutation({
    mutationFn: () => api.resetPassword(user.id, password, self ? current : undefined),
    onSuccess: onClose,
  })

  return (
    <Dialog open onOpenChange={(open) => (open ? undefined : onClose())} title={`New password for ${user.username}`}>
      <form
        onSubmit={(event: FormEvent) => {
          event.preventDefault()
          reset.mutate()
        }}
      >
        {self ? (
          <Field label="Your current password">
            <input autoFocus type="password" value={current} onChange={(event) => setCurrent(event.target.value)} autoComplete="current-password" className={inputClass} />
          </Field>
        ) : null}
        <Field label="New password, 12+ characters with mixed classes">
          <input autoFocus={!self} type="password" value={password} onChange={(event) => setPassword(event.target.value)} autoComplete="new-password" className={inputClass} />
        </Field>
        <div role="alert" className="min-h-5 text-sm text-alert-soft">
          {reset.error ? message(reset.error, 'Password not changed') : ''}
        </div>
        <Button type="submit" variant="primary" className="mt-1 w-full" disabled={reset.isPending || !password || (self && !current)}>
          Set password and sign out every session
        </Button>
      </form>
    </Dialog>
  )
}

function UserSheet({ user, self, entries, now }: { user: UserSummary; self: boolean; entries: AuditEntry[]; now: number }) {
  const queryClient = useQueryClient()
  const navigate = route.useNavigate()
  const [dialog, setDialog] = useState<'password' | 'delete' | null>(null)
  const refresh = () => {
    void queryClient.invalidateQueries({ queryKey: ['users'] })
    void queryClient.invalidateQueries({ queryKey: ['audit'] })
  }
  const update = useMutation({ mutationFn: (body: { role?: string; disabled?: boolean }) => api.updateUser(user.id, body), onSuccess: refresh })
  const signOut = useMutation({ mutationFn: () => api.signOutUser(user.id), onSuccess: refresh })
  const resetMfa = useMutation({ mutationFn: () => api.resetMfa(user.id), onSuccess: refresh })
  const remove = useMutation({
    mutationFn: () => api.deleteUser(user.id),
    onSuccess: () => {
      refresh()
      void navigate({ search: {}, replace: true })
    },
  })
  const impersonate = useSession((state) => state.impersonate)
  const go = useNavigate()
  const view = useMutation({
    mutationFn: () => api.impersonate(user.id),
    onSuccess: (issued) => {
      impersonate({ token: issued.token, username: issued.username, role: issued.role }, issued.expires_at)
      void go({ to: '/endpoints' })
    },
  })
  const failure = update.error ?? signOut.error ?? resetMfa.error ?? remove.error ?? view.error
  const disabled = user.disabled_at != null

  return (
    <div className="flex min-h-full flex-col">
      <div className="flex items-center gap-3 pr-9">
        <Avatar user={user} />
        <h2 className="min-w-0 truncate font-mono text-xl font-medium tracking-tight">{user.username}</h2>
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <Chip tone={disabled ? 'alert' : 'accent'}>{disabled ? 'disabled' : 'active'}</Chip>
        <Chip tone={user.mfa_enabled ? 'neutral' : 'warn'}>{user.mfa_enabled ? 'two-factor on' : 'no two-factor'}</Chip>
        {self ? <Chip>you</Chip> : null}
      </div>

      <dl className="mt-4 grid grid-cols-[92px_minmax(0,1fr)] gap-x-3 gap-y-1.5 text-[13px]">
        <dt className="text-muted">Last sign-in</dt>
        <dd className="font-mono">{user.last_login_at ? dateTime(user.last_login_at) : 'never'}</dd>
        <dt className="text-muted">Created</dt>
        <dd className="font-mono">{user.created_at ? dateTime(user.created_at) : '-'}</dd>
      </dl>

      <SectionTitle className="mb-2 mt-5">Role</SectionTitle>
      <fieldset disabled={self || update.isPending} className="disabled:opacity-50">
        <Segmented label="Role" value={user.role === 'admin' ? 'admin' : 'user'} options={ROLES} onChange={(role) => update.mutate({ role })} />
      </fieldset>

      <SectionTitle className="mb-2 mt-5">Access</SectionTitle>
      <div className="grid grid-cols-2 gap-2 [&>button]:min-w-0 [&>button]:justify-start [&>button]:px-2.5">
        {self || disabled || user.role === 'admin' ? null : (
          <Button size="sm" onClick={() => view.mutate()} disabled={view.isPending}>
            <Eye size={14} strokeWidth={1.5} aria-hidden />
            Impersonate
          </Button>
        )}
        <Button size="sm" onClick={() => signOut.mutate()} disabled={signOut.isPending}>
          <LogOut size={14} strokeWidth={1.5} aria-hidden />
          Sign out everywhere
        </Button>
        <Button size="sm" onClick={() => setDialog('password')}>
          <KeyRound size={14} strokeWidth={1.5} aria-hidden />
          New password
        </Button>
        {user.mfa_enabled && !self ? (
          <Button size="sm" onClick={() => resetMfa.mutate()} disabled={resetMfa.isPending}>
            <ShieldOff size={14} strokeWidth={1.5} aria-hidden />
            Reset two-factor
          </Button>
        ) : null}
        {self ? null : (
          <Button size="sm" variant={disabled ? 'outline' : 'danger'} onClick={() => update.mutate({ disabled: !disabled })} disabled={update.isPending}>
            {disabled ? <UserCheck size={14} strokeWidth={1.5} aria-hidden /> : <UserX size={14} strokeWidth={1.5} aria-hidden />}
            {disabled ? 'Enable' : 'Disable'}
          </Button>
        )}
        {self ? null : (
          <Button size="sm" variant="danger" onClick={() => setDialog('delete')}>
            <Trash2 size={14} strokeWidth={1.5} aria-hidden />
            Delete
          </Button>
        )}
      </div>
      <div role="alert" className="mt-2 min-h-5 text-sm text-alert-soft">
        {failure ? message(failure, 'Not changed') : ''}
      </div>

      <div className="mb-2 mt-3 flex items-center justify-between">
        <SectionTitle>Activity</SectionTitle>
        <Link to="/events" search={{ show: 'audit', q: user.username }} className="font-mono text-xs text-soft hover:text-text hover:underline">
          all in events
        </Link>
      </div>
      {entries.length === 0 ? <div className="font-mono text-xs text-muted">nothing recorded</div> : null}
      {entries.slice(0, 12).map((entry) => (
        <div key={entry.seq} className="flex h-8 items-center gap-3 border-b border-hairline font-mono text-xs">
          <span className="w-[52px] shrink-0 text-muted">{ago(entry.timestamp, now)}</span>
          <span className="min-w-0 flex-1 truncate" style={{ color: auditTone(entry.action) }}>
            {entry.action}
          </span>
          <span className="max-w-[45%] truncate text-muted">{entry.target ?? ''}</span>
        </div>
      ))}

      {dialog === 'password' ? <NewPassword user={user} self={self} onClose={() => setDialog(null)} /> : null}
      <Dialog open={dialog === 'delete'} onOpenChange={(open) => setDialog(open ? 'delete' : null)} title={`Delete ${user.username}`}>
        <Button variant="danger" className="w-full" onClick={() => remove.mutate()} disabled={remove.isPending}>
          Delete the account, its API keys and its recovery codes
        </Button>
      </Dialog>
    </div>
  )
}

export function Users() {
  const search = route.useSearch()
  const navigate = route.useNavigate()
  const session = useSession((state) => state.session)
  const admin = isAdmin(session)
  const now = useNow(10_000)
  const narrow = useMedia('(max-width: 860px)')
  const side = useCollapsible(STRIP_SIZE)
  const range: Range = search.range ?? '24h'
  const [adding, setAdding] = useState(false)
  const { data: users } = useQuery({ queryKey: ['users'], queryFn: api.users, enabled: admin })
  const { data: audit } = useQuery({ queryKey: ['audit', 'accounts'], queryFn: () => api.audit(500, 0), enabled: admin, refetchInterval: 30_000 })

  if (!admin) return <Empty title="Accounts are managed by admins" />

  const seconds = RANGES.find((option) => option.id === range)!.seconds
  const from = now - seconds
  const entriesOf = (user: UserSummary) => (audit?.entries ?? []).filter((entry) => entry.actor_id === user.id)
  const list = users ?? []
  const selected = list.find((user) => user.id === search.user)
  const { collapsed, toggle } = side

  return (
    <div className="absolute inset-0 flex flex-col gap-3 overflow-hidden px-6 pb-5 pt-4">
      <PageHeader title="Users" meta={`${list.length} accounts · ${list.filter((user) => user.role === 'admin').length} admins`}>
        <Button variant="primary" size="sm" onClick={() => setAdding(true)}>
          <Plus size={15} strokeWidth={2} aria-hidden />
          User
        </Button>
      </PageHeader>

      <div className="min-h-0 flex-1">
        <Split id={narrow ? 'users-narrow' : 'users'} orientation={narrow ? 'vertical' : 'horizontal'}>
          <Panel id="lanes" minSize={320}>
            <div className="@container flex h-full flex-col overflow-hidden rounded-card border border-line bg-surface">
              <div className={cn(GRID, 'h-10 shrink-0 border-b border-line px-3 font-display text-[11px] uppercase tracking-wider text-muted')}>
                <span />
                <span>Account</span>
                <span className={WIDE}>Role</span>
                <span className={WIDE}>2FA</span>
                <span className="relative flex h-full items-center justify-end font-mono normal-case tracking-normal text-faint">
                  {TICKS.slice(0, -1).map((tick) => (
                    <span key={tick} className={cn('absolute pl-1', tick !== 0 && 'hidden @[620px]:inline')} style={{ left: `${tick * 100}%` }}>
                      {span(seconds * (1 - tick))}
                    </span>
                  ))}
                  <Segmented
                    label="Activity range"
                    value={range}
                    options={RANGES}
                    onChange={(next) => void navigate({ search: (previous) => ({ ...previous, range: next === '24h' ? undefined : next }), replace: true })}
                    className="[&>button]:h-6 [&>button]:px-2 [&>button]:text-[11px]"
                  />
                </span>
                <span className="text-right">Acts</span>
              </div>
              <div className="min-h-0 flex-1 overflow-y-auto">
                {list.map((user) => {
                  const entries = entriesOf(user).filter((entry) => entry.timestamp >= from)
                  const picked = user.id === selected?.id
                  return (
                    <button
                      key={user.id}
                      type="button"
                      aria-pressed={picked}
                      onClick={() => {
                        void navigate({ search: (previous) => ({ ...previous, user: user.id }), replace: true })
                        if (collapsed) toggle()
                      }}
                      className={cn(
                        GRID,
                        'min-h-[52px] w-full border-b border-hairline px-3 text-left hover:bg-raised',
                        picked && 'bg-selected hover:bg-selected',
                        user.disabled_at != null && 'opacity-55',
                      )}
                    >
                      <Avatar user={user} />
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-[13px] text-text">{user.username}</span>
                        <span className="block truncate font-mono text-[11px] text-muted">
                          {user.last_login_at ? `signed in ${ago(user.last_login_at, now)} ago` : 'never signed in'}
                        </span>
                      </span>
                      <span className={WIDE}>
                        <Chip tone={user.role === 'admin' ? 'accent' : 'neutral'}>{user.role === 'admin' ? 'admin' : 'read only'}</Chip>
                      </span>
                      <span className={cn(WIDE, 'font-mono text-[11px]', user.mfa_enabled ? 'text-soft' : 'text-warn')} title={user.mfa_enabled ? 'two-factor on' : 'two-factor off'}>
                        <StateDot state={user.mfa_enabled ? 'shell' : 'suspect'} className="mr-1.5 align-middle" />
                        {user.mfa_enabled ? 'on' : 'off'}
                      </span>
                      <Lane entries={entries} from={from} to={now} />
                      <span className={cn('text-right font-mono text-xs', entries.length > 0 ? 'text-soft' : 'text-faint')}>{entries.length}</span>
                    </button>
                  )
                })}
              </div>
            </div>
          </Panel>
          <Handle orientation={narrow ? 'vertical' : 'horizontal'} />
          <Panel
            id="account"
            defaultSize={narrow ? 320 : 400}
            minSize={narrow ? 200 : 320}
            maxSize={620}
            collapsible
            collapsedSize={STRIP_SIZE}
            panelRef={side.panelRef}
            onResize={side.onResize}
          >
            {collapsed ? (
              <PaneStrip
                label="Account"
                icon={<PanelRight size={18} strokeWidth={1.5} aria-hidden />}
                onOpen={toggle}
                orientation={narrow ? 'vertical' : 'horizontal'}
              />
            ) : (
              <aside aria-label="Account" className="relative h-full overflow-y-auto rounded-card border border-line bg-surface p-[18px]">
                <CollapseToggle collapsed={false} onToggle={toggle} label="account" flip className="absolute right-3 top-[18px] z-10" />
                {selected ? (
                  <UserSheet
                    key={selected.id}
                    user={selected}
                    self={selected.username === session?.username}
                    entries={entriesOf(selected)}
                    now={now}
                  />
                ) : (
                  <div className="font-mono text-xs text-muted">select an account</div>
                )}
              </aside>
            )}
          </Panel>
        </Split>
      </div>

      <NewUser open={adding} onOpenChange={setAdding} />
    </div>
  )
}
