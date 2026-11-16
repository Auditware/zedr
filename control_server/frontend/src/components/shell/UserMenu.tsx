import * as Menu from '@radix-ui/react-dropdown-menu'
import { useNavigate } from '@tanstack/react-router'
import { LogOut, SlidersHorizontal, Undo2 } from 'lucide-react'
import { useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { useLive } from '@/lib/live'

type Props = { wide: boolean; side: 'right' | 'bottom'; className: string }

const item =
  'flex h-9 cursor-pointer items-center gap-2.5 rounded-lg px-2.5 text-sm text-soft outline-none data-[highlighted]:bg-selected data-[highlighted]:text-accent-strong'

export function UserMenu({ wide, side, className }: Props) {
  const session = useSession((state) => state.session)
  const signOut = useSession((state) => state.signOut)
  const stopImpersonating = useSession((state) => state.stopImpersonating)
  const navigate = useNavigate()
  const connected = useLive((state) => state.connected)
  if (!session) return null
  const status = connected ? 'Live' : 'Offline'

  return (
    <Menu.Root>
      <Menu.Trigger asChild>
        <button
          type="button"
          aria-label={`Account ${session.username}, ${status.toLowerCase()}`}
          className={cn(className, wide ? 'h-12 w-full gap-3 px-2' : 'h-10 w-10 justify-center')}
        >
          <span className="relative flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-selected font-display text-xs font-semibold uppercase text-text">
            {session.username.slice(0, 1)}
            <span
              aria-hidden
              className={cn(
                'absolute -bottom-0.5 -right-0.5 h-2.5 w-2.5 rounded-full border-2 border-rail',
                connected ? 'animate-blink bg-accent' : 'bg-alert',
              )}
            />
          </span>
          {wide ? (
            <span className="min-w-0 flex-1 text-left leading-tight">
              <span className="block truncate text-[13px] text-text">{session.username}</span>
              <span className={cn('block text-[11px]', connected ? 'text-muted' : 'text-alert-soft')}>{status}</span>
            </span>
          ) : null}
        </button>
      </Menu.Trigger>
      <Menu.Portal>
        <Menu.Content
          side={side}
          align="end"
          sideOffset={8}
          className="z-50 min-w-48 rounded-xl border border-line-strong bg-raised p-1 shadow-lg"
        >
          <div className="px-2.5 py-2">
            <div className="truncate font-mono text-[13px] text-text">{session.username}</div>
            <div className="text-[11px] text-muted">
              {session.view ? `${session.role}, shown to ${session.view.admin.username}` : session.role} · {status.toLowerCase()}
            </div>
          </div>
          <Menu.Separator className="my-1 h-px bg-line" />
          {session.view ? (
            <Menu.Item onSelect={stopImpersonating} className={item}>
              <Undo2 size={15} strokeWidth={1.5} aria-hidden />
              Return to {session.view.admin.username}
            </Menu.Item>
          ) : null}
          <Menu.Item onSelect={() => void navigate({ to: '/settings' })} className={item}>
            <SlidersHorizontal size={15} strokeWidth={1.5} aria-hidden />
            Settings
          </Menu.Item>
          <Menu.Item onSelect={signOut} className={item}>
            <LogOut size={15} strokeWidth={1.5} aria-hidden />
            Sign out
          </Menu.Item>
        </Menu.Content>
      </Menu.Portal>
    </Menu.Root>
  )
}
