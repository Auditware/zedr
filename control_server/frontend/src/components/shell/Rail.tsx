import { Link } from '@tanstack/react-router'
import { Crosshair, KeyRound, PanelLeftClose, PanelLeftOpen, SquareTerminal, UsersRound } from 'lucide-react'
import type { ReactNode } from 'react'
import { Tip } from '@/components/ui/bits'
import { isAdmin, useSession } from '@/lib/auth'
import { cn } from '@/lib/cn'
import { useIncidents, useMedia } from '@/lib/queries'
import { useUi } from '@/lib/ui'
import { Logo } from './Logo'
import { UserMenu } from './UserMenu'

const svg = {
  width: 20,
  height: 20,
  viewBox: '0 0 24 24',
  fill: 'none',
  stroke: 'currentColor',
  strokeWidth: 1.5,
  strokeLinecap: 'round',
  strokeLinejoin: 'round',
  'aria-hidden': true,
} as const

function MapIcon() {
  return (
    <svg {...svg}>
      <circle cx="7" cy="8" r="2.3" />
      <circle cx="16.5" cy="6.5" r="2.3" />
      <circle cx="17.5" cy="16" r="2.3" />
      <circle cx="8.5" cy="17.5" r="2.3" />
    </svg>
  )
}

function EventsIcon() {
  return (
    <svg {...svg}>
      <path d="M5 7h14" />
      <path d="M5 12h9" />
      <path d="M5 17h12" />
    </svg>
  )
}

const base =
  'relative flex h-10 shrink-0 items-center rounded-xl text-[13px] text-muted outline-none transition-colors hover:bg-row hover:text-text focus-visible:outline-2 focus-visible:outline-accent'
const current =
  'bg-raised text-accent-strong hover:bg-raised before:absolute before:inset-y-2.5 before:left-0 before:w-[3px] before:rounded-full before:bg-alert max-md:before:hidden'

const toggle = 'inline-flex h-8 w-8 shrink-0 items-center justify-center rounded-md text-muted hover:bg-row hover:text-text'

type ItemProps = { to: string; label: string; icon: ReactNode; badge?: number; wide: boolean }

function NavItem({ to, label, icon, badge, wide }: ItemProps) {
  const shape = wide ? 'w-full gap-3 px-3' : 'w-10 justify-center'
  const link = (
    <Link to={to} aria-label={label} className={cn(base, shape)} activeProps={{ className: cn(base, shape, current) }}>
      {icon}
      {wide ? <span className="truncate">{label}</span> : null}
      {badge ? (
        <span
          className={cn(
            'h-4 min-w-4 rounded-full bg-alert px-1 text-center font-mono text-[10px] font-medium leading-4 text-ink',
            wide ? 'ml-auto' : 'absolute -right-0.5 -top-0.5',
          )}
        >
          {badge}
        </span>
      ) : null}
    </Link>
  )
  return wide ? link : <Tip label={label}>{link}</Tip>
}

export function Rail() {
  const railOpen = useUi((state) => state.railOpen)
  const toggleRail = useUi((state) => state.toggleRail)
  const admin = isAdmin(useSession((state) => state.session))
  const small = useMedia('(max-width: 767px)')
  const wide = railOpen && !small
  const { data: incidents } = useIncidents()
  const open = new Set(incidents?.filter((incident) => incident.closed_at == null).map((incident) => incident.agent_id)).size
  const size = 20

  return (
    <nav
      aria-label="Pages"
      className={cn(
        'flex shrink-0 flex-col gap-1 border-r border-hairline bg-rail py-3 transition-[width] duration-200',
        wide ? 'w-[196px] px-2.5' : 'w-[60px] items-center px-0',
        'max-md:w-full max-md:flex-row max-md:items-center max-md:overflow-x-auto max-md:border-b max-md:border-r-0 max-md:px-3 max-md:py-2',
      )}
    >
      <div className={cn('mb-3 flex items-center max-md:mb-0 max-md:mr-2', wide ? 'h-9 justify-between' : 'flex-col gap-1')}>
        <Link to="/" aria-label="Home" className={cn(toggle, 'h-9 w-9 outline-none focus-visible:outline-2 focus-visible:outline-accent')}>
          <Logo />
        </Link>
        {wide ? (
          <Tip label="Collapse  ⌘B">
            <button type="button" onClick={toggleRail} aria-label="Collapse sidebar" aria-expanded className={toggle}>
              <PanelLeftClose size={17} strokeWidth={1.5} aria-hidden />
            </button>
          </Tip>
        ) : small ? null : (
          <Tip label="Expand  ⌘B">
            <button type="button" onClick={toggleRail} aria-label="Expand sidebar" aria-expanded={false} className={toggle}>
              <PanelLeftOpen size={17} strokeWidth={1.5} aria-hidden />
            </button>
          </Tip>
        )}
      </div>
      <NavItem to="/endpoints" label="Endpoints" icon={<MapIcon />} badge={open} wide={wide} />
      <NavItem to="/hunt" label="Hunt" icon={<Crosshair size={size} strokeWidth={1.5} aria-hidden />} wide={wide} />
      <NavItem to="/events" label="Events" icon={<EventsIcon />} wide={wide} />
      <NavItem to="/shell" label="Shell" icon={<SquareTerminal size={size} strokeWidth={1.5} aria-hidden />} wide={wide} />
      <NavItem to="/installers" label="Installers" icon={<KeyRound size={size} strokeWidth={1.5} aria-hidden />} wide={wide} />
      {admin ? <NavItem to="/users" label="Users" icon={<UsersRound size={size} strokeWidth={1.5} aria-hidden />} wide={wide} /> : null}
      <div className="flex-1" />
      <UserMenu wide={wide} side={small ? 'bottom' : 'right'} className={base} />
    </nav>
  )
}
