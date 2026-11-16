import { createRootRoute, createRoute, createRouter, lazyRouteComponent, Outlet, redirect } from '@tanstack/react-router'
import { useSession } from '@/lib/auth'
import { RANGES, type Range } from '@/lib/lanes'
import type { GroupBy } from '@/lib/map-layout'
import { MOMENTS, type Moment } from '@/lib/persistence'
import type { Focus } from '@/lib/process-tree'
import { Login } from '@/pages/Login'

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

function index(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isInteger(value) && value >= 0 ? value : undefined
}

const GROUPS: GroupBy[] = ['subnet', 'os', 'version', 'liveness']
const LENSES = ['processes', 'network', 'files', 'persistence', 'sealed', 'agent'] as const
const FOCUSES: Focus[] = ['all', 'notable']

export type EndpointsSearch = {
  host?: string
  group?: GroupBy
  pick?: string
  view?: (typeof LENSES)[number]
  proc?: string
  item?: string
  win?: number
  when?: Moment
  layout?: 'list'
  focus?: Focus
  find?: string
  cam?: string
  t?: string
}

function Pending() {
  return (
    <div role="status" className="flex h-full items-center justify-center font-display text-lg text-soft">
      Loading
    </div>
  )
}

// Everything behind sign-in is one chunk: the pages share most of their code, and a chunk each costs a signed-in load a dozen more requests
const signedIn = () => import('@/console')

const rootRoute = createRootRoute({ component: Outlet })

const loginRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: '/login',
  component: Login,
  beforeLoad: () => {
    if (useSession.getState().session) throw redirect({ to: '/endpoints' })
  },
})

const appRoute = createRoute({
  getParentRoute: () => rootRoute,
  id: 'app',
  component: lazyRouteComponent(signedIn, 'AppShell'),
  beforeLoad: () => {
    if (!useSession.getState().session) throw redirect({ to: '/login' })
  },
})

const indexRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/',
  beforeLoad: () => {
    throw redirect({ to: '/endpoints' })
  },
})

const endpointsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/endpoints',
  component: lazyRouteComponent(signedIn, 'Endpoints'),
  validateSearch: (search: Record<string, unknown>): EndpointsSearch => ({
    host: text(search.host),
    group: GROUPS.find((group) => group === search.group),
    pick: text(search.pick),
    view: LENSES.find((lens) => lens === search.view),
    proc: text(search.proc),
    layout: search.layout === 'list' ? 'list' : undefined,
    focus: FOCUSES.find((focus) => focus === search.focus),
    find: text(search.find),
    item: text(search.item),
    win: index(search.win),
    when: MOMENTS.find((moment) => moment.id === search.when)?.id,
    cam: text(search.cam),
    t: text(search.t),
  }),
})

const eventsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/events',
  component: lazyRouteComponent(signedIn, 'Events'),
  validateSearch: (search: Record<string, unknown>): { agent?: string; show?: string; event?: string; q?: string; range?: Range; t?: string } => ({
    agent: text(search.agent),
    show: text(search.show),
    event: text(search.event),
    q: text(search.q),
    range: RANGES.find((range) => range.id === search.range)?.id,
    t: text(search.t),
  }),
})

const huntRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/hunt',
  component: lazyRouteComponent(signedIn, 'Hunt'),
  validateSearch: (search: Record<string, unknown>): { q?: string; host?: string } => ({ q: text(search.q), host: text(search.host) }),
})

const rulesRoute = createRoute({ getParentRoute: () => appRoute, path: '/rules', component: lazyRouteComponent(signedIn, 'Rules') })

const installersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/installers',
  component: lazyRouteComponent(signedIn, 'Installers'),
  validateSearch: (search: Record<string, unknown>): { show?: string } => ({ show: text(search.show) }),
})
const usersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/users',
  component: lazyRouteComponent(signedIn, 'Users'),
  validateSearch: (search: Record<string, unknown>): { user?: string; range?: '7d' } => ({
    user: text(search.user),
    range: search.range === '7d' ? '7d' : undefined,
  }),
})
const settingsRoute = createRoute({ getParentRoute: () => appRoute, path: '/settings', component: lazyRouteComponent(signedIn, 'Settings') })

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([
    indexRoute,
    endpointsRoute,
    eventsRoute,
    huntRoute,
    rulesRoute,
    installersRoute,
    usersRoute,
    settingsRoute,
  ]),
])

export const router = createRouter({
  routeTree,
  defaultPreload: false,
  defaultPendingComponent: Pending,
  // What was waited for shows as soon as it arrives, the router would otherwise hold the pending state for half a second
  defaultPendingMinMs: 0,
})

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
