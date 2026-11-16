import { createRootRoute, createRoute, createRouter, Outlet, redirect } from '@tanstack/react-router'
import { AppShell } from '@/components/shell/AppShell'
import { useSession } from '@/lib/auth'
import { RANGES, type Range } from '@/lib/lanes'
import type { GroupBy } from '@/lib/map-layout'
import { MOMENTS, type Moment } from '@/lib/persistence'
import type { Focus } from '@/lib/process-tree'
import { Events } from '@/pages/Events'
import { Hunt } from '@/pages/Hunt'
import { Endpoints } from '@/pages/Endpoints'
import { Installers } from '@/pages/Installers'
import { Login } from '@/pages/Login'
import { Settings } from '@/pages/Settings'
import { Shell } from '@/pages/Shell'
import { Users } from '@/pages/Users'

function text(value: unknown): string | undefined {
  return typeof value === 'string' && value.length > 0 ? value : undefined
}

const GROUPS: GroupBy[] = ['subnet', 'os', 'version', 'liveness']
const LENSES = ['processes', 'network', 'files', 'apps', 'persistence', 'agent'] as const
const FOCUSES: Focus[] = ['all', 'notable']

export type EndpointsSearch = {
  host?: string
  group?: GroupBy
  pick?: string
  view?: (typeof LENSES)[number]
  proc?: string
  item?: string
  when?: Moment
  layout?: 'list'
  focus?: Focus
  find?: string
  cam?: string
  t?: string
}

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
  component: AppShell,
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
  component: Endpoints,
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
    when: MOMENTS.find((moment) => moment.id === search.when)?.id,
    cam: text(search.cam),
    t: text(search.t),
  }),
})

const eventsRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/events',
  component: Events,
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
  component: Hunt,
  validateSearch: (search: Record<string, unknown>): { q?: string; host?: string } => ({ q: text(search.q), host: text(search.host) }),
})

const shellRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/shell',
  component: Shell,
  validateSearch: (search: Record<string, unknown>): { session?: string; agent?: string } => ({
    session: text(search.session),
    agent: text(search.agent),
  }),
})

const installersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/installers',
  component: Installers,
  validateSearch: (search: Record<string, unknown>): { show?: string } => ({ show: text(search.show) }),
})
const usersRoute = createRoute({
  getParentRoute: () => appRoute,
  path: '/users',
  component: Users,
  validateSearch: (search: Record<string, unknown>): { user?: string; range?: '7d' } => ({
    user: text(search.user),
    range: search.range === '7d' ? '7d' : undefined,
  }),
})
const settingsRoute = createRoute({ getParentRoute: () => appRoute, path: '/settings', component: Settings })

const routeTree = rootRoute.addChildren([
  loginRoute,
  appRoute.addChildren([
    indexRoute,
    endpointsRoute,
    eventsRoute,
    huntRoute,
    shellRoute,
    installersRoute,
    usersRoute,
    settingsRoute,
  ]),
])

export const router = createRouter({ routeTree, defaultPreload: false })

declare module '@tanstack/react-router' {
  interface Register {
    router: typeof router
  }
}
