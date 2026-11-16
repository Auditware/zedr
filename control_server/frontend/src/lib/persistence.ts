import type { ApiEvent } from './api'
import { eventData } from './events'

type Change = 'Added' | 'Changed' | 'Removed'

type AutostartFinding = { title: string; technique: string; high: boolean }

export type AutostartItem = {
  key: string
  kind: string
  name: string
  path: string
  command: string
  user: string
  enabled: boolean
  hash: string | null
  change: Change | null
  changedAt: number | null
  seenAt: number
  finding: AutostartFinding | null
}

export const KIND_ORDER = [
  'ld_preload',
  'authorized_key',
  'cron',
  'scheduled_task',
  'systemd_timer',
  'systemd_unit',
  'launch_daemon',
  'windows_service',
  'launch_agent',
  'run_key',
  'startup_folder',
  'shell_profile',
  'rc_local',
  'init_script',
]

export const KIND_LABEL: Record<string, string> = {
  ld_preload: 'Preloaded libraries',
  authorized_key: 'SSH keys',
  cron: 'Cron',
  systemd_timer: 'systemd timers',
  systemd_unit: 'systemd units',
  shell_profile: 'Shell profiles',
  rc_local: 'rc.local',
  init_script: 'Init scripts',
  launch_daemon: 'Launch daemons',
  launch_agent: 'Launch agents',
  run_key: 'Run keys',
  windows_service: 'Windows services',
  scheduled_task: 'Scheduled tasks',
  startup_folder: 'Startup folders',
}

export type Moment = 'boot' | 'schedule' | 'signin' | 'remote' | 'program'

export const MOMENTS: { id: Moment; label: string; short: string; kinds: string[] }[] = [
  { id: 'boot', label: 'At boot', short: 'Boot', kinds: ['systemd_unit', 'rc_local', 'init_script', 'launch_daemon', 'windows_service'] },
  { id: 'schedule', label: 'On a schedule', short: 'Timed', kinds: ['systemd_timer', 'cron', 'scheduled_task'] },
  { id: 'signin', label: 'At sign-in', short: 'Sign-in', kinds: ['shell_profile', 'launch_agent', 'run_key', 'startup_folder'] },
  { id: 'remote', label: 'Remote access', short: 'Remote', kinds: ['authorized_key'] },
  { id: 'program', label: 'In every program', short: 'Preload', kinds: ['ld_preload'] },
]

export function momentOf(kind: string): Moment | null {
  return MOMENTS.find((moment) => moment.kinds.includes(kind))?.id ?? null
}

export type ItemState = 'flagged' | 'noted' | 'changed' | 'removed' | 'plain'

export function itemState(item: AutostartItem): ItemState {
  if (item.finding?.high) return 'flagged'
  if (item.finding) return 'noted'
  if (item.change === 'Removed') return 'removed'
  return item.change ? 'changed' : 'plain'
}

function text(value: unknown): string {
  return typeof value === 'string' ? value : ''
}

function itemKey(kind: string, path: string, name: string): string {
  return `${kind}|${path}|${name}`
}

export function buildAutostart(inventory: ApiEvent[], detections: ApiEvent[]): AutostartItem[] {
  const items = new Map<string, AutostartItem>()
  const ordered = inventory.filter((event) => event.event_type === 'persistence').sort((a, b) => a.timestamp - b.timestamp)
  for (const event of ordered) {
    const data = eventData(event)
    const key = itemKey(text(data.kind), text(data.path), text(data.name))
    const action = text(data.action)
    const known = items.get(key)
    const changed = action === 'Added' || action === 'Changed' || action === 'Removed'
    items.set(key, {
      key,
      kind: text(data.kind),
      name: text(data.name),
      path: text(data.path),
      command: text(data.command),
      user: text(data.user),
      enabled: data.enabled === true,
      hash: typeof data.hash === 'string' ? data.hash : null,
      change: changed ? action : (known?.change ?? null),
      changedAt: changed ? event.timestamp : (known?.changedAt ?? null),
      seenAt: event.timestamp,
      finding: null,
    })
  }

  for (const event of detections) {
    if (event.event_type !== 'detection') continue
    const data = eventData(event)
    if (typeof data.autostart !== 'string') continue
    const item = items.get(itemKey(data.autostart, text(data.image), text(data.subject)))
    if (!item || item.change === 'Removed') continue
    const high = data.level === 'high'
    if (!item.finding || (high && !item.finding.high)) item.finding = { title: text(data.title), technique: text(data.technique), high }
  }

  const rank = (item: AutostartItem) => (item.finding?.high ? 0 : item.finding ? 1 : item.change ? 2 : 3)
  return [...items.values()].sort(
    (a, b) =>
      rank(a) - rank(b) ||
      (b.changedAt ?? 0) - (a.changedAt ?? 0) ||
      KIND_ORDER.indexOf(a.kind) - KIND_ORDER.indexOf(b.kind) ||
      a.name.localeCompare(b.name),
  )
}

export function matchesAutostart(item: AutostartItem, find: string): boolean {
  const needle = find.trim().toLowerCase()
  if (!needle) return true
  return [item.name, item.command, item.path, item.user, item.kind].some((field) => field.toLowerCase().includes(needle))
}
