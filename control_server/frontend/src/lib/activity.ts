import { baseName, severity, type ProcessModel, type Proc, type Severity } from './process-tree'

export type ActivityLane = 'processes' | 'network' | 'files'
export type Period = [number, number]
export type Bin = { count: number; weight: number; names: string[] }
export type Mark = { time: number; key: string; severity: Severity; detail: string }
export type MarkGroup = { lane: ActivityLane; bin: number; severity: Severity; members: Mark[] }
export type Activity = { bins: Record<ActivityLane, Bin[]>; peaks: Record<ActivityLane, number>; marks: MarkGroup[] }

const LANES: ActivityLane[] = ['processes', 'network', 'files']
const NAMES_SHOWN = 3

export function binIndex(time: number, from: number, to: number, count: number): number | null {
  if (time < from || time > to || to <= from) return null
  return Math.min(count - 1, Math.floor(((time - from) / (to - from)) * count))
}

export function binPeriod(index: number, from: number, to: number, count: number): Period {
  const width = (to - from) / count
  return [Math.floor(from + index * width), Math.ceil(from + (index + 1) * width)]
}

export function inPeriod(proc: Proc, [from, to]: Period): boolean {
  const within = (time: number) => time >= from && time <= to
  return within(proc.start) || proc.connections.some((connection) => within(connection.time)) || proc.files.some((file) => within(file.time))
}

export function nextMember(group: MarkGroup, selectedKey: string | null): Mark {
  const keys = [...new Set(group.members.map((member) => member.key))]
  const next = keys[(keys.indexOf(selectedKey ?? '') + 1) % keys.length]!
  return group.members.find((member) => member.key === next)!
}

export function buildActivity(model: ProcessModel, from: number, to: number, count: number): Activity {
  const tallies = {} as Record<ActivityLane, { count: number; weight: number; names: Map<string, number> }[]>
  for (const lane of LANES) {
    tallies[lane] = Array.from({ length: count }, () => ({ count: 0, weight: 0, names: new Map<string, number>() }))
  }
  const groups = new Map<string, MarkGroup>()
  const mark = (lane: ActivityLane, member: Mark) => {
    const bin = binIndex(member.time, from, to, count)!
    const id = `${lane}:${bin}`
    const group = groups.get(id)
    if (!group) {
      groups.set(id, { lane, bin, severity: member.severity, members: [member] })
      return
    }
    group.members.push(member)
    if (member.severity === 'alert') group.severity = 'alert'
  }
  const add = (lane: ActivityLane, time: number, weight: number, name: string): boolean => {
    const index = binIndex(time, from, to, count)
    if (index === null) return false
    const bin = tallies[lane][index]!
    bin.count += 1
    bin.weight += weight
    bin.names.set(name, (bin.names.get(name) ?? 0) + 1)
    return true
  }

  for (const proc of model.all) {
    const level = severity(proc)
    if (add('processes', proc.start, 1, proc.name) && (level === 'alert' || level === 'warn')) {
      mark('processes', { time: proc.start, key: proc.key, severity: level, detail: proc.command || proc.name })
    }
    for (const connection of proc.connections) {
      const remote = `${connection.destIp}:${connection.destPort}`
      if (add('network', connection.time, connection.sent + connection.received, remote) && level === 'alert') {
        mark('network', { time: connection.time, key: proc.key, severity: 'alert', detail: `${proc.name} to ${remote}` })
      }
    }
    for (const file of proc.files) {
      if (add('files', file.time, 1, baseName(file.path)) && (level === 'alert' || level === 'warn')) {
        mark('files', { time: file.time, key: proc.key, severity: level, detail: `${proc.name} ${file.action} ${file.path}` })
      }
    }
  }

  const bins = {} as Record<ActivityLane, Bin[]>
  const peaks = {} as Record<ActivityLane, number>
  for (const lane of LANES) {
    bins[lane] = tallies[lane].map((tally) => ({
      count: tally.count,
      weight: tally.weight,
      names: [...tally.names]
        .sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))
        .slice(0, NAMES_SHOWN)
        .map(([name, times]) => (times > 1 ? `${name} ×${times}` : name)),
    }))
    peaks[lane] = Math.max(1, ...bins[lane].map((bin) => (lane === 'network' ? bin.weight : bin.count)))
  }
  for (const group of groups.values()) group.members.sort((a, b) => a.time - b.time)
  return { bins, peaks, marks: [...groups.values()] }
}
