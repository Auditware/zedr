export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000)
}

export function span(seconds: number): string {
  const s = Math.max(0, Math.floor(seconds))
  if (s < 60) return `${s}s`
  if (s < 3600) return `${Math.floor(s / 60)}m`
  if (s < 86400) {
    const hours = Math.floor(s / 3600)
    const minutes = Math.floor((s % 3600) / 60)
    return minutes ? `${hours}h ${minutes}m` : `${hours}h`
  }
  return `${Math.floor(s / 86400)}d`
}

export function ago(timestamp: number, now: number = nowSeconds()): string {
  return span(now - timestamp)
}

function two(value: number): string {
  return value < 10 ? `0${value}` : `${value}`
}

export function clock(timestamp: number): string {
  const date = new Date(timestamp * 1000)
  return `${two(date.getHours())}:${two(date.getMinutes())}:${two(date.getSeconds())}`
}

export function dateTime(timestamp: number): string {
  const date = new Date(timestamp * 1000)
  return `${date.getFullYear()}-${two(date.getMonth() + 1)}-${two(date.getDate())} ${clock(timestamp)}`
}

export function shortId(id: string): string {
  return id.slice(0, 8)
}

export function shortHash(hash: string): string {
  return hash.length > 14 ? `${hash.slice(0, 8)}…${hash.slice(-4)}` : hash
}

export function subnet(ip: string | null | undefined): string {
  if (!ip) return 'no address'
  const parts = ip.split('.')
  return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}.0/24` : ip
}

export function bytes(count: number): string {
  if (count < 1024) return `${count} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = count / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value >= 100 ? Math.round(value) : value.toFixed(1)} ${units[unit]}`
}
