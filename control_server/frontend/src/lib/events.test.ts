import { describe, expect, it } from 'vitest'
import { auditEvent, CATEGORIES, categoryOf, detectionOf, eventData, incidentTitle, summarize, typesOf } from './events'

describe('event categories', () => {
  it('assigns every known event type to exactly one category', () => {
    const all = CATEGORIES.flatMap((category) => category.types)
    expect(new Set(all).size).toBe(all.length)
    expect(categoryOf('incident_opened').id).toBe('incident')
    expect(categoryOf('shell_command_executed').id).toBe('shell')
    expect(categoryOf('heartbeat').id).toBe('heartbeat')
  })

  it('files unknown event types under lifecycle instead of dropping them', () => {
    expect(categoryOf('brand_new_event').id).toBe('lifecycle')
  })

  it('expands categories into the event types the API filters on', () => {
    expect(typesOf(['incident', 'upgrade'])).toEqual(['incident_opened', 'incident_closed', 'detection', 'upgrade'])
    expect(typesOf([])).toEqual([])
  })
})

describe('eventData', () => {
  it('parses object payloads and survives anything else', () => {
    expect(eventData({ data: '{"reason":"ServiceStop"}' })).toEqual({ reason: 'ServiceStop' })
    expect(eventData({ data: 'not json' })).toEqual({})
    expect(eventData({ data: '[1,2]' })).toEqual({})
  })
})

describe('summarize', () => {
  it('shows the field an analyst needs per event type', () => {
    expect(summarize({ event_type: 'agent_stopping', data: '{"reason":"ServiceStop"}' })).toBe('ServiceStop')
    expect(summarize({ event_type: 'incident_opened', data: '{"incident_type":"replay"}' })).toBe('replay')
    expect(summarize({ event_type: 'shell_command_queued', data: '{"command_text":"whoami"}' })).toBe('whoami')
    expect(summarize({ event_type: 'shell_command_executed', data: '{"exit_code":1,"execution_time_ms":42}' })).toBe(
      'exit 1 · 42 ms',
    )
    expect(summarize({ event_type: 'network', data: '{"action":"Connect","dest_ip":"10.0.0.9","dest_port":443}' })).toBe(
      'Connect 10.0.0.9:443',
    )
  })

  it('stays empty for heartbeats and for payloads it cannot read', () => {
    expect(summarize({ event_type: 'heartbeat', data: '{"timestamp":1}' })).toBe('')
    expect(summarize({ event_type: 'agent_stopping', data: 'broken' })).toBe('')
  })
})

describe('incident titles', () => {
  const tamper = (incident_type: string) => ({ incident_type, evidence: '{}' })
  const detection = {
    incident_type: 'detection.office-child',
    evidence: JSON.stringify({
      rule: 'office-child',
      title: 'Office application started a script host',
      technique: 'T1204.002',
      pid: 2600,
      started_at: 1700000900,
      image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
    }),
  }

  it('names the known tamper incidents and passes unknown ones through', () => {
    expect(incidentTitle(tamper('service_stopped'))).toBe('Service stopped, system running')
    expect(incidentTitle(tamper('future_type'))).toBe('future_type')
    expect(detectionOf(tamper('replay'))).toBeNull()
  })

  it('reads a detection from its evidence, with the key of the process it is about', () => {
    expect(incidentTitle(detection)).toBe('Office application started a script host')
    expect(detectionOf(detection)).toEqual({
      title: 'Office application started a script host',
      technique: 'T1204.002',
      image: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
      processKey: '2600@1700000900',
      autostart: null,
    })
  })

  it('reads a finding about an autostart item as the item, not a process', () => {
    const planted = {
      incident_type: 'detection.autostart-fetch',
      evidence: JSON.stringify({ title: 'Autostart item downloads and runs code', technique: 'T1053.003', pid: 0, started_at: 500, image: '/etc/cron.d/sysupdate', subject: 'sysupdate', autostart: 'cron' }),
    }
    expect(detectionOf(planted)?.autostart).toBe('sysupdate')
  })

  it('summarises a detection event by what fired and where', () => {
    expect(categoryOf('detection').id).toBe('incident')
    expect(summarize({ event_type: 'detection', data: detection.evidence })).toBe('Office application started a script host · powershell.exe')
  })
})

describe('audit entries as events', () => {
  const entry = {
    seq: 41,
    timestamp: 1700000000,
    actor_id: 'user-1',
    actor: 'tester',
    action: 'user.disable',
    target: 'user-2',
    detail: '{"username":"reader"}',
    prev_hash: 'aa',
    hash: 'bb',
  }

  it('become rows in the audit category that keep their hashes', () => {
    const event = auditEvent(entry)
    expect(event.id).toBe('audit:41')
    expect(categoryOf(event.event_type).id).toBe('audit')
    expect(summarize(event)).toBe('user.disable → user-2')
    expect(eventData(event)).toMatchObject({ actor: 'tester', hash: 'bb', prev_hash: 'aa', detail: { username: 'reader' } })
  })

  it('summarise to the action alone when there is no target', () => {
    expect(summarize(auditEvent({ ...entry, action: 'login', target: null }))).toBe('login')
  })
})
