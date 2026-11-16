import type { Proc } from './process-tree'

export type Level = 'high' | 'medium'
export type Finding = { rule: string; title: string; technique: string; level: Level }

type Rule = Finding & { test: (proc: Proc, name: string, command: string) => boolean }

const OFFICE = new Set([
  'winword.exe',
  'excel.exe',
  'powerpnt.exe',
  'outlook.exe',
  'onenote.exe',
  'msaccess.exe',
  'mspub.exe',
  'visio.exe',
  'acrord32.exe',
  'acrobat.exe',
  'soffice.bin',
  'microsoft word',
  'microsoft excel',
  'microsoft powerpoint',
  'microsoft outlook',
])
const SHELLS = new Set(['powershell.exe', 'pwsh.exe', 'pwsh', 'cmd.exe', 'wscript.exe', 'cscript.exe', 'bash', 'sh', 'zsh', 'dash', 'fish', 'osascript'])
const PROXIES = new Set([
  'rundll32.exe',
  'regsvr32.exe',
  'mshta.exe',
  'certutil.exe',
  'bitsadmin.exe',
  'msiexec.exe',
  'installutil.exe',
  'wmic.exe',
  'cmstp.exe',
  'odbcconf.exe',
])
const SERVERS = new Set([
  'w3wp.exe',
  'sqlservr.exe',
  'httpd',
  'apache2',
  'nginx',
  'php-fpm',
  'postgres',
  'mysqld',
  'mariadbd',
  'redis-server',
  'mongod',
])

const WRITABLE = /\\users\\public\\|\\appdata\\local\\temp\\|\\windows\\temp\\|\\downloads\\|^\/tmp\/|\s\/tmp\/|\/dev\/shm\/|\/var\/tmp\/|\/downloads\//i
const DROPPED = /\.(dll|exe|sys|scr|ps1|vbs|jse?|bat|cmd|hta|lnk|so|dylib|sh|elf|jar)$/i
const ENCODED = /\s-e(c|nc|nco\w*)?\s+[a-z0-9+/=]{8,}|frombase64string/i
const HIDDEN = /\s-w(in|indowstyle)?\s+h(idden)?\b/i
const REVERSE = /\/dev\/(tcp|udp)\/|\bn(c|cat)\b.*\s-e\s|\bbash\s+-i\b|\bsocat\b.*\bexec\b|\bmkfifo\b.*\bn(c|cat)\b/i
const FETCH_AND_RUN =
  /\b(curl|wget)\b[^|]*\|\s*(ba|z|da)?sh\b|\biex\b|invoke-expression|downloadstring|certutil(\.exe)?\s.*-urlcache|bitsadmin(\.exe)?\s.*\/transfer/i

const RULES: Rule[] = [
  {
    rule: 'office-child',
    title: 'Office application started a script host',
    technique: 'T1204.002',
    level: 'high',
    test: (proc, name) => (SHELLS.has(name) || PROXIES.has(name)) && proc.parent !== null && OFFICE.has(proc.parent.name.toLowerCase()),
  },
  {
    rule: 'server-child',
    title: 'Server process started a shell',
    technique: 'T1505.003',
    level: 'high',
    test: (proc, name) => SHELLS.has(name) && proc.parent !== null && SERVERS.has(proc.parent.name.toLowerCase()),
  },
  {
    rule: 'encoded-command',
    title: 'Encoded PowerShell command',
    technique: 'T1059.001',
    level: 'high',
    test: (_, name, command) => (name === 'powershell.exe' || name === 'pwsh.exe' || name === 'pwsh') && ENCODED.test(command),
  },
  {
    rule: 'reverse-shell',
    title: 'Shell wired to a socket',
    technique: 'T1059.004',
    level: 'high',
    test: (_, __, command) => REVERSE.test(command),
  },
  {
    rule: 'fetch-and-run',
    title: 'Download piped into execution',
    technique: 'T1105',
    level: 'high',
    test: (_, __, command) => FETCH_AND_RUN.test(command),
  },
  {
    rule: 'proxy-network',
    title: 'System binary reached the network',
    technique: 'T1218',
    level: 'high',
    test: (proc, name) => PROXIES.has(name) && proc.connections.length > 0,
  },
  {
    rule: 'proxy-loads-writable',
    title: 'System binary loaded code from a user-writable folder',
    technique: 'T1218.011',
    level: 'high',
    test: (_, name, command) => PROXIES.has(name) && WRITABLE.test(command.slice(command.indexOf(' ') + 1)),
  },
  {
    rule: 'writable-image',
    title: 'Runs from a user-writable folder',
    technique: 'T1204.002',
    level: 'high',
    test: (proc) => WRITABLE.test(proc.path),
  },
  {
    rule: 'drops-executable',
    title: 'Script host wrote an executable file',
    technique: 'T1105',
    level: 'high',
    test: (proc, name) =>
      SHELLS.has(name) && proc.files.some((file) => file.action !== 'Read' && file.action !== 'Delete' && DROPPED.test(file.path)),
  },
  {
    rule: 'hidden-window',
    title: 'Hidden window',
    technique: 'T1564.003',
    level: 'medium',
    test: (_, name, command) => SHELLS.has(name) && HIDDEN.test(command),
  },
  {
    rule: 'shell-network',
    title: 'Shell with an outbound connection',
    technique: 'T1071',
    level: 'medium',
    test: (proc, name) => SHELLS.has(name) && proc.connections.length > 0,
  },
]

export function detect(proc: Proc): Finding[] {
  const name = proc.name.toLowerCase()
  const found: Finding[] = []
  for (const { test, ...finding } of RULES) {
    if (test(proc, name, proc.command)) found.push(finding)
  }
  return found
}
