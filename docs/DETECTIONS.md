This file documents the agent's detection techniques per operating system

## MacOS

The macOS agent collects the same kinds of telemetry as the Linux agent, through the process interfaces of the macOS kernel, and seals and judges it with the same runtime and the same rules. The control server reads an event only when a rule opened it ([ADR 031](./adr/031-sealed-telemetry-opened-by-proven-rules.md)). The agent reads everything itself, it starts no helper program.

### Collected

- [x] Process inventory: every running process at agent start, with pid, parent pid, user, executable path, command line and start time, read with `proc_listallpids`, `proc_pidinfo`, `proc_pidpath` and the `KERN_PROCARGS2` sysctl. Zombies and the kernel task are left out, a command line is cut at 4 KiB like on Linux
- [x] Process start and end: a poll every five seconds reports processes that appeared and processes that are gone
- [x] Image change: a process that ran `exec` on another program is reported with its new executable and command line
- [x] Outbound TCP connections per process, over IPv4 and IPv6: destination address and port, the process that holds the socket and its executable, read from the socket descriptors of every process (`PROC_PIDLISTFDS`, `PROC_PIDFDSOCKETINFO`). Listening sockets, accepted connections and sockets that are half open, closed or in time-wait are left out
- [ ] Processes and connections that live shorter than the poll interval
- [ ] An `exec` of the program a process already runs, the image is told apart by its executable path only
- [ ] Listening sockets, UDP, DNS lookups, bytes per connection
- [ ] File events, EndpointSecurity
- [x] Persistence inventory: launch daemons in `/Library/LaunchDaemons`, launch agents in `/Library/LaunchAgents` and in every `~/Library/LaunchAgents`, from definitions in XML or binary form, with the label, the program and its arguments, the user the job runs as, whether launchd starts it and a hash of the definition. Also `/etc/crontab` and the user crontabs in `/usr/lib/cron/tabs`, shell profiles (`/etc/zshenv`, `/etc/zprofile`, `/etc/zshrc`, `/etc/profile`, `/etc/bashrc` and `.zshenv`, `.zprofile`, `.zshrc`, `.bashrc`, `.bash_profile`, `.profile` in every home) and `authorized_keys`, for root in `/var/root` and for every account with a home in `/Users` but `Shared`
- [x] Persistence changes: a read every minute reports what was added, changed or removed since the last one
- [ ] Persistence that lives elsewhere: `/System/Library`, which is on the sealed system volume and holds Apple's own jobs, login items and the jobs apps register with `SMAppService` in the Background Task Management database, the overrides of `launchctl enable` and `disable`, `periodic` scripts, `at` jobs, kernel and system extensions, authorization plugins, configuration profiles
- [x] Installed packages: Homebrew formulas and casks under `/opt/homebrew` and `/usr/local`, each with its newest installed version, application bundles in `/Applications`, `/Applications/Utilities` and every `~/Applications` with the version from their `Info.plist` and the architectures of their executable, and installer receipts in `/var/db/receipts`. They are read every five minutes and reported like on Linux, and no rule opens a package event
- [ ] Bundles in subfolders of `/Applications` or anywhere else, older Homebrew versions still on disk, packages of languages such as pip and npm, MacPorts
- [ ] Resource use per process, logins

As root the agent reads every process and every socket. Run as another user it still lists every process, but the sockets of its own user only.

### Rules

The rules are those of the Linux section, one rule set for every platform. An autostart rule that fires on a launch daemon names T1543.004, on a launch agent T1543.001.

### Proving

No prover is built for macOS yet. The installer goes on without one, the endpoint seals and releases its windows and the console shows them as not proven.

## Windows

The Windows agent collects the same kinds of telemetry as the Linux agent and seals and judges it with the same runtime and the same rules. The control server reads an event only when a rule opened it ([ADR 031](./adr/031-sealed-telemetry-opened-by-proven-rules.md)). The agent reads everything through system calls and the registry itself, it starts no helper program. Type-checked and unit-tested on another platform, not yet run on Windows.

### Collected

- [x] Process inventory: every running process at agent start, with pid, parent pid, session, executable path, command line and start time. The list comes from a Toolhelp snapshot, the path from `QueryFullProcessImageNameW`, the start from `GetProcessTimes` and the command line from `NtQueryInformationProcess`, cut at 4 KiB and split by the rules of `CommandLineToArgvW`. The user field holds the session id, 0 for services. A process that cannot be opened is listed with its image name from the snapshot only
- [x] Process start and end: a poll every five seconds reports processes that appeared and processes that are gone
- [x] Outbound TCP connections per process, over IPv4 and IPv6: destination address and port and the process that owns the connection, from `GetExtendedTcpTable`. Only established connections count. Connections to the machine itself and connections accepted on a port something listens on are left out
- [ ] Processes and connections that live shorter than the poll interval
- [ ] Listening sockets, UDP, DNS lookups, bytes per connection
- [ ] File and registry events, ETW
- [x] Persistence inventory, each item with the command it runs where it has one, the account, whether it is set to start, and a hash. Variables such as `%SystemRoot%` are written out, as are `\SystemRoot\` and `\??\` in driver paths
  - [x] `Run` and `RunOnce` values of the machine, in the native and the 32 bit registry view, and of every loaded user hive
  - [x] Services and drivers under `HKLM\SYSTEM\CurrentControlSet\Services` with their `ImagePath`, enabled when `Start` is boot, system or automatic
  - [x] Scheduled tasks: the definitions in `System32\Tasks`, one item per program the task starts, enabled as the task says, with the account of its principal. The hash is that of the definition
  - [x] Files in the common Startup folder and the Startup folder of every profile
  - The hash of a `Run` value or a service is that of the program it starts, found as `CreateProcess` would find it. Hashes are kept by path, size and modification time, and a file larger than 32 MiB is hashed by its first 32 MiB
- [x] Persistence changes: a read every minute reports what was added, changed or removed since the last one
- [ ] Persistence that lives elsewhere: the `ServiceDll` behind `svchost`, WMI subscriptions, `Winlogon` and `Image File Execution Options` keys, AppInit DLLs, COM hijacks, the shortcut target of a Startup folder file, the hives of users who are not signed in
- [x] Installed programs: name, version and architecture from the `Uninstall` keys of the machine in both views and of every loaded user hive, read every five minutes and reported like on Linux. No rule opens a package event
- [ ] Programs that register nothing in `Uninstall`, packages of Microsoft Store and winget, languages such as pip and npm

### Rules

The rules are those of the Linux section, one rule set for every platform.

## Linux

The Linux agent collects telemetry, seals it on the endpoint and judges it there. The control server reads an event only when a rule below opened it ([ADR 031](./adr/031-sealed-telemetry-opened-by-proven-rules.md)).

### Collected

- [x] Process inventory: every running process at agent start, with pid, parent pid, user, executable path, command line and start time, read from `/proc` ([ADR 020](./adr/020-polling-sensor-for-process-and-connection-telemetry.md))
- [x] Process start and end: a poll every five seconds reports processes that appeared and processes that are gone, which is enough to rebuild the process tree
- [x] Image change: a process that replaced its program with `exec` is reported with its new executable and command line
- [x] Outbound TCP connections per process: destination address and port, the process that holds the socket and its executable, across the network namespaces the agent can see
- [ ] Processes and connections that live shorter than the poll interval
- [ ] Listening sockets, UDP, DNS lookups, bytes per connection
- [ ] File events
- [x] Persistence inventory: systemd units and timers, cron entries and periodic scripts, shell profiles, authorized keys, preloaded libraries, `rc.local` and init scripts, each with the command it runs where it has one, the user, whether it is set to start, and a hash. Everything is listed when the agent starts ([ADR 022](./adr/022-persistence-inventory.md))
- [x] Persistence changes: a read every minute reports what was added, changed or removed since the last one
- [ ] Persistence that lives elsewhere: socket and path units, `at` jobs, udev rules, kernel modules, XDG autostart, other shells' startup files, keys named by `sshd_config`
- [x] Installed packages: name, version and architecture of every dpkg and apk package when the agent starts, then installs, upgrades with the version they replaced, and removals, read every five minutes ([ADR 023](./adr/023-package-inventory.md)). They are sealed and committed like every other event. No rule opens a package event, so the control server never reads one
- [ ] Installed packages on rpm hosts, packages of languages such as pip and npm, software copied in by hand
- [ ] Resource use per process, logins, applications in use: no event types yet, see the proposal in ADR 020

### Rules

The rules are the `rules` crate. The agent runs them as events are sealed, and the prover runs the same code inside the proof. A rule fires once per process or item. A high finding opens an incident, a medium one is recorded.

| Rule | Fires when | Technique | Level | Opens |
|---|---|---|---|---|
| `office-child` | an Office application starts a shell, a script host or a system binary that runs code for others | T1204.002 | high | the process and its parent |
| `server-child` | a web or database server starts a shell | T1505.003 | high | the process and its parent |
| `encoded-command` | PowerShell runs with an encoded command | T1059.001 | high | the process and its parent |
| `reverse-shell` | a command line wires a shell to a socket | T1059.004 | high | the process and its parent |
| `fetch-and-run` | a command line pipes a download into a shell or runs what it downloads | T1105 | high | the process and its parent |
| `proxy-network` | a system binary that can run code for others reaches the network | T1218 | high | the connection, the process and its parent |
| `proxy-loads-writable` | such a binary loads code from a user-writable folder | T1218.011 | high | the process and its parent |
| `writable-image` | a program runs from a temporary or download folder | T1204.002 | high | the process and its parent |
| `drops-executable` | a shell or script host writes an executable file | T1105 | high | the file event, the process and its parent |
| `hidden-window` | a shell or script host runs with a hidden window | T1564.003 | medium | the process and its parent |
| `shell-network` | a shell holds an outbound connection | T1071 | medium | the connection, the process and its parent |
| `autostart-fetch` | an autostart item downloads and runs code or opens a reverse shell | by kind of item | high | the autostart item |
| `autostart-writable` | an autostart item runs from a temporary or download folder | by kind of item | high | the autostart item |
| `preload-added` | a library is added to `ld.so.preload`, or the file changes | T1574.006 | high | the autostart item |
| `root-key-added` | an SSH key is added for root | T1098.004 | medium | the autostart item |
| `flagged-process-ended` | a process with a finding ends | none | info | the end of the process and the process |

The last rule is a follow-up, not a finding. Without it the control server would never learn that a process it was shown has ended.

Several rules name Windows programs. They are kept so that one rule set and one rule program cover every platform, and they stay silent on Linux.

### What proving costs

`zedr-prover bench <events>` proves a made-up workload of process starts, connections and process ends on the machine it runs on. Measured with the static arm64 prover in a Linux container on an Apple M4 Max with 14 cores, CPU only, while the machine was busy with other work, so the times are on the high side:

| One proof of 50 events | Segments | CPU time | Wall time | Peak memory | Receipt |
|---|---|---|---|---|---|
| One proof per segment of 2^18 cycles, the default | 5 | 16 min | 74 s | 2.7 GB | 1.3 MB |
| The same in segments of 2^17 | 13 | 37 min | 177 s | 1.4 GB | 3.1 MB |
| The same in one segment of 2^20 | 1 | 25 min | 126 s | 9.9 GB | 0.3 MB |
| Folded into one small receipt, segments of 2^18 | 5 | 47 min | 235 s | 2.5 GB | 0.2 MB |

- The rules take about 15,600 zkVM cycles for one event of this workload, and an empty window about 17,000.
- That is about 20 seconds of one core for every event. An endpoint that gives the prover four cores all the time covers about 700 events an hour.
- The control server verifies a receipt in well under a second for every segment and stores none.
- In the run of `make test-e2e-linux` on the same machine, the first three windows of a fresh Alpine container, about fifty events of processes, autostart items and packages, were proven on the endpoint and verified by the control server 192 seconds after the run began.
- The static prover uses its own allocator. With the one of musl the same proof spent more time waiting in the kernel than proving.

- [ ] Prove on a GPU, or hand the proving to a machine the owner of the endpoint runs
- [ ] Fewer cycles for every event: the tables of the patterns are paged into every segment, and the process table allocates
- [ ] Rules over file events, which no agent sends yet
- [ ] Suppression and exclusions, which have to be part of the proven rule program to mean anything
- [ ] Rules that read more than one epoch, rule state starts empty at every agent start
