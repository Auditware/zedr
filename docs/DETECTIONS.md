This file documents the agent's detection techniques per operating system

## MacOS

## Windows

## Linux

The Linux agent collects telemetry and does not judge it yet. Nothing below raises an alert on its own ([ADR 020](./adr/020-polling-sensor-for-process-and-connection-telemetry.md)).

- [x] Process inventory: every running process at agent start, with pid, parent pid, user, executable path, command line and start time, read from `/proc`
- [x] Process start and end: a poll every five seconds reports processes that appeared and processes that are gone, which is enough to rebuild the process tree
- [x] Image change: a process that replaced its program with `exec` is reported with its new executable and command line
- [x] Outbound TCP connections per process: destination address and port, the process that holds the socket and its executable, across the network namespaces the agent can see
- [ ] Processes and connections that live shorter than the poll interval
- [ ] Listening sockets, UDP, DNS lookups, bytes per connection
- [ ] File events
- [x] Persistence inventory: systemd units and timers, cron entries and periodic scripts, shell profiles, authorized keys, preloaded libraries, `rc.local` and init scripts, each with the command it runs where it has one, the user, whether it is set to start, and a hash. Everything is listed when the agent starts ([ADR 022](./adr/022-persistence-inventory.md))
- [x] Persistence changes: a read every minute reports what was added, changed or removed since the last one
- [ ] Persistence that lives elsewhere: socket and path units, `at` jobs, udev rules, kernel modules, XDG autostart, other shells' startup files, keys named by `sshd_config`
- [x] Installed packages: name, version and architecture of every dpkg and apk package when the agent starts, then installs, upgrades with the version they replaced, and removals, read every five minutes ([ADR 023](./adr/023-package-inventory.md))
- [ ] Installed packages on rpm hosts, packages of languages such as pip and npm, software copied in by hand
- [ ] Resource use per process, logins, applications in use: no event types yet, see the proposal in ADR 020
- [ ] Rules, signatures or any other verdict on what is collected
