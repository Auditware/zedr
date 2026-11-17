This file documents the agent's technical capabilities per operating system

## Table of Contents

- [MacOS](#macos)
  - [Service Persistence](#service-persistence)
  - [libproc and sysctl](#libproc-and-sysctl)
  - [Property lists and inventory folders](#property-lists-and-inventory-folders)
  - [EndpointSecurity](#endpointsecurity)
  - [OpenBSM (audit subsystem)](#openbsm-audit-subsystem)
- [Windows](#windows)
  - [Service Persistence](#service-persistence-1)
  - [Win32 and the registry](#win32-and-the-registry)
  - [ETW (Event Tracing for Windows)](#etw-event-tracing-for-windows)
  - [WFP (Windows Filtering Platform)](#wfp-windows-filtering-platform)
  - [eBPF](#ebpf)
- [Linux](#linux)
  - [Service Persistence](#service-persistence-2)
  - [procfs](#procfs)
  - [Configuration files](#configuration-files)
  - [eBPF](#ebpf-1)
  - [fanotify](#fanotify)

# MacOS:

## Service Persistence

- [ ] Run as system LaunchDaemon with root privileges, auto-start on boot, survive crashes
  - [ ] Run as the LaunchDaemon `com.zedr.agent` as root, start at boot and again after a crash or a kill (`KeepAlive`), log to `/var/log/zedr-agent.log` (`/install.sh`). The installer creates the state directory and stages the enrollment key as on Linux. Written, not yet run as root under launchd
  - [ ] Enroll, send signed heartbeats, seal windows and send a stop notice, through the same runtime as Linux. Not yet run against a control server: a binary the control server sealed is killed by the kernel on Apple silicon, because patching the address and the key into it breaks the page hashes of the ad hoc signature the linker gave it. Rehashing the two patched pages in that signature before the binary is signed lets it start, tried on a copy by hand
  - [x] Build the release agent for the architecture of the Mac it is built on and put it where the control server serves it from (`make build-macos-binary`)
  - [ ] Prove: no prover is built for macOS yet, the installer goes on without one

## libproc and sysctl

- [x] As any user, can list every process with parent, user, executable and command line, and report starts, ends and `exec` by polling (`cargo test -p zedr-agent-macos`)
- [x] As root, can read the socket descriptors of every process and report outbound TCP over IPv4 and IPv6 with the process that holds the socket. As another user, of its own processes only (`cargo test -p zedr-agent-macos`)
- [x] Describe the host as `macOS <version> (<build>)` from `kern.osproductversion` and `kern.osversion`
- [ ] Resource use per process (`proc_pid_rusage`)

## Property lists and inventory folders

- [x] As root, can read launchd job definitions in XML and binary form, crontabs, shell profiles and authorized keys, and report what was added, changed or removed by polling (`cargo test -p zedr-agent-macos`)
- [x] Can read Homebrew's Cellar and Caskroom, application bundles and installer receipts, and report installed, upgraded and removed packages by polling (`cargo test -p zedr-agent-macos`)
- [ ] Read the Background Task Management database, which lists login items and the jobs apps register with `SMAppService`
- [ ] Read launchd's overrides of `launchctl enable` and `disable`
- [ ] Watch the same folders with FSEvents instead of reading them every minute

## EndpointSecurity

- [ ] As EndpointSecurity entitlement holder, can connect to EndpointSecurity framework to monitor system events (`make test-macos-vm-es-connect`)
  - [ ] Capture process execution EXEC (`make test-macos-vm-es-exec`)
  - [ ] Capture process fork FORK (`make test-macos-vm-es-fork`)
  - [ ] Capture file open OPEN (`make test-macos-vm-es-open`)
  - [ ] Capture file create CREATE (`make test-macos-vm-es-create`)
  - [ ] Capture file write WRITE (`make test-macos-vm-es-write`)
  - [ ] Capture file delete UNLINK (`make test-macos-vm-es-unlink`)
  - [ ] Block process execution AUTH mode (`make test-macos-es-block-exec`)
  - [ ] Block file write (`make test-macos-es-block-write`)
  - [ ] Terminate running process (`make test-macos-kill-process`)
  - [ ] Quarantine file (`make test-macos-quarantine-file`)

## OpenBSM (audit subsystem)

- [ ] As root process, can subscribe to kernel audit events via auditpipe (`make test-macos-bsm-connect`)
  - [ ] Capture process execution via audit trail (`make test-macos-bsm-exec`)
  - [ ] Capture file access events (`make test-macos-bsm-file`)
  - [ ] Capture network connections (`make test-macos-bsm-network`)
  - [ ] Capture authentication events (`make test-macos-bsm-auth`)

# Windows:

## Service Persistence

- [x] Run as Windows Service with NT/AUTHORITY privileges, auto-start on boot, survive crashes
- [x] Seal windows and send a stop notice, through the same runtime as Linux. Type-checked and unit-tested on another platform, not yet run on Windows

## Win32 and the registry

- [x] As SYSTEM, can list every process and read its path, start time, session and command line (`CreateToolhelp32Snapshot`, `QueryFullProcessImageNameW`, `GetProcessTimes`, `NtQueryInformationProcess`). A protected process may refuse
- [x] Can read the TCP tables of both address families with the owning process (`GetExtendedTcpTable`)
- [x] Can read `Run` keys, services, `Uninstall` keys and the loaded user hives, task definitions in `System32\Tasks` and Startup folders, and report what was added, changed or removed by polling (`cargo test -p zedr-agent-shared`, which covers the parsing)
- [ ] Read the registry hives of users who are not signed in
- [ ] Run the sensor on a Windows machine (`cargo test -p zedr-agent-windows`)

## ETW (Event Tracing for Windows)

- [ ] As elevated userspace process, can subscribe to kernel ETW providers to monitor system events (`make test-windows-etw-connect`)
  - [ ] Capture process creation via Microsoft-Windows-Kernel-Process provider (`make test-windows-etw-process`)
  - [ ] Capture file I/O via Microsoft-Windows-Kernel-File provider (`make test-windows-etw-file`)
  - [ ] Capture network connections via Microsoft-Windows-Kernel-Network provider (`make test-windows-etw-network`)
  - [ ] Capture registry operations via Microsoft-Windows-Kernel-Registry provider (`make test-windows-etw-registry`)

## WFP (Windows Filtering Platform)

- [ ] As elevated userspace process, can register filters for network monitoring and blocking (`make test-windows-wfp-init`)
  - [ ] Monitor TCP connections via WFP callout (`make test-windows-wfp-tcp`)
  - [ ] Block network connections via WFP filter (`make test-windows-wfp-block`)

## eBPF

- [ ] As user-space process with network access, can load eBPF-for-Windows programs to monitor network traffic (`make test-windows-ebpf-load`)
  - [ ] Capture TCP connection via eBPF (`make test-windows-ebpf-tcp`)

# Linux:

## Service Persistence

- [ ] Run as systemd service with CAP_BPF capability, auto-start on boot, survive crashes
  - [x] Run as systemd service as root, auto-start on boot, restart after a crash (`/install.sh`)
  - [x] Run in a container and as a Kubernetes DaemonSet (`deploy/agents`)
  - [x] Enroll, send signed heartbeats and report a stop apart from a shutdown

## procfs

- [x] As root, can read `/proc` to list processes with parent, user, executable and command line, and report starts, ends and `exec` by polling (`make test-linux-container`)
- [x] As root, can read the TCP socket table of every visible network namespace and find the process that holds a socket (`make test-linux-container`)
- [ ] Resource use per process from `/proc/<pid>/stat`, `statm` and `io`

## Configuration files

- [x] As root, can read the persistence locations of the host through `/proc/1/root`, also from a container that shares the host's process namespace: systemd units and timers, cron, shell profiles, authorized keys, `ld.so.preload`, `rc.local` and init scripts, and report what was added, changed or removed by polling (`make test-linux-container`)
- [ ] Watch the same locations with inotify or fanotify instead of reading them every minute
- [x] As root, can read the dpkg and apk package databases of the host through `/proc/1/root` and report installed, upgraded and removed packages by polling (`make test-linux-container`)
- [ ] Read the rpm database, which is SQLite, Berkeley DB or ndb depending on the release

## Proving

- [x] As root, can run the rule program in a zkVM as a child process at the lowest priority, from one static binary with nothing else to install, on arm64 (`make test-e2e-linux`)
- [x] The same static prover for x64, which builds and proves and verifies its self-test under emulation on an arm64 machine
- [ ] The whole flow on an x64 machine
- [ ] Prove on a GPU where the endpoint has one

## eBPF

- [ ] As CAP_BPF capability holder, can load eBPF programs into kernel to monitor system events (`make test-linux-ebpf-load`)
  - [ ] Capture process execution execve (`make test-linux-ebpf-exec`)
  - [ ] Capture process fork/clone (`make test-linux-ebpf-fork`)
  - [ ] Capture file open openat (`make test-linux-ebpf-open`)
  - [ ] Capture file create creat (`make test-linux-ebpf-create`)
  - [ ] Capture file write (`make test-linux-ebpf-write`)
  - [ ] Capture file delete unlink (`make test-linux-ebpf-unlink`)
  - [ ] Capture TCP connect syscall (`make test-linux-ebpf-tcp`)
  - [ ] Terminate process (`make test-linux-kill-process`)

## fanotify

- [ ] As CAP_SYS_ADMIN capability holder, can use fanotify for file access control (`make test-linux-fanotify-init`)
  - [ ] Block process execution FAN_OPEN_EXEC_PERM (`make test-linux-fanotify-block-exec`)
  - [ ] Block file write FAN_OPEN_PERM (`make test-linux-fanotify-block-write`)
  - [ ] Quarantine file (`make test-linux-quarantine-file`)
