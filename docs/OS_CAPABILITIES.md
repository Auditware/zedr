This file documents the agent's technical capabilities per operating system

## Table of Contents

- [MacOS](#macos)
  - [Service Persistence](#service-persistence)
  - [EndpointSecurity](#endpointsecurity)
  - [OpenBSM (audit subsystem)](#openbsm-audit-subsystem)
- [Windows](#windows)
  - [Service Persistence](#service-persistence-1)
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
- [ ] Secure Remote Shell Capability
  - [ ] Signed command execution over HTTP
  - [ ] Signed file retrieval

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
- [ ] Secure Remote Shell Capability
  - [ ] Signed command execution over HTTP
  - [ ] Signed file retrieval

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
- [ ] Secure Remote Shell Capability
  - [x] Signed command execution over HTTP
  - [ ] Signed file retrieval

## procfs

- [x] As root, can read `/proc` to list processes with parent, user, executable and command line, and report starts, ends and `exec` by polling (`make test-linux-container`)
- [x] As root, can read the TCP socket table of every visible network namespace and find the process that holds a socket (`make test-linux-container`)
- [ ] Resource use per process from `/proc/<pid>/stat`, `statm` and `io`

## Configuration files

- [x] As root, can read the persistence locations of the host through `/proc/1/root`, also from a container that shares the host's process namespace: systemd units and timers, cron, shell profiles, authorized keys, `ld.so.preload`, `rc.local` and init scripts, and report what was added, changed or removed by polling (`make test-linux-container`)
- [ ] Watch the same locations with inotify or fanotify instead of reading them every minute
- [x] As root, can read the dpkg and apk package databases of the host through `/proc/1/root` and report installed, upgraded and removed packages by polling (`make test-linux-container`)
- [ ] Read the rpm database, which is SQLite, Berkeley DB or ndb depending on the release

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
