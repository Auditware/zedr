This file documents the technical measures to prevent agent bypassing or tampering per operating system

## Shared

- [ ] "Unexpectedly" check core binary hash to detect malicious patching
- [x] Detect heartbeat pattern abnormality: the control server derives `active`, `stale`, `suspect` and `incident` from the time since the last signed heartbeat and opens a `silence` incident only when one machine is uniquely quiet ([ADR 014](./adr/014-liveness-and-tamper-incidents.md))
- [x] Detect failed reinstallation with an already used key: a registration with a used, expired or revoked key is rejected and recorded as `enrollment_rejected`, and a key change on an enrolled agent opens an `identity_conflict` incident ([ADR 013](./adr/013-agent-identity-and-signed-requests.md))
- [x] Authenticate every agent request: per-agent Ed25519 key generated on the endpoint and pinned at enrollment, signature over the exact request bytes
- [x] Detect replayed requests and cloned identities: per-session sequence numbers, a `replay` incident when a validly signed request is seen twice or out of order
- [x] Bind signed commands to one agent, so a command captured for one machine is refused by every other machine
- [x] Every signed command is recorded on disk before the agent acts on it, so an agent that restarted does not accept the same command again ([ADR 029](./adr/029-signed-commands-run-once-across-agent-restarts.md))
- [x] Trust one deployment only: the control server patches its own signing public key into every agent it serves and signs over it, so an agent refuses binaries and commands signed by any other key, and an agent that was not served by a control server refuses to start ([ADR 017](./adr/017-per-deployment-signing-key.md))
- [x] Report why the agent stops: a signed stop notice separates a system shutdown from a service stop and from an upgrade handoff
- [x] Keep fleet enrollment from weakening agent identity: a reusable fleet token enrolls new agents only, it never replaces a pinned key, it expires, can be capped and revoked, and every refusal is recorded with its reason ([ADR 019](./adr/019-fleet-enrollment-tokens.md))
- [x] Back off after a refused registration, so a machine with a dead token does not flood the control server
- [x] No command channel: the agent has no code that runs a command for the control server, an upgrade is the only thing a signed command can ask for ([ADR 030](./adr/030-no-remote-shell.md))

## MacOS

- [x] Refuse to start when the binary does not carry a valid signature of the deployment that served it, same check as on Linux
- [ ] Start at all once the control server has sealed it: on Apple silicon the kernel kills a sealed binary, because the patched address and key break the ad hoc signature the linker gave it. The control server has to rehash the patched pages of that signature before it signs the binary
- [ ] A Developer ID signature, the hardened runtime and notarization. The binary carries only the linker's ad hoc signature
- [x] Agent state directory (`/Library/Application Support/zedr`) is created with mode `0700` and owned by root by the installer before the enrollment key is written, and the agent itself refuses a directory that is a symlink or belongs to another user and closes one that is open to group or others. The identity seed and the enrollment key are files with mode `0600`
- [x] Agent id is derived from the agent's own public key, as on Linux
- [ ] A stop while the system keeps running opens a `service_stopped` incident, but so does every shutdown: the agent sends a signed stop notice on every `SIGTERM` and reports it as a service stop, because it cannot tell a shutdown apart
- [x] launchd starts the agent at boot and again after a crash or a kill (`KeepAlive`), and the installer writes the definition owned by root with mode `0644`. Not yet run as root under launchd
- [x] Telemetry is read by the agent itself through `libproc`, `sysctl` and the files it inventories. No helper program such as `ps`, `lsof`, `launchctl`, `plutil`, `pkgutil` or `brew` is started that could be replaced on the path, and property lists are parsed inside the agent
- [x] TLS comes from the system's Security framework, which lives on the sealed system volume
- [x] The agent leaves its own connections out of the telemetry by process id, not by destination
- [x] Sealing, the hash chain, delivery and the handling of refusals are the shared runtime, and work as described for Linux

## Windows

- [x] Agent data directory (`%ProgramData%\zedr`) is restricted to SYSTEM and Administrators by the installer before the enrollment key and the identity seed are written
- [x] A service stop while the system keeps running opens a `service_stopped` incident on the control server within one request. The service control handler tells a stop from a shutdown
- [x] Telemetry is read by the agent itself through system calls and the registry, no helper program is started that could be replaced on the path
- [x] The agent leaves its own connections out of the telemetry by process id, not by destination
- [x] The last sensor round is sealed and flushed before the stop notice leaves
- [x] Every sensor event is committed in a hash chain before it leaves the endpoint, and sealing, delivery and the handling of refusals are the shared runtime, as described for Linux
- [x] Task definitions are parsed without expanding entities a document defines itself
- [ ] These measures are type-checked and unit-tested on another platform and not yet run on Windows

## Linux

- [x] Refuse to start when the binary does not carry a valid signature of the deployment that served it, same check as on Windows
- [x] Agent state directory (`/var/lib/zedr`) is created with mode `0700` by the installer before the enrollment key is written, and the agent itself refuses a directory that is a symlink or belongs to another user and closes one that is open to group or others. The identity seed and the enrollment key are files with mode `0600`
- [x] Agent id is derived from the agent's own public key, so an id cannot be claimed without the key and cloned images do not share one
- [x] A stop while the system keeps running opens a `service_stopped` incident on the control server within one request. The agent asks systemd whether the system is stopping (`SystemState` over `/run/systemd/private`) and reports a shutdown only then. When it cannot ask, it reports a stop
- [x] systemd restarts the agent after a crash or a kill (`Restart=always`), and starts it at boot
- [x] Static binary with its own TLS stack, so the agent does not load libraries from the host that could be swapped
- [x] Telemetry is read by the agent itself from `/proc`, no helper program is started that could be replaced on the path, and events travel sealed in requests that are signed and sequenced like heartbeats
- [x] The agent leaves its own connections out of the telemetry by process id, not by destination, so nothing else can hide behind the control server's address
- [x] Every sensor event is committed in a hash chain before it leaves the endpoint. A window that is missing, out of order or changed afterwards does not fit the chain the control server holds, and opens `chain_fork` or `chain_gap` ([ADR 031](./adr/031-sealed-telemetry-opened-by-proven-rules.md))
- [x] A window is sealed every minute also when nothing happened, so a sensor that was stopped while the agent keeps its heartbeat shows on the control server as windows that stop arriving
- [ ] Open an incident when an endpoint heartbeats and its windows stop arriving, today only the chain view shows it
- [x] Sealed windows stay on disk until the control server acknowledged them with a signature of the deployment key, and only a refusal with that signature makes the agent drop one. Nothing on the network path can make it discard telemetry
- [x] A match the agent did not report is named by the proof of that window, which opens `match_not_released`. A window that is never proven opens `proof_overdue`, and an endpoint that stops proving opens `proving_stopped`
- [x] The ledger and the proof inputs are files of mode `0600` in folders of mode `0700`, and plaintext is removed once a proof covers it
