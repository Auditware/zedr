This file documents the technical measures to prevent agent bypassing or tampering per operating system

## Shared

- [ ] "Unexpectedly" check core binary hash to detect malicious patching
- [x] Detect heartbeat pattern abnormality: the control server derives `active`, `stale`, `suspect` and `incident` from the time since the last signed heartbeat and opens a `silence` incident only when one machine is uniquely quiet ([ADR 014](./adr/014-liveness-and-tamper-incidents.md))
- [x] Detect failed reinstallation with an already used key: a registration with a used, expired or revoked key is rejected and recorded as `enrollment_rejected`, and a key change on an enrolled agent opens an `identity_conflict` incident ([ADR 013](./adr/013-agent-identity-and-signed-requests.md))
- [x] Authenticate every agent request: per-agent Ed25519 key generated on the endpoint and pinned at enrollment, signature over the exact request bytes
- [x] Detect replayed requests and cloned identities: per-session sequence numbers, a `replay` incident when a validly signed request is seen twice or out of order
- [x] Bind signed commands to one agent and one shell session, so a command captured for one machine is refused by every other machine
- [x] Every signed command, shell or upgrade, is recorded on disk before the agent acts on it, so an agent that restarted does not accept the same command again ([ADR 029](./adr/029-signed-commands-run-once-across-agent-restarts.md))
- [x] A stored result of a shell command cannot be replaced. The control server keeps the first result an agent sends for a command and leaves later ones out ([ADR 029](./adr/029-signed-commands-run-once-across-agent-restarts.md))
- [x] Trust one deployment only: the control server patches its own signing public key into every agent it serves and signs over it, so an agent refuses binaries and commands signed by any other key, and an agent that was not served by a control server refuses to start ([ADR 017](./adr/017-per-deployment-signing-key.md))
- [x] Report why the agent stops: a signed stop notice separates a system shutdown from a service stop and from an upgrade handoff
- [x] Keep fleet enrollment from weakening agent identity: a reusable fleet token enrolls new agents only, it never replaces a pinned key, it expires, can be capped and revoked, and every refusal is recorded with its reason ([ADR 019](./adr/019-fleet-enrollment-tokens.md))
- [x] Back off after a refused registration, so a machine with a dead token does not flood the control server

## MacOS

## Windows

- [x] Agent data directory (`%ProgramData%\zedr`) is restricted to SYSTEM and Administrators by the installer before the enrollment key and the identity seed are written
- [x] A service stop while the system keeps running opens a `service_stopped` incident on the control server within one request

## Linux

- [x] Refuse to start when the binary does not carry a valid signature of the deployment that served it, same check as on Windows
- [x] Agent state directory (`/var/lib/zedr`) is created with mode `0700` by the installer before the enrollment key is written, and the agent itself refuses a directory that is a symlink or belongs to another user and closes one that is open to group or others. The identity seed and the enrollment key are files with mode `0600`
- [x] Agent id is derived from the agent's own public key, so an id cannot be claimed without the key and cloned images do not share one
- [x] A stop while the system keeps running opens a `service_stopped` incident on the control server within one request. The agent asks systemd whether the system is stopping (`SystemState` over `/run/systemd/private`) and reports a shutdown only then. When it cannot ask, it reports a stop
- [x] systemd restarts the agent after a crash or a kill (`Restart=always`), and starts it at boot
- [x] Static binary with its own TLS stack, so the agent does not load libraries from the host that could be swapped
- [x] Remote shell commands get no stdin, a time limit and an output cap, and run only when signed for this agent by the deployment key. Each one is recorded on disk before it runs, so it runs once, also when the agent restarts in between ([ADR 029](./adr/029-signed-commands-run-once-across-agent-restarts.md))
- [x] Telemetry is read by the agent itself from `/proc`, no helper program is started that could be replaced on the path, and events travel in the same signed and sequenced requests as heartbeats
- [x] The agent leaves its own connections out of the telemetry by process id, not by destination, so nothing else can hide behind the control server's address
