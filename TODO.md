# Sealed telemetry and proofs

- [x] No remote shell: the agent has no code that runs a command for the control server (ADR 030)
- [x] Every sensor event sealed on the endpoint and committed in a hash chain of one-minute windows, with signed acknowledgements and signed refusals (ADR 031)
- [x] Detection rules in the agent, one crate shared with the prover and the control server: fifteen rules and the follow-up that opens the end of a flagged process
- [x] Releases: a rule opens its own evidence, the control server checks each opened event against its commitment and builds the finding from it
- [x] The rule run proven in RISC Zero over the committed windows, verified by the control server against pinned image IDs and compared with the releases
- [x] The prover as one static Linux binary, served and installed with the agent, at low priority, resting between proofs and bounded to 2.7 GB of memory
- [x] Incidents for a broken chain, a bad release, a bad or missing proof, a match that was not released, a release no proof stands behind and an endpoint that stops proving
- [x] Hunt, process tree and live stream over opened events only
- [x] Console: what the server holds of an endpoint as sealed rows with the opened ones in the clear, the commitment chain with the proof state of every window, findings with their proof, and the rule set with the accepted rule programs. `make demo` shows it on a test tenant: a simulated fleet with intrusion stories from real cases, whose server takes an endpoint's statement for a proof and says so
- [x] The whole flow run for real in containers: `make test-e2e-linux`
- [ ] Proving costs about 20 seconds of one core for every event, so a busy endpoint cannot keep up on its CPU. What would change that: fewer zkVM cycles for every event, GPU proving, a prover the owner of the endpoint runs elsewhere, or circuits for the pattern matching. See the measurements in docs/DETECTIONS.md
- [ ] Measure proving on a quiet machine and on x64, the numbers in docs/DETECTIONS.md are from a busy arm64 machine
- [ ] Run the whole flow on an x64 machine. The x64 agent and prover build, and the prover passes its self-test under emulation, the end-to-end run was on arm64 only
- [ ] Run `make test-e2e-linux` and build the guest, the agent and the prover in CI, and publish them from the release workflow. Today a developer machine builds them and the image copies them in
- [ ] Reproducible agent and prover builds, so the owner of an endpoint can compare what a control server serves with a build of this repository. The rule program already builds reproducibly
- [ ] A dishonest endpoint is caught by its proof, at the latest after the proof deadline. Shorten that for windows that hold a release
- [ ] A process opened only as the parent of a finding is shown as the rules last saw it, and the control server never learns that it ended
- [ ] Rule state that survives an agent restart, today every start is a new epoch with an empty process table
- [ ] Suppression and exclusions as part of the proven rule program, and a way to roll out a new rule set across a fleet with two image IDs accepted during the change
- [ ] Hide how many events a window holds: pad the count, or seal on a fixed schedule only
- [ ] Break-glass opening for an investigation that needs more than the rules open, with the key split among several holders
- [ ] Keys bound to hardware instead of files that root can read
- [ ] Prove a new rule over windows sealed in the past
- [x] A macOS agent that enrolls, heartbeats and seals: processes, outbound connections, launchd jobs, cron, shell profiles, SSH keys, Homebrew, apps and installer receipts, read through the kernel and the files themselves (ADR 033)
- [ ] Run the macOS agent as root under launchd against a real control server, through the installer, and on an Intel Mac
- [x] A Windows sensor: processes, outbound connections, Run keys, services, scheduled tasks, Startup folders and installed programs (ADR 033)
- [ ] Run the Windows agent and its sensor on Windows, it was type-checked for x64 and ARM64 and its parsing unit-tested on a Mac only
- [ ] A prover for macOS and Windows endpoints, both seal and release without proving today

# Agent trust, console and deployment

- [x] Agent identity, signed requests and agent-bound commands (ADR 013)
- [x] Liveness state machine and tamper incidents (ADR 014)
- [x] Console roles, TOTP second factor and hash-chained audit log (ADR 015)
- [x] BYOC deployment packaging (ADR 016)
- [x] Per-deployment signing key, patched into the agent at download (ADR 017)
- [x] Startup check that refuses a changed `ZEDR_SIGNING_KEY_HEX` while agents are enrolled (ADR 017)
- [x] Console around an endpoint map, with shared components and resizable panes (ADR 018)
- [x] Install anywhere: a working Linux agent, fleet enrollment tokens for autoscaling groups, and recipes for EC2 user data, containers and Kubernetes (ADR 019)
- [x] Linux sensor: process tree and outbound TCP connections per process from `/proc` (ADR 020), autostart inventory with changes (ADR 022), installed packages on Debian, Ubuntu and Alpine (ADR 023)
- [x] Account controls, live session checks and audited impersonation, with a Users page (ADR 021)
- [x] Upgrade commands recorded on disk before the agent acts on them, so a restarted agent does not accept one again (ADR 029)
- [x] Lock files committed, so every build uses pinned dependencies
- [ ] Build the Windows agent with `make build-windows-binary` and enroll it. No Windows binary was built from this tree, and the move of its server link and heartbeat loop into `agent/shared` was only type-checked from macOS
- [ ] Install the chart on a cluster. The image builds from a clean checkout and a container of it serves the console, the installer, the agent and the prover, the chart was only linted and rendered
- [ ] Signing key rotation that moves enrolled agents to a new key, and a console marker for agents that still trust a replaced key
- [ ] Move the binary signing key out of the control server into CI, with pre-flight and rollback on upgrade
- [ ] Console page for fleet enrollment tokens (create, list, revoke) and agents grouped by `enrollment_group`, today the tokens are API only
- [ ] Run the EC2 recipe on a real autoscaling group and the DaemonSet on a managed cluster, both ran only on local containers and a kind cluster
- [ ] Remove or quarantine an agent, and retire the agents of terminated instances
- [ ] Linux agent self-upgrade, today an upgrade command is answered with a failure and the installer has to be run again
- [ ] Report a node shutdown as a shutdown under kubelet graceful node shutdown, which needs the logind state as well as the systemd state
- [ ] Platform attestation as a condition on a fleet token, starting with the AWS instance identity document
- [ ] Revoke an install key from the console, the key has a `revoked_at` and no route sets it
- [ ] Let a read-only user change their own password, and list an account's sessions so one can be ended on its own
- [ ] Refresh token rotation and a mandatory second factor for admins
- [ ] Console: run the browser journeys (`npm run sweep`) in CI, incident acknowledgement
- [ ] Console: repeat the browser journeys at laptop and pane width, after the sealed rows were added only the desktop run was repeated. The sealed rows stop refreshing once paged past the first 200
- [ ] Console: see `chain_fork`, `window_malformed`, `release_invalid`, `proof_invalid`, `proof_overdue`, `release_not_proven` and `proving_stopped` on a live server, their cards are unit-tested only
- [ ] Retention for sealed windows, opened events and the hunt index on the control server

# Sensor

- [ ] Event-driven collection, so short-lived processes and connections are not missed: exec and connect events on Linux (eBPF or the proc connector), ETW providers on Windows, Endpoint Security on macOS. Today the Linux agent polls `/proc`
- [ ] Image hash and signer on every process start
- [ ] DNS queries, UDP and listening sockets
- [ ] File events for executable writes and watched folders, the protocol has `FileEvent` and a rule for it, and no agent sends it
- [ ] Logon and privilege events: interactive and remote logons, sudo, new accounts
- [ ] The remaining event types proposed in ADR 020 (`ProcessUsage`, `AppUsage`, `Login`, `Dns`)
- [ ] Persistence on Linux that is not read yet: socket and path units, `at` jobs, udev rules, kernel modules, XDG autostart, other shells' startup files, keys named by `sshd_config`, and the lines that changed in a shell profile
- [ ] Persistence the macOS and Windows sensors do not read yet: login items and `SMAppService` jobs, launchd overrides, periodic scripts on macOS, WMI subscriptions, Winlogon, IFEO, AppInit, COM hijacks and the `ServiceDll` behind svchost on Windows
- [ ] Installed packages on rpm hosts, Store and winget apps on Windows, and packages of languages such as pip and npm
- [ ] Run the DaemonSet on a cluster and check that it reports the node's persistence, reading the host through `/proc/1/root` was only run with a container that shares the host's process namespace
- [ ] Response actions as signed commands with one fixed meaning each: isolate the endpoint, kill a process, quarantine a file
