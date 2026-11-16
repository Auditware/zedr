# PoC phase

PoC phase describes the preliminary ground work to

- [x] Baseline code structures, documentation organization principles applies (like ADRs)
- [x] Developer VM setup experience decision and documentation
- [x] Windows arm64 agent running as a persistent NT/AUTHORITY service
- [x] Secrets and envs are carefully managed at `./secrets` directory and encrypted at rest
- [x] Control server operational for administrators, and allows control of generating installation request including necessary patching and signing
- [x] Windows arm64 agent verifies signatures and communicates to control server
- [x] Control server upgrade logs (push, old service, new service)
- [x] Proper testing of crucial components and enforcement through pre-commit hooks that calls testing for changed code portions
- [x] Agent<->Server enforced encrypted communication
- [ ] Secured and Signed Remote Shell Access with expiring sessions

# Agent trust, console and deployment

- [x] Agent identity, signed requests and agent-bound commands (ADR 013)
- [x] Liveness state machine and tamper incidents (ADR 014)
- [x] Console roles, TOTP second factor and hash-chained audit log (ADR 015)
- [x] BYOC deployment packaging (ADR 016)
- [x] Per-deployment signing key, patched into the agent at download (ADR 017)
- [ ] Rebuild the Windows agent with `make build-windows-binary` and enroll it again, the committed v0.1.0 binary predates signed requests and the signing key slot, and the control server refuses to serve it
- [ ] Build the container image and install the chart on a cluster, neither has been run yet
- [x] Startup check that refuses a changed `ZEDR_SIGNING_KEY_HEX` while agents are enrolled (ADR 017)
- [ ] Signing key rotation that moves enrolled agents to a new key, and a console marker for agents that still trust a replaced key
- [ ] Commit `Cargo.lock` so release images build from pinned dependencies
- [ ] Move the binary signing key out of the control server into CI, with pre-flight and rollback on upgrade
- [x] Console rewritten around an endpoint map, with shared components and resizable panes (ADR 018)
- [x] Install anywhere: a working Linux agent, fleet enrollment tokens for autoscaling groups, and recipes for EC2 user data, containers and Kubernetes (ADR 019)
- [ ] Console page for fleet enrollment tokens (create, list, revoke) and agents grouped by `enrollment_group`, today the tokens are API only
- [ ] Run the EC2 recipe on a real autoscaling group and the DaemonSet on a managed cluster, both ran only on local containers and a kind cluster
- [ ] Publish the agent image from the release workflow, and build the Linux agent binaries there instead of on a developer machine (`make build-linux-binary`)
- [ ] Remove or quarantine an agent, and retire the agents of terminated instances
- [ ] Linux agent self-upgrade, today an upgrade command is answered with a failure and the installer has to be run again
- [ ] Report a node shutdown as a shutdown under kubelet graceful node shutdown, which needs the logind state as well as the systemd state
- [ ] Platform attestation as a condition on a fleet token, starting with the AWS instance identity document
- [x] First Linux sensor: process tree and outbound TCP connections per process from `/proc`, through the existing `process` and `network` events (ADR 020)
- [ ] Decide the remaining event types proposed in ADR 020 (`ProcessUsage`, `AppUsage`, `Login`, `Dns`) and build them
- [ ] macOS source for the shared sensor, and a real macOS agent to carry it
- [ ] See what polling misses: eBPF or the netlink process connector for short-lived processes and connections, `sock_diag` instead of reading socket tables per namespace
- [ ] Keep unsent events on disk, and give stored events a retention limit on the control server
- [x] Event batches filled by encoded size up to a limit the control server states, and a refused batch narrowed down to the event the server refuses (ADR 024)
- [ ] Tell the control server how many events an agent discarded or dropped, today only the agent's log says so
- [x] Results of remote shell commands that are larger than one event batch are cut by encoded size until they fit, and keep their exit code (ADR 027)
- [x] Results of remote shell commands that the control server did not take are kept and sent again after every heartbeat it accepts (ADR 028)
- [x] Shell commands recorded on disk before they run, so that a restarted agent does not run one again, and commands a restart cut off answered when the agent starts (ADR 029)
- [x] Control server keeps the first result it stores for a shell command, a later one is accepted and left out (ADR 029)
- [x] Upgrade commands recorded on disk like shell commands, and a command without an answer handed out again only after two minutes (ADR 029)
- [x] Shell command the agent refuses for its age answered with the reason, and not run (ADR 029)
- [ ] Decide what happens to a shell command the agent refuses for its signature, it gets no answer and holds back the commands behind it until the session ends
- [ ] Run an upgrade on Windows through the record of accepted commands, that path was only type-checked
- [ ] Keep the results of remote shell commands that wait for the control server on disk, and send `ShellSessionTerminated` again as well, today a waiting result is lost when the agent restarts
- [ ] Run the refactored Windows agent on Windows, the move of its server link, heartbeat loop and shell into `agent/shared` was only type-checked from macOS
- [ ] Console: run the browser journeys (`npm run sweep`) in CI, incident acknowledgement
- [x] Console: every view has a picture of its own, and the Events lanes are counted by the server per time bucket (ADR 018)
- [ ] Revoke an install key from the console, the key has a `revoked_at` and no route sets it
- [x] Account controls, live session checks and audited impersonation, with a Users page (ADR 021)
- [ ] Let a read-only user change their own password, and list an account's sessions so one can be ended on its own
- [x] Server-side detections: eleven process rules and four persistence rules run as events arrive, a high finding opens an incident that reaches the map, and an admin can close it (ADR 025)
- [ ] Detections: suppression and exclusions, triage state beyond closing, Sigma import, and a process table that survives a server restart
- [ ] Event-driven collection, so short-lived processes and connections are not missed: exec and connect events on Linux (eBPF or the proc connector), ETW providers on Windows, Endpoint Security or eslogger on macOS. Today the Linux agent polls /proc
- [ ] Image hash and signer on every process start, and first-seen counts per hash across endpoints
- [ ] DNS queries, UDP and listening sockets
- [x] Persistence inventory with change events on Linux: systemd units and timers, cron, shell profiles, authorized_keys, ld.so.preload, rc.local and init scripts, read every minute and stored as `persistence` events (ADR 022)
- [ ] Persistence inventory on the other platforms: Run keys, services, scheduled tasks and WMI subscriptions on Windows, LaunchAgents, LaunchDaemons and login items on macOS
- [ ] Console view of the persistence inventory and its changes, and rules on it, today the events are stored and nothing reads them
- [ ] Persistence on Linux that is not read yet: socket and path units, `at` jobs, udev rules, kernel modules, XDG autostart, other shells' startup files, keys named by `sshd_config`, and the lines that changed in a shell profile
- [ ] Run the DaemonSet on a cluster and check that it reports the node's persistence, reading the host through `/proc/1/root` was only run with a container that shares the host's process namespace
- [ ] File events for executable writes and watched folders, the protocol has `FileEvent` and no agent sends it
- [ ] Logon and privilege events: interactive and remote logons, sudo, new accounts
- [ ] Response actions as signed commands: isolate the endpoint, kill a process, quarantine a file
- [x] Hunt across endpoints: a query language over indexed processes, connections, files and detections, with a Hunt page (ADR 026)
- [x] Hunt for installed packages by version and for autostart items, with a Persistence view on the endpoint (ADR 026)
- [ ] Hunt: a backfill of events stored before the index, saved hunts, retention for the index tables, and a packages view on the endpoint
- [x] Installed packages per endpoint on Debian, Ubuntu and Alpine, read from the dpkg and apk databases every five minutes and stored as `package` events with installs, upgrades and removals (ADR 023)
- [ ] Installed packages on rpm hosts (RHEL, Fedora, Amazon Linux, SUSE), on Windows and on macOS, and packages of languages such as pip and npm
- [ ] Listening services per endpoint
- [ ] Run the investigation against a real Linux agent, it has only seen simulated process, network and file events
- [ ] Three signer approval for shell sessions
- [ ] Refresh token rotation and a mandatory second factor for admins

# Deferred

- [ ] Remove hardcoded bindings like "admin" and transition to .env use
- [ ] MacOS Linux and Windows x86_64 needs to get up to speed with Windows arm64 development
- [ ] Fix login input fields bright colors
