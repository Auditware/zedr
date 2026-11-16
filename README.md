# zedr

Zero-knowledge endpoint detection and response.

zedr is an open source EDR that stays in user space and keeps endpoint telemetry private. The control server can read an event only when a detection rule matched it, and it can check that the rules ran over everything else without reading any of it.

This is a proof of concept. The sealed pipeline runs end to end on Linux. The Windows and macOS agents enroll and heartbeat and have no sensor yet.

## How it works

1. The agent reads processes, outbound connections, autostart items and installed packages from `/proc` and the file system. There is no kernel driver.
2. Every event is encrypted on the endpoint with a key that never leaves it, and committed to in a hash chain of one-minute windows. The control server stores ciphertext and commitments.
3. The detection rules run in the agent. When one matches, the agent releases the keys of the events that rule opens. The control server checks them against the commitments and builds the finding from the opened events.
4. A prover on the endpoint runs the same rules in a zkVM ([RISC Zero](https://risczero.com)) over the committed events. The control server verifies the proof and compares it with what was released. A match that was not released, or a release no proof stands behind, opens an incident.
5. The console shows what was opened: findings, the process tree around them and hunts over them. Everything else shows as sealed rows with their place in the chain and the state of their proof.

The design and its limits are in [ADR 031](./docs/adr/031-sealed-telemetry-opened-by-proven-rules.md), the messages in [AGENT_PROTOCOL.md](./docs/architecture/AGENT_PROTOCOL.md), the rules and the cost of proving in [DETECTIONS.md](./docs/DETECTIONS.md).

## What a proof says

A proof says that the pinned rule program ran over every event the endpoint committed, in order and without a hidden gap, and names every match. It does not say that the endpoint committed everything that happened: whoever has root on an endpoint can keep an event from being sealed. The other known ways around the agent and the control server are listed in [BYPASSES.md](./docs/BYPASSES.md).

## Try it

The Makefile assumes a macOS development machine with Docker, Rust and Node 22. Anything that proves also needs the RISC Zero build tool in the version the rule program is pinned to: install [rzup](https://dev.risczero.com/api/zkvm/install), then `rzup install cargo-risczero 3.1.0` and `rzup install r0vm 3.1.0`.

```bash
cp secrets/.env.local.example secrets/.env.local
```

```bash
make test
```

runs the unit and integration tests of the protocol, the ledger, the rules, the agent and the control server. It needs neither Docker nor RISC Zero.

```bash
make test-e2e-linux
```

runs the whole flow for real: it builds the rule program, the agent and the prover, starts a control server, lets the installer set up an endpoint in a container, runs an ordinary command and a download piped into a shell there, and waits until the finding is open, the ordinary command is nowhere in the database and the server has verified the proofs. It takes about ten minutes once everything is built.

```bash
make demo
```

opens the console on http://localhost:7771 against a test tenant: a control server and a fleet of about 190 endpoints played by the development simulator in `agent/simulator`, which commits, seals and releases with the agent's own code. Sign in with the test tenant button. After `make guest prover`, two of the endpoints prove for real, and one of them holds a match back and is caught by its own proof a few minutes later. The fleet includes Windows and macOS machines to show the rules that are about them. Their real agents seal nothing yet.

`make help` lists the other targets.

## Layout

| Path | What |
|---|---|
| `agent/` | The agents: `shared` holds the sensor loop, the ledger and the link to the control server, `linux`, `windows` and `macos` the platform parts |
| `protocol/` | The messages between agent and control server, and the canonical form of a sensor event |
| `ledger/` | Commitments, the window chain and sealing |
| `rules/` | The detection rules and the function a proof is about |
| `prover/` | `guest` is the rule program for the zkVM, `host` the `zedr-prover` binary that runs on an endpoint |
| `control_server/backend/` | The control server: Axum and SQLite |
| `control_server/frontend/` | The console: React and Vite |
| `deploy/` | Container image, Helm chart, Terraform and the recipes for installing agents |
| `e2e/` | The run behind `make test-e2e-linux` |
| `docs/` | Decision records, the protocol, what is collected and detected, and what is not |

## Standards

- [Core agent capabilities](.github/instructions/agent.instructions.md#core-agent-uncompromisable-capabilities)
- [Central management capabilities](.github/instructions/control_server_backend.instructions.md#central-management-uncompromisable-capabilities)
- [Operating system capabilities](./docs/OS_CAPABILITIES.md)
- [Development and deployment standards](.github/copilot-instructions.md#developments-and-deployment-standards)

What is done and what is open is in [TODO.md](./TODO.md).
