# Agent and Control Server Protocol

Everything an agent sends is a signed HTTPS request. Lifecycle events go to `POST /api/events`, telemetry goes sealed to `POST /api/windows`, and proofs go to `POST /api/proofs`. The message types are in the `protocol` crate.

## Request Signing

See [ADR 013](../adr/013-agent-identity-and-signed-requests.md) for the reasoning.

- The agent keeps an Ed25519 seed and a session counter in `identity.json` in its data directory (`%ProgramData%\zedr` on Windows, `/var/lib/zedr` on Linux). The seed is generated on first start and never leaves the machine.
- Header `X-Zedr-Signature`: hex Ed25519 signature over the exact request body bytes.
- `session`: advances by one on every process start.
- `seq`: starts at 1 in each session and advances by one on every request.
- The server rejects a request with `401` when the signature is missing or wrong or the agent is unknown, and with `409` when `seq` did not advance or the session is older than the four most recent ones. A `409` on a validly signed request opens a `replay` incident.

## Installation

An endpoint is installed with a single-use install key or a fleet enrollment token ([ADR 019](../adr/019-fleet-enrollment-tokens.md)). Either travels in the `X-Zedr-Enrollment-Key` header or as `?key=`.

1. `GET /install.sh` or `GET /install.ps1` returns the installer with the address of the control server and the key filled in.
2. On Linux the installer asks for the prover first, `GET /api/installers/binaries/{os}-{arch}/prover`. A control server that built none for the platform answers `404`, and the endpoint then seals without proving.
3. The installer downloads the agent, `GET /api/installers/binaries/{os}-{arch}`. This uses up an install key, which is why the prover comes first. The agent and the prover are replaced together or not at all, because both carry the same rules.
4. The installer writes the key to `enrollment.key` in the data directory and starts the agent.

The control server stores only the SHA-256 of a key. An install key expires, can be revoked, downloads one agent and enrolls one endpoint.

### What the control server writes into the agent

The agent is built with two 64 byte placeholders, one for the address of the control server and one for the public key of the deployment ([ADR 017](../adr/017-per-deployment-signing-key.md)). When the control server serves an agent it fills both, from `ZEDR_SERVER_URL` and `ZEDR_SIGNING_KEY_HEX`, signs the whole binary and appends the signature.

- The address is therefore at most 64 bytes, and an installed agent talks to one control server until it is installed again.
- The control server refuses to serve a binary where a placeholder is missing or appears more than once.
- The agent checks its own binary, upgrade binaries and signed answers against that key. A binary read straight from the filesystem still holds the placeholder and refuses to start.
- The prover is served as built. It holds nothing about a deployment.

## Registration

`POST /api/agents/register`:

```json
{
  "agent_id": "5f1c9a0e4b7d2c8a6e3f0b9d1a2c4e6f",
  "hostname": "build-07",
  "platform": "linux",
  "os_version": "Debian GNU/Linux 12 (bookworm)",
  "architecture": "aarch64",
  "version": "0.1.0",
  "ip_address": "10.0.4.17",
  "public_key": "<64 hex characters>",
  "enrollment_key": "zedr_...",
  "session": 1,
  "seq": 1
}
```

- The control server verifies the signature against `public_key`. It accepts when that key is already pinned to this agent, or when `enrollment_key` is valid. It then pins the key, counts the enrollment against the install key or the fleet token and answers `200`. Anything else is `401`.
- The agent deletes `enrollment.key` after a `200`. Later registrations omit it.
- On Linux the agent id is the first 16 bytes of the SHA-256 of the agent's public key, as hex. On Windows it is the machine GUID.
- A fleet token enrolls an agent id that has no pinned key and never replaces a pinned key.
- After a refused registration the agent waits 30 seconds and doubles the wait up to 10 minutes.

## Heartbeat

Every 30 seconds, `POST /api/events`:

```json
{
  "agent_id": "5f1c9a0e4b7d2c8a6e3f0b9d1a2c4e6f",
  "session": 1,
  "seq": 2,
  "events": [{ "Heartbeat": { "timestamp": 1765893841 } }]
}
```

- The control server answers `200` and, when one is pending, a signed `upgrade` command. It names the agent, and the agent refuses a command issued for another one and accepts each command once ([ADR 029](../adr/029-signed-commands-run-once-across-agent-restarts.md)). An upgrade is the only command the control server can send ([ADR 030](../adr/030-no-remote-shell.md)).
- The control server updates `last_heartbeat`, sets the liveness state to `active` and closes open `silence` and `service_stopped` incidents ([ADR 014](../adr/014-liveness-and-tamper-incidents.md)).
- On `401` the agent registers again.
- When the service manager stops the agent it sends `AgentStopping` with a reason of `ServiceStop`, `SystemShutdown` or `Upgrade`.

`POST /api/events` takes lifecycle events only. A process, connection, file, autostart or package event in it is refused with `422`.

## Sealed Windows

Telemetry leaves the endpoint sealed ([ADR 031](../adr/031-sealed-telemetry-opened-by-proven-rules.md)). The Linux agent closes a window every 60 seconds, earlier when it holds 1,000 events or 1 MiB, and at once when a rule fires. `POST /api/windows`:

```json
{
  "agent_id": "5f1c9a0e4b7d2c8a6e3f0b9d1a2c4e6f",
  "session": 1,
  "seq": 3,
  "header": {
    "epoch": 1,
    "window": 4,
    "first_index": 212,
    "count": 2,
    "fresh": false,
    "gap": false,
    "prev_head": "<64 hex characters>",
    "root": "<64 hex characters>",
    "head": "<64 hex characters>"
  },
  "events": [
    { "leaf": "<64 hex characters>", "sealed": "<base64 ciphertext>" },
    { "leaf": "<64 hex characters>", "sealed": "<base64 ciphertext>" }
  ],
  "releases": [
    {
      "trigger": 213,
      "rule": "fetch-and-run",
      "context": [207],
      "pid": 4812,
      "started_at": 1765893790,
      "openings": [
        { "index": 213, "seed": "<64 hex characters>" },
        { "index": 207, "seed": "<64 hex characters>" }
      ]
    }
  ],
  "proving": true
}
```

- `events` holds, per event, the commitment and the ciphertext. The control server cannot read either.
- `header` chains the window to the one before. `epoch` advances at every agent start, `fresh` marks the first window of an epoch, and `gap` says that the agent lost events before it could seal them.
- `releases` holds what a rule opened. `trigger` is the event the rule fired on, `context` the other events it opens, and `openings` the secret of each. An opening may point into an earlier window of the same epoch.
- `proving` says whether the endpoint has a prover.

The control server checks the header against the leaves and against the head it holds for the agent, stores the window, opens what was released and answers `200` with an acknowledgement signed by the deployment key:

```json
{ "window": 4, "next_index": 214, "head": "<64 hex characters>", "signature": "<64 bytes as an array of numbers>" }
```

The agent keeps a window on disk until it holds that signature, and sends the same bytes again until then. A window the control server already holds is acknowledged again.

A window is refused with `422` when it is not a window an honest agent seals, and with `409` when it does not continue the chain the control server holds. Both carry a signed refusal that names the position the control server holds:

```json
{ "epoch": 1, "next_window": 4, "next_index": 212, "head": "<64 hex characters>", "signature": "<64 bytes as an array of numbers>" }
```

The signature covers the agent, the session and the `seq` of the request it answers, so a refusal cannot be replayed to move an agent back. The agent drops the windows the control server did not take, continues at the position named in an epoch later than both its own and the one named, and waits 60 seconds before the next window, doubling up to one hour while refusals continue.

Window numbers and event indices run on across epochs, one chain per agent. A fresh window is only taken in a later epoch than the one stored.

| Incident | Opened when |
|---|---|
| `window_malformed` | the header does not match the leaves, the window is for another agent, or a ciphertext is not one of the sealed sizes |
| `chain_fork` | a window is not the next one, does not start at the next event, does not follow the stored head, or is in the wrong epoch |
| `chain_gap` | the header of a stored window says the agent lost events before it could seal them |
| `release_invalid` | a release does not open the event that was committed, or its rule does not open what it names. The window is kept and the release opens nothing |

## Proofs

An endpoint with a prover proves the windows the control server acknowledged, several windows in one proof. `POST /api/proofs`:

```json
{
  "agent_id": "5f1c9a0e4b7d2c8a6e3f0b9d1a2c4e6f",
  "session": 1,
  "seq": 9,
  "receipt": "<base64 of the bincode receipt>"
}
```

The receipt is a RISC Zero composite receipt of the rule program in `prover/guest`: one proof per segment of the run, about a quarter of a megabyte each, so a proof of 250 events is around six megabytes. The control server reads up to 32 MiB and keeps no receipt. Its public output names the agent, the epoch, the window and index range, the chain head before and after, a commitment to the rule state before and after, and every match.

The control server verifies the receipt against the image IDs in `ZEDR_GUEST_IMAGE_IDS`, checks that it continues where the last proof of the epoch ended, and compares its matches with the releases it stored. It answers `200` with `{ "first_window": 2, "last_window": 4 }` and marks those windows verified.

| Incident | Opened when |
|---|---|
| `proof_invalid` | the receipt does not verify, is for another rule program, or does not continue the proven chain |
| `match_not_released` | the proof names a match the endpoint sent no release for |
| `release_not_proven` | the endpoint released events for a match the proof does not name |
| `proof_overdue` | a window from a proving endpoint has no proof after `ZEDR_PROOF_DEADLINE_SECS`, one hour unless set |
| `proving_stopped` | an endpoint whose last window said it proves sends one that says it does not |

An endpoint rests 15 minutes after a proof (`ZEDR_PROOF_REST`, in seconds) and proves earlier once 250 events wait (`ZEDR_PROOF_EVENTS`), which is also the most one proof covers. The prover works in segments of 2^18 cycles (`ZEDR_PROOF_SEGMENT_PO2`, 13 to 24). The memory it needs about doubles with every step up and halves with every step down, and smaller segments make a larger receipt.

## What the control server holds about an endpoint

- Its registration and its lifecycle events, in plaintext.
- For every sensor event: its position in the chain, a commitment, a ciphertext padded to one of eight sizes, and the time its window arrived.
- For an event a rule opened: the event itself, and the finding built from it.
- For every proven run of windows: the receipt and its public output.
