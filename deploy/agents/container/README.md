# Agent container image

A small image that fetches the agent from your control server when it starts and runs it in the foreground. The agent binary is sealed per deployment at download ([ADR 017](../../../docs/adr/017-per-deployment-signing-key.md)), so the image holds no agent and works with any control server.

## Build

```bash
make agent-image
```

## Run

```bash
docker run -d --name zedr-agent --restart unless-stopped \
  --pid host --network host \
  -v zedr-agent-state:/var/lib/zedr \
  -v /etc/os-release:/etc/os-release:ro \
  -v /run/systemd:/run/systemd:ro \
  -e ZEDR_SERVER_URL=https://zedr.example.com \
  -e ZEDR_ENROLLMENT_KEY=zedr_fleet_... \
  zedr-agent:dev
```

| Setting | Why |
|---|---|
| `/var/lib/zedr` volume | Holds the agent identity. A container that loses it comes back as a new agent. It also keeps the last downloaded agent and installer, so a restart works while the control server is unreachable or after the token was revoked. |
| `--pid host` | The agent sees the processes of the host, not only its own. |
| `--network host` | The agent reports the host name and address. |
| `/etc/os-release` | The console shows the host distribution instead of Alpine. |
| `/run/systemd` | Lets the agent ask the host's systemd whether the machine is shutting down. Without it every stop of the container is reported as a service stop and opens a `service_stopped` incident, also when the host powers off. |

For a control server with a private certificate authority, mount the CA file and point `SSL_CERT_FILE` at it.

Remote shell commands run inside the container as root.

Status: built and run on Docker Desktop for arm64 against a local control server, including a restart after the token was revoked. The `/run/systemd` mount was not exercised there, the Docker Desktop VM has no systemd.
