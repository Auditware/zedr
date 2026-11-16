# Installing agents

Every recipe here enrolls with a fleet enrollment token ([ADR 019](../../docs/adr/019-fleet-enrollment-tokens.md)). One token enrolls every machine that presents it until it expires, reaches its use cap or is revoked.

| Where the agent runs | Recipe |
|---|---|
| One Linux server with systemd | The one-liner below |
| EC2 instance or autoscaling group | [ec2](./ec2/README.md) |
| Docker or another container host | [container](./container/README.md) |
| Kubernetes nodes | [kubernetes](./kubernetes/README.md) |

## Create a token

An admin creates the token through the API. The token is shown once.

```bash
curl -fsS -X POST "$ZEDR_SERVER_URL/api/admin/enrollment-tokens" \
  -H "Authorization: Bearer $ZEDR_ADMIN_JWT" -H 'Content-Type: application/json' \
  -d '{"label": "prod-web", "expires_in_days": 90, "max_uses": 500}'
```

`label` becomes the group of every agent the token enrolls. `expires_in_days` is required, 1 to 365. `max_uses` is optional. The response carries `token` and ready `linux_command` and `windows_command` lines.

List tokens with their use count with `GET /api/admin/enrollment-tokens`, revoke one with `DELETE /api/admin/enrollment-tokens/<id>`. Revoking stops new enrollments. Agents that already enrolled keep working.

## One Linux server

```bash
curl -fsSL -H 'X-Zedr-Enrollment-Key: zedr_fleet_...' https://zedr.example.com/install.sh | sudo sh
```

The script installs the static agent to `/usr/local/bin/zedr-agent`, keeps its identity in `/var/lib/zedr` (root only), writes `zedr-agent.service`, starts it and waits until the agent has enrolled. Running it again replaces the binary and restarts the service, the machine stays the same agent and uses no further token use.

Needs systemd, `curl` or `wget`, and x86_64 or arm64.

## Rotating a token

Create a new token with the same label, put it where the old one was (launch template, secret store, Kubernetes Secret), then revoke the old one. Enrolled agents are not affected.
