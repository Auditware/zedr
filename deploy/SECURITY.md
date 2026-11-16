# Exposure model of a zedr deployment

The control server terminates TLS itself and listens on one port. Agents on endpoints and operators in browsers both connect to it. There is no ingress controller, reverse proxy or load balancer in front that could filter by path, so the split between the agent surface and the operator surface is enforced inside the server, against the address of the connecting peer.

Everything else on the box is reachable from the admin network only, or not at all.

## Surfaces

| Surface | Exposure | Control | Status |
|---|---|---|---|
| Agent paths: `/install.ps1`, `/install.sh`, `/api/installers/binaries/*`, `/api/agents/*`, `/api/events`, `/api/windows`, `/api/proofs` | Public, port 443 | TLS in the server. Install keys for downloads, signed requests per agent identity for the rest. | Enforced by the server |
| Operator paths: console, `/api/admin/*`, `/api/auth/*`, `/api-docs/*` | Port 443, limited to `server.adminAllowedCidrs` | Peer address checked in the server before any handler, then login, optional MFA, or an API key. An unknown peer address is denied. | Enforced once `server.adminAllowedCidrs` is set. Empty means any address. `bootstrap.sh` refuses an empty list. |
| Health: `/healthz`, `/readyz`, `/health` | Public, port 443, no authentication | Return status only. `/health` also returns the server version. | By design, the kubelet probes them |
| Client address seen by the server | n/a | `service.externalTrafficPolicy: Local`, the chart default. With `Cluster` the server sees a cluster address and the allowlist rejects every operator. | Enforced by the chart default |
| SQLite database | Not exposed | A file on the volume mounted at `/data` of the single pod | By construction |
| JWT secret, admin password, signing key, TLS key | Not exposed | Kubernetes Secrets, mounted or injected into the one pod. Secrets are encrypted at rest by `k3s --secrets-encryption`. The root volume is encrypted. | Enforced by the chart and cloud-init |
| Container | n/a | Distroless image, uid 65532, read-only root filesystem, all capabilities dropped, seccomp RuntimeDefault, no service account token | Enforced by the chart |
| Pod network | n/a | NetworkPolicy: the server port in, DNS and 443 out | Optional, `networkPolicy.enabled` |
| ArgoCD | Not exposed | Core mode has no API server and no UI. Reached with `kubectl` only. | By construction |
| Kubernetes API 6443, SSH 22 | `admin_cidr` only | Security group. SSH with keys only. The kubeconfig is readable by root only. | Enforced by Terraform and cloud-init |
| Port 80 and every other port | Closed | Security group. Traefik is disabled, nothing listens on 80. | Enforced by Terraform and cloud-init |
| Instance metadata | Host only | IMDSv2 required, hop limit 1, no instance role | Enforced by Terraform |
| Image and chart | Private registry | Read-only token, typed into `bootstrap.sh` on the box. It is stored in two Secrets in the cluster and nowhere in Terraform state or user data. | Enforced by the release workflow and the bootstrap |
| Publisher access | None | Pull over push: the cluster pulls a pinned chart version, the chart pins the image digest. The publisher holds no credential into a deployment. | By construction |

## Not done

- The image has not been built and nothing has been installed on a cluster or applied to a cloud account. Chart rendering, Terraform validation and script linting are what has been run.
- Signing key rotation. Each deployment generates its own key and the server patches the public half into every agent it serves ([ADR 017](../docs/adr/017-per-deployment-signing-key.md)). Agents keep the key they were installed with, so replacing `ZEDR_SIGNING_KEY_HEX` strands them until they are reinstalled. The server refuses to start with a changed key while agents are enrolled, unless `server.signingKeyChangeAccepted` names the new public key, and there is still no way to move enrolled agents to a new key.
- Backups. Nothing snapshots the volume or exports the signing key. Losing the key strands every deployed agent.
- Certificate reload. The server reads its certificate at startup, so a renewed certificate is served only after the pod restarts.
- Rate limiting and brute-force protection on the public port. The server is directly on the internet with nothing in front.
- A proxy or CDN in front. The server trusts the TCP peer address and reads no forwarding header, so behind a proxy every client looks like the proxy and the allowlist stops working.
- High availability. One SQLite file means one replica, and an upgrade restarts it.
- External secret stores. `secrets.mode: existing` accepts a Secret written by any operator, but none is wired up.
- Egress filtering beyond ports. The optional NetworkPolicy allows 443 to any destination, and the security group allows all outbound traffic.
- Verification of what is pulled. The image carries provenance and an SBOM, but nothing is signed and the cluster verifies no signature. Base images are pinned by tag, the k3s installer and the ArgoCD manifest are fetched by version without a checksum.
- Reproducible server builds. `Cargo.lock` is not committed, so a release build resolves dependency versions at build time.
- Operating system patching of the box beyond the Ubuntu defaults.
