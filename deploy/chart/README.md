# zedr Helm chart

Runs the zedr control server on Kubernetes.

## What it creates

| Object | When |
|---|---|
| StatefulSet with one pod and a PersistentVolumeClaim mounted at `/data` | always |
| Service on port 443 forwarding to the pod on 7770 | always |
| Secret with the three server secrets | `secrets.mode=create` |
| cert-manager Certificate | `tls.mode=certManager` |
| NetworkPolicy | `networkPolicy.enabled=true` |
| Test pod that calls `/readyz` | `helm test` |

The server terminates TLS itself and speaks only HTTPS, so there is no Ingress and no ingress controller. Agents and operators use the same port.

The database is one SQLite file on the volume. The chart always runs exactly one replica and has no value to change that.

## Install

The image and the chart are private. Create the namespace, a pull secret, the server secrets and the TLS secret, then install.

```bash
kubectl create namespace zedr

kubectl -n zedr create secret docker-registry ghcr-pull \
  --docker-server=ghcr.io --docker-username=<user> --docker-password=<token with read:packages>

(umask 077 && openssl rand -hex 32 > zedr-signing-key.hex)
kubectl -n zedr create secret generic zedr-secrets \
  --from-literal=JWT_SECRET="$(openssl rand -hex 32)" \
  --from-literal=ADMIN_PASSWORD="$(openssl rand -base64 24)" \
  --from-literal=ZEDR_SIGNING_KEY_HEX="$(cat zedr-signing-key.hex)"

kubectl -n zedr create secret tls zedr-tls --cert=fullchain.pem --key=privkey.pem

helm registry login ghcr.io
helm install zedr oci://ghcr.io/auditware/charts/zedr --version <x.y.z> --namespace zedr \
  --set server.url=https://zedr.example.com \
  --set 'server.adminAllowedCidrs={203.0.113.10/32}' \
  --set 'imagePullSecrets[0].name=ghcr-pull' \
  --set secrets.mode=existing --set secrets.existingSecret=zedr-secrets \
  --set tls.existingSecret=zedr-tls

helm -n zedr test zedr
```

Sign in to the console as `admin` with `ADMIN_PASSWORD`. The password seeds that user on the first start only.

## Values

| Value | Default | Notes |
|---|---|---|
| `server.url` | none, required | Public https origin without a path. At most 64 bytes, because the server patches it into agent binaries. Rendering fails otherwise. |
| `server.adminAllowedCidrs` | `[]` | CIDRs allowed to reach the console, `/api/admin`, `/api/auth` and `/api-docs`. Empty allows any address. Agent paths are never restricted. |
| `server.agentVersion` | `0.1.0` | Agent release handed to endpoints. The image must hold `/app/binaries/v<agentVersion>`. |
| `server.signingKeyChangeAccepted` | empty | Public key of a replaced signing key. See [Signing key](#signing-key). |
| `server.guestImageIds` | `[]` | Image IDs of the rule programs whose proofs the server accepts, 64 hex characters each, as `zedr-prover image-id` prints them. Sets `ZEDR_GUEST_IMAGE_IDS`. Empty accepts no proof, so every proof an endpoint sends opens a `proof_invalid` incident. |
| `server.proofDeadlineSecs` | `3600` | Seconds an endpoint with a prover has to prove a sealed window before a `proof_overdue` incident opens. Sets `ZEDR_PROOF_DEADLINE_SECS`. |
| `server.logLevel` | empty | Sets `ZEDR_LOG_LEVEL`. |
| `secrets.mode` | `create` | `create` renders a Secret from `secrets.jwtSecret`, `secrets.adminPassword` and `secrets.signingKeyHex`, all required. `existing` reads `secrets.existingSecret`, which must hold the keys `JWT_SECRET`, `ADMIN_PASSWORD` and `ZEDR_SIGNING_KEY_HEX`. |
| `tls.mode` | `existingSecret` | `existingSecret` mounts the `kubernetes.io/tls` Secret named in `tls.existingSecret`. `certManager` requests a Certificate for the host of `server.url` from `tls.certManager.issuerRef`. |
| `service.type` | `LoadBalancer` | |
| `service.port` | `443` | |
| `service.externalTrafficPolicy` | `Local` | Keeps the client address. With `Cluster` the server sees a cluster address and `server.adminAllowedCidrs` rejects every operator. |
| `service.annotations` | `{}` | For cloud load balancer settings. |
| `persistence.size` | `10Gi` | Fixed after install, a StatefulSet cannot change its volume claim. |
| `persistence.storageClassName` | empty | Empty uses the default StorageClass. |
| `networkPolicy.enabled` | `false` | Denies everything except the server port in, and DNS and port 443 out. |
| `image.digest`, `image.tag` | empty | A digest wins over a tag. Released charts carry the digest of the image built in the same pipeline run. |
| `imagePullSecrets` | `[]` | |
| `test.image` | `curlimages/curl:8.23.0` | Image of the `helm test` pod. |

Use `secrets.mode=existing` with ArgoCD or any other GitOps tool, so that no secret is stored in the values. The chart never uses `lookup` and never generates a value, so it renders the same without cluster access.

## Signing key

`ZEDR_SIGNING_KEY_HEX` is the 32 byte Ed25519 seed, as 64 hex characters, that signs agent binaries and commands.

- Generate one per deployment with `openssl rand -hex 32`. The server patches the matching public key into every agent it serves, so agents trust this deployment and no other ([ADR 017](../../docs/adr/017-per-deployment-signing-key.md)).
- Move `zedr-signing-key.hex` from the install step to a place outside the cluster. If the key is lost or replaced, every deployed agent has to be reinstalled.
- The server records its public key on the first start. When the key in the Secret changes while agents are enrolled, the server refuses to start and the pod log names the old and the new public key. Put the old key back, or reinstall the agents and set `server.signingKeyChangeAccepted` to the new public key from that log line. The value only covers that one key, so it can stay set.

## TLS

Endpoints and browsers must trust the certificate for the host in `server.url`.

- Bring your own: put the certificate chain and key in a `kubernetes.io/tls` Secret and name it in `tls.existingSecret`.
- cert-manager: install cert-manager and an Issuer or ClusterIssuer yourself and name it in `tls.certManager.issuerRef`. There is no ingress controller, so an HTTP-01 solver has nothing to route through. Use a DNS-01 solver or a private CA issuer.

The server reads the certificate at startup only. After a renewal, restart the pod with `kubectl -n zedr rollout restart statefulset/zedr`.

## Upgrade

```bash
helm upgrade zedr oci://ghcr.io/auditware/charts/zedr --version <x.y.z> --namespace zedr --reuse-values
```

The single pod restarts, the server drains for 10 seconds, and agents retry until it is back. Database migrations run at startup.

## Not done

- No backup of the database or the signing key. Snapshot the volume and keep the key elsewhere.
- No certificate reload without a restart.
- No high availability, one SQLite file means one replica.
- Installed and tested on a live cluster: not yet. Rendering and linting are what has been run.
