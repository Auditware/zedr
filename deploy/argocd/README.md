# ArgoCD bootstrap

The publisher pushes a release to the private registry. ArgoCD inside the customer cluster pulls it. The publisher holds no credentials into the cluster.

## What bootstrap.sh sets up

- ArgoCD in core mode at a pinned version: application controller, repo server and redis, with no API server and no UI.
- A repository Secret with the read-only credential for the private OCI chart.
- The `zedr` namespace and the image pull secret `ghcr-pull` in it, from the same credential.
- The AppProject in [appproject.yaml](appproject.yaml), limited to the chart repository, the `zedr` namespace and the kinds the chart renders.
- The Application in [root-app.yaml](root-app.yaml): the chart at a pinned version, synced automatically with prune and self-heal.

It is safe to run again. Running it with a new token replaces the stored credential.

## Use

Needs `kubectl` pointed at the cluster, and `openssl`.

1. In `root-app.yaml` set `server.url` and `server.adminAllowedCidrs`. `bootstrap.sh` refuses to run while either is empty.
2. Create the two Secrets the chart reads. The commands are in the [chart README](../chart/README.md#install).

   ```bash
   kubectl create namespace zedr
   kubectl -n zedr create secret generic zedr-secrets ...
   kubectl -n zedr create secret tls zedr-tls ...
   ```

3. Run the bootstrap. It asks for the registry username and a token with `read:packages`. Without a terminal it reads `REGISTRY_USER` and `REGISTRY_TOKEN` from the environment.

   ```bash
   ./bootstrap.sh
   kubectl -n argocd get application zedr -w
   ```

The Application is done when it reads `Synced` and `Healthy`. If it does not get there, `kubectl -n argocd describe application zedr` shows the reason, including a chart rendering error.

## Take a release

Change `targetRevision` in `root-app.yaml` to the new chart version and apply it:

```bash
kubectl apply -f root-app.yaml
```

ArgoCD pulls the chart, which carries the digest of the image built in the same pipeline run, and restarts the single pod.

## Why the manifests look the way they do

Each of these was learned by running the same layout on a sibling project.

- The ArgoCD version has to know the Kubernetes version of the cluster, or every sync stops at `Unknown`. `ARGOCD_VERSION` is pinned to v3.5.7 for k3s v1.35.
- Core mode creates no `default` project, so the AppProject is applied explicitly, and it has to allow the cluster-scoped `Namespace` for `CreateNamespace=true`.
- Core mode leaves `server.secretkey` empty and the controller complains on every loop, so the bootstrap seeds it.
- Kubernetes adds defaults to `volumeClaimTemplates`, so the Application ignores differences there.
- The repo server renders the chart without cluster access. The chart therefore uses no `lookup`, and secrets come from `secrets.mode: existing`.
- ArgoCD does not run `helm test` hooks, so the chart test pod is never created by a sync.

## Not done

- Run against a live cluster for zedr: not yet.
- cert-manager is not installed. `root-app.yaml` expects the TLS Secret to exist.
- Nothing moves `targetRevision` automatically.
- ArgoCD is installed from the manifest of a version tag and is not verified by checksum.
