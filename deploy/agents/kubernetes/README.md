# Kubernetes DaemonSet

[`daemonset.yaml`](./daemonset.yaml) runs one agent on every node, including control plane nodes.

## Install

1. Build and push the [agent image](../container/README.md) to a registry your nodes can pull from, and set `image` in the manifest. The image is not published by the release workflow yet.
2. Set `server-url` and `enrollment-key` in the Secret, or create the Secret from your secret store and remove it from the file.
3. Apply it.

```bash
kubectl apply -f deploy/agents/kubernetes/daemonset.yaml
kubectl -n zedr-agent rollout status daemonset/zedr-agent
```

## What the pod gets

| Setting | Why |
|---|---|
| `hostPath /var/lib/zedr` | The identity stays on the node, so a restarted pod is the same agent. A replaced node is a new agent. |
| `hostPID`, `hostNetwork` | The agent sees the node's processes and reports the node's name and address. |
| `hostPath /run/systemd`, read only | The agent asks the node's systemd whether the node is shutting down. |
| `hostPath /etc/os-release`, read only | The console shows the node's distribution. |
| `privileged` | Remote shell commands run as root in the pod, and from there `nsenter -t 1 -m -u -i -n` reaches the node. |
| `system-node-critical`, tolerates every taint | The agent is scheduled on every node and evicted last. |

For a control server with a private certificate authority, mount the CA from a ConfigMap and set `SSL_CERT_FILE` to its path.

## Things to know

- Deleting the pod or rolling the DaemonSet stops the agent while the node keeps running. That is reported as a service stop and opens a `service_stopped` incident, which closes when the new pod reports.
- A node that shuts down is reported as a shutdown only when the pod is stopped while systemd is already stopping the node. With kubelet graceful node shutdown the pods are stopped before that point, so the node is reported as a service stop.
- An expired or revoked token does not stop pods on enrolled nodes. They start the agent that is kept in `/var/lib/zedr`.
