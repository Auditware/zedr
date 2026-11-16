# AWS reference module

One EC2 box running k3s, ready for the [ArgoCD bootstrap](../../argocd/README.md) that pulls the zedr chart. No load balancer and no NAT gateway.

## What it creates

| Resource | Notes |
|---|---|
| EC2 instance, `t4g.small` (arm64) by default | Ubuntu 24.04, IMDSv2 only |
| Root volume, 30 GB gp3, encrypted | Holds the OS, the images, the database and the Kubernetes Secrets |
| Elastic IP | Stable address for your DNS record |
| VPC `10.0.0.0/16`, one public subnet, internet gateway, route table | The range stays clear of the k3s pod range `10.42.0.0/16` |
| Security group | 443 from anywhere, 22 and 6443 from `admin_cidr` only. Port 80 stays closed. |
| Key pair | From `ssh_public_key` |

cloud-init installs the pinned k3s with `--secrets-encryption --disable-cloud-controller --disable traefik`, and copies `bootstrap.sh`, `appproject.yaml` and `root-app.yaml` to `/opt/zedr`. It does not run the bootstrap. The bootstrap needs the registry token, and that token must not end up in user data or in the Terraform state, so you type it on the box.

Traefik is disabled because the k3s service load balancer can give port 443 to one Service only, and the control server terminates TLS itself.

DNS is yours. The module creates no hosted zone and outputs the public IP.

## Cost

us-east-1, on demand, per month: `t4g.small` about $12, 30 GB gp3 about $2.40, public IPv4 about $3.65. Roughly $18, plus data transfer.

`t4g.small` has 2 GB of memory, which is tight for k3s together with ArgoCD. `t4g.medium` (4 GB) costs about $12 more.

## Apply

```bash
aws sso login --profile <profile>
export AWS_PROFILE=<profile>
aws sts get-caller-identity

cp terraform.tfvars.example terraform.tfvars
terraform init
terraform plan
terraform apply
```

Terraform reads the standard AWS credential chain. No credential is stored in this module. `terraform.tfvars`, `terraform.tfstate` and `.terraform/` must stay out of git.

## Finish on the box

1. Create an A record for the control server host pointing at the `public_ip` output.
2. `ssh ubuntu@<public_ip>`, then follow the steps printed at login:

   ```bash
   sudoedit /opt/zedr/root-app.yaml
   sudo kubectl create namespace zedr
   sudo kubectl -n zedr create secret generic zedr-secrets ...
   sudo kubectl -n zedr create secret tls zedr-tls ...
   sudo /opt/zedr/bootstrap.sh
   sudo kubectl -n argocd get application zedr -w
   ```

   The Secret commands are in the [chart README](../../chart/README.md#install).

The kubeconfig is readable by root only. `kubectl get service -n zedr` shows the private address of the node as the external IP. That is expected: the Elastic IP maps to it.

## Changes after the first boot

cloud-init runs once. Later changes to `k3s_version` or to the files in `deploy/argocd` do not reach a running box, and the module ignores them instead of restarting the instance. Copy changed files to `/opt/zedr` yourself, or replace the instance.

## Teardown

```bash
terraform destroy
```

This deletes the box and its root volume. The volume holds the database and the Secret with the signing key. If the signing key is gone, every deployed agent has to be reinstalled. Copy the key off the box and snapshot the volume before you destroy it.

## Not done

- Applied to an AWS account for zedr: not yet. `terraform validate` is what has been run.
- No backups or snapshots of the volume.
- No remote state backend. State is local unless you add one.
- The k3s installer is fetched from get.k3s.io at boot and is not pinned by checksum.
- Hetzner and GCP modules.
