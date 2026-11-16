#!/usr/bin/env bash
set -euo pipefail

ARGOCD_VERSION="${ARGOCD_VERSION:-v3.5.7}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_APP="${HERE}/root-app.yaml"

die() {
  echo "bootstrap: $*" >&2
  exit 1
}

# A no-op local patch makes kubectl parse the manifest without contacting the cluster.
root_app_field() {
  kubectl patch --local -f "${ROOT_APP}" --type merge -p '{}' -o "jsonpath=$1"
}

chart_repo="$(root_app_field '{.spec.source.repoURL}')"
app_namespace="$(root_app_field '{.spec.destination.namespace}')"
pull_secret="$(root_app_field '{.spec.source.helm.valuesObject.imagePullSecrets[0].name}')"
server_url="$(root_app_field '{.spec.source.helm.valuesObject.server.url}')"
admin_cidrs="$(root_app_field '{.spec.source.helm.valuesObject.server.adminAllowedCidrs[*]}')"

[[ -n "${chart_repo}" ]] || die "spec.source.repoURL is empty in ${ROOT_APP}"
[[ -n "${app_namespace}" ]] || die "spec.destination.namespace is empty in ${ROOT_APP}"
[[ -n "${pull_secret}" ]] || die "imagePullSecrets is empty in ${ROOT_APP}"
[[ -n "${server_url}" ]] || die "set server.url in ${ROOT_APP}"
[[ -n "${admin_cidrs}" ]] || die "set server.adminAllowedCidrs in ${ROOT_APP}. Opening the console to any address has to be written out as 0.0.0.0/0 and ::/0"

if [[ -t 0 ]]; then
  [[ -n "${REGISTRY_USER:-}" ]] || read -rp "Registry username: " REGISTRY_USER
  if [[ -z "${REGISTRY_TOKEN:-}" ]]; then
    read -rsp "Registry token (read:packages): " REGISTRY_TOKEN
    echo
  fi
fi
: "${REGISTRY_USER:?REGISTRY_USER is required}"
: "${REGISTRY_TOKEN:?REGISTRY_TOKEN is required}"

registry="${chart_repo%%/*}"

kubectl create namespace argocd --dry-run=client -o yaml | kubectl apply -f -
kubectl apply -n argocd --server-side --force-conflicts \
  -f "https://raw.githubusercontent.com/argoproj/argo-cd/${ARGOCD_VERSION}/manifests/core-install.yaml"
kubectl -n argocd rollout status deployment/argocd-repo-server --timeout=300s
kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=300s

# Core mode has no API server to create this key, and the controller logs an error on every loop without it.
if ! kubectl -n argocd get secret argocd-secret -o jsonpath='{.data.server\.secretkey}' | grep -q .; then
  kubectl -n argocd patch secret argocd-secret --type merge --patch-file /dev/stdin <<JSON
{"stringData":{"server.secretkey":"$(openssl rand -base64 32)"}}
JSON
fi

kubectl apply -f - <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: repo-zedr-charts
  namespace: argocd
  labels:
    argocd.argoproj.io/secret-type: repository
stringData:
  name: zedr-charts
  type: helm
  url: "${chart_repo}"
  enableOCI: "true"
  username: "${REGISTRY_USER}"
  password: "${REGISTRY_TOKEN}"
YAML

kubectl create namespace "${app_namespace}" --dry-run=client -o yaml | kubectl apply -f -
registry_auth="$(printf '%s:%s' "${REGISTRY_USER}" "${REGISTRY_TOKEN}" | base64 | tr -d '\n')"
kubectl apply -f - <<YAML
apiVersion: v1
kind: Secret
metadata:
  name: "${pull_secret}"
  namespace: "${app_namespace}"
type: kubernetes.io/dockerconfigjson
stringData:
  .dockerconfigjson: '{"auths":{"${registry}":{"auth":"${registry_auth}"}}}'
YAML

kubectl apply -f "${HERE}/appproject.yaml"
kubectl apply -f "${ROOT_APP}"
