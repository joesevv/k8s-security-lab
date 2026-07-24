# Sealed-secrets install record — Phase 3 secrets management

Installed 2026-07-23 on the kind `seclab` cluster (context `kind-seclab`,
Kubernetes v1.35.5).

## Exact commands

```bash
# NOTE: the project moved GitHub orgs — the old bitnami-labs.github.io Pages
# repo now 404s. The live chart repo is bitnami.github.io/sealed-secrets.
helm repo add sealed-secrets https://bitnami.github.io/sealed-secrets
helm repo update sealed-secrets
helm search repo sealed-secrets -l | grep -E "0\.38\.4"   # resolve chart for app 0.38.4
# -> sealed-secrets/sealed-secrets  2.19.1  0.38.4  Helm chart for the sealed-secrets controller.
helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system --version 2.19.1 \
  --set fullnameOverride=sealed-secrets-controller
```

`fullnameOverride=sealed-secrets-controller` makes the controller Service and
Deployment match kubeseal's built-in default name, so `kubeseal` works with no
`--controller-name`/`--controller-namespace` flags when run interactively.

## Pinned versions (observed)

| What | Value |
| --- | --- |
| Helm chart | `sealed-secrets/sealed-secrets` **2.19.1** (pinned via `--version`) |
| App version | **0.38.4** (`helm list -n kube-system` APP VERSION) |
| Controller image | `docker.io/bitnami/sealed-secrets-controller:0.38.4` |
| Controller image digest | `sha256:ab8e4687a97fb097f30ca2f028222f779f231c224555ba05f43d172c61f84497` |

`helm list -n kube-system`:

```
NAME          	NAMESPACE  	REVISION	UPDATED                              	STATUS  	CHART                	APP VERSION
sealed-secrets	kube-system	1       	2026-07-23 17:40:26.7263997 -0500 CDT	deployed	sealed-secrets-2.19.1	0.38.4
```

The controller Deployment `sealed-secrets-controller` rolled out and the pod
went 1/1 Running within ~20s. On first start it generated its RSA keypair and
stored the private half as a Secret in `kube-system`
(`name=sealed-secrets-key2t2vk`) — that private key never leaves the cluster.

## Served SealedSecret apiVersion (resolved on-cluster)

`kubectl api-resources | grep -i sealed`:

```
sealedsecrets                                    bitnami.com/v1alpha1              true         SealedSecret
```

The cluster serves **`bitnami.com/v1alpha1`**. This `v1alpha1` is CORRECT and
expected for the sealed-secrets controller — the lab's "avoid v1alpha1" rule is
Kyverno-specific and does NOT apply here. `kubectl get crd | grep -i sealed`
confirms the CRD is installed:

```
sealedsecrets.bitnami.com                               2026-07-23T22:40:26Z
```

## Admission note

The four Phase 2b Kyverno `ValidatingPolicy` rules are scoped to the `demo`
namespace and target Pods; the controller runs in `kube-system` and the
`SealedSecret`/`Secret` objects are not Pods, so no admission conflict occurs.
The controller pod was admitted and reached Ready with no webhook rejection.
