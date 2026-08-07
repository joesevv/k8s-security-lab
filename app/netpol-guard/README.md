<!-- Phase 8 — explains the one invariant this controller enforces, why no
     admission policy can enforce it, and how to run it in both modes. -->
# netpol-guard — phase-8 reconciliation controller

A small Go controller that enforces exactly one invariant in one namespace:

> **Every pod in the namespace must be selected by a NetworkPolicy for BOTH
> `Ingress` and `Egress`.**

Kubernetes semantics: a pod is *isolated* for a direction when **any**
NetworkPolicy selects it and lists that direction in `policyTypes`; an empty
`podSelector` (`{}`) selects every pod in the namespace. The controller
computes this with `metav1.LabelSelectorAsSelector`, so the empty selector
becomes `labels.Everything()` rather than "matches nothing" — the single most
important detail in the whole program.

## Why admission control cannot do this

Admission validates **the object being written**. The failure this controller
catches is caused by **deleting an unrelated object**:

```
kubectl delete networkpolicy default-deny -n demo
```

At that moment no pod is created, updated, or touched in any way. There is no
`AdmissionReview` for `signed-app` — so there is nothing for a Kyverno
`ValidatingPolicy` or a Pod Security Admission profile to evaluate, and the pod
silently loses its Ingress protection while running. This is a structural
limit, not a gap in this lab's policy set: all five Kyverno policies here match
`pods`/`deployments`/`jobs` on `CREATE, UPDATE` only, and none of them match
`networkpolicies` at all.

Only something that **continuously reconciles observed cluster state** can
notice. That is what this is.

It also closes a gap phase 7 measured rather than assumed: ArgoCD's
`demo-workloads` Application syncs `workloads/` only, so `network/` is outside
its scope — phase 7 drifted an out-of-scope object and ArgoCD reported `Synced`
throughout. Nothing on this cluster noticed a deleted NetworkPolicy before
phase 8.

## Two modes, one flag apart

| flag | behaviour |
| --- | --- |
| `--remediate=false` *(default)* | Detect only. Reports the violation on every scan, forever, and changes nothing. |
| `--remediate=true` | Creates the baseline `default-deny` NetworkPolicy when it is absent. Idempotent. |

Detect-only is the default on purpose: a controller that writes to the cluster
should be an opt-in decision recorded in a manifest, not an inherited default.

**It never updates and never deletes.** Its only write is a single `Create` of
`default-deny`, and its RBAC (`docs/evidence/phase-8-netpol-guard/rbac.yaml`)
grants no `update`, `patch` or `delete` verb — so that promise is enforced by
the apiserver, not merely by the code.

## Flags

```
--namespace   string    namespace to check                       (default "demo")
--remediate   bool      restore the baseline when violated       (default false)
--interval    duration  time between scans                       (default 30s)
--kubeconfig  string    path to a kubeconfig; in-cluster when empty
--once        bool      one scan, then exit; exit 1 on a violation in detect-only mode
```

There is no silent fallback from in-cluster config to `~/.kube/config`. A
controller that quietly picks up an operator's admin credentials when its
ServiceAccount token is missing is a security bug, not a convenience.

## Running it

**`go` is not on `PATH` in non-interactive shells on the lab host.** Use the
absolute path, the same way this repo does for `gh`:

```sh
"C:\Program Files\Go\bin\go.exe" build ./...
"C:\Program Files\Go\bin\go.exe" vet ./...
"C:\Program Files\Go\bin\go.exe" test ./...
```

Out of cluster, against a kubeconfig — this is how phase 8 was demonstrated:

```sh
# detect only, one scan, non-zero exit if the invariant is broken
"C:\Program Files\Go\bin\go.exe" run . \
  --kubeconfig=C:/Users/josep/.kube/config --namespace=demo --once

# detect only, continuous
"C:\Program Files\Go\bin\go.exe" run . \
  --kubeconfig=C:/Users/josep/.kube/config --namespace=demo --interval=15s

# remediate
"C:\Program Files\Go\bin\go.exe" run . \
  --kubeconfig=C:/Users/josep/.kube/config --namespace=demo --interval=15s --remediate=true
```

In cluster: `docs/evidence/phase-8-netpol-guard/` holds a `Deployment`,
`ServiceAccount`, `Role` and `RoleBinding`. **They are committed UNAPPLIED and
would fail today.** The image has never been published (CI builds only
`app/signed-app`, and only on push to `main`), the
`require-keyless-signed-ghcr` policy would deny an unsigned
`ghcr.io/joesevv/k8s-security-lab/*` image in `demo`, phase 5b's
`AlwaysPullImages` rules out `kind load` as a workaround, and a pod in `demo`
cannot reach the apiserver under the very `default-deny` baseline it is
guarding. Each of those is stated in full in the manifests themselves.

## Local image build (verification only — do not push)

```sh
docker build -t netpol-guard:localtest app/netpol-guard
docker run --rm netpol-guard:localtest --help
docker inspect -f 'User={{.Config.User}}' netpol-guard:localtest   # 65532:65532
```

## What it does NOT check

- **Rules.** It verifies that isolation *exists*, not that the policies are
  *correct*. A NetworkPolicy that selects every pod for both directions and
  then allows `0.0.0.0/0` would satisfy this invariant completely.
- **Other namespaces.** One namespace per process, `demo` by default.
- **Anything but NetworkPolicies vs Pods.** Not Services, not Ingress, not
  CNI enforcement. It reads the API's intent; phase 8's evidence proves
  enforcement separately with a real reachability probe.
- **Terminal pods.** Pods in `Succeeded`/`Failed` are skipped — they have no
  running container to protect, and counting them would make any namespace
  that has ever run a Job permanently "violating".
- **The gap.** It reconciles on a timer, so there is a real window — up to one
  `--interval` — in which a pod is unprotected and no one has noticed yet.
  Phase 8 measured 6.950 s of that window with `--interval=15s`. A controller
  shrinks this window; only admission control could make it zero, and
  admission control structurally cannot see this event at all.
