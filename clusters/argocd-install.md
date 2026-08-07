# ArgoCD install record — Phase 7 GitOps drift control

Installed 2026-08-07 on the kind `seclab` cluster (context `kind-seclab`,
Kubernetes v1.35.5).

ArgoCD is a RECONCILER, not an admission controller. It is not in the request
path and it cannot refuse a write. Everything it does happens after the
apiserver has accepted a change and after the kubelet has started the
resulting pod — which is why phase 7 is structured as two runs of the same
drift, one with `selfHeal: false` and one with `selfHeal: true`, and why even
the second one leaves a measured window in which a weakened container really
ran. It is also the first component in this lab that can WRITE to the cluster
rather than merely watch it, and it granted itself cluster-admin to do so, so
that grant is written down here rather than assumed. See
`runbooks/phase-7-argocd.md` and `docs/evidence/phase-7-argocd/` for the
demonstration and the honest limits.

This record follows the **falco model**: the install is a small number of
commands, every pin and every deliberate omission is justified in prose
immediately below, and the record is written so the install replays from what
is on this page. It differs from the falco and sealed-secrets records in one
way: there is no Helm chart here, so there are no `--set` overrides to
justify. What has to be justified instead is a URL, a hash, and the three
fields on one `Application`.

## Exact commands

```bash
# 1. Resolve what "stable" actually means today, rather than trusting the ref.
#    NOTE: git ls-remote returns the ANNOTATED TAG OBJECT; ^{} peels it to the
#    commit. Both refs below are annotated tags sharing one tag object.
git ls-remote https://github.com/argoproj/argo-cd.git 'refs/tags/stable*' 'refs/tags/v3.5.0*'
# -> f8a2c4798f39c36175580f97266ad7ec64d48344  refs/tags/stable
# -> e95e1be88a2da6c06bff5c2fe1791e4d233ed810  refs/tags/stable^{}
# -> f8a2c4798f39c36175580f97266ad7ec64d48344  refs/tags/v3.5.0
# -> e95e1be88a2da6c06bff5c2fe1791e4d233ed810  refs/tags/v3.5.0^{}

# 2. Fetch the manifest ONCE and hash it. There is no install.yaml asset on the
#    GitHub release (only cli_checksums.txt and sbom.tar.gz), so the manifest
#    comes from the manifests/ path at the pinned tag.
curl -sSL https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.0/manifests/install.yaml > install.yaml
sha256sum install.yaml
# -> a32bf36a437071a1f563ebf9e81c8a39fba9057c17db7d5d041afb7b6e3f4afe *install.yaml
#    1917766 bytes, 34050 lines. Fetching the same path by the PEELED COMMIT
#    e95e1be8 yields a byte-identical file (cmp exit 0), which proves the tag
#    had not been repointed between the two reads.

# 3. Namespace first, so its (absent) admission posture is a visible line in
#    this record rather than something inherited silently. See the admission
#    note below — it gets the built-in `privileged` default.
kubectl create namespace argocd

# 4. Install. --server-side is REQUIRED here, not stylistic; see below.
kubectl apply -n argocd --server-side \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.0/manifests/install.yaml
# -> 59 objects serverside-applied, first attempt, no retry.

# 5. Wait for all 7 workloads (6 Deployments + 1 StatefulSet).
for d in argocd-applicationset-controller argocd-dex-server \
         argocd-notifications-controller argocd-redis \
         argocd-repo-server argocd-server; do
  kubectl -n argocd rollout status deploy/$d --timeout=300s
done
kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=300s
# -> all up 17:59:33Z -> 18:00:06Z = 33 s.

# 6. The Application. Committed at gitops/application-workloads.yaml, and it
#    carries the FINAL posture (prune:false, selfHeal:true), so this apply is
#    all a replay needs — step 7 is history, not a required step.
kubectl apply -f gitops/application-workloads.yaml

# 7. The patch that moved the LIVE Application to its final posture on
#    2026-08-07, when the committed file still carried selfHeal:false. The
#    file has since been corrected to true, so re-running this is a no-op;
#    it is kept because it is what was actually executed, and its timestamp
#    (18:16:44Z) is the start of the stage-2 measurement in the runbook.
kubectl -n argocd patch application demo-workloads --type=merge \
  -p '{"spec":{"syncPolicy":{"automated":{"selfHeal":true}}}}'
```

**Why a version-pinned URL and not `stable`.** ArgoCD's own documentation
installs from `.../argo-cd/stable/manifests/install.yaml`. `stable` is a
moving ref: it is repointed at each release, so the same command produces
different bytes on different days and the install is not replayable. Pinning
`v3.5.0` fixes the bytes. The reason to trust that particular version is
recorded rather than asserted — `refs/tags/stable` and `refs/tags/v3.5.0` were
resolved side by side and peel to the same commit, so on 2026-08-07 the pin
installs exactly what `stable` would have installed, and unlike `stable` it
still will next month. v3.5.0 was published 2026-08-04 and is not a
prerelease.

**Why the manifest is NOT committed to this repo.** It is 34050 lines of
vendored upstream YAML. Committing it would put an unreviewable blob in a
repository whose whole point is that every object is small enough to read, and
it would rot silently against the URL it came from. The URL, the sha256
`a32bf36a...b6e3f4afe`, and the resolved image digests below are the
reproducibility record: anyone can re-fetch and re-hash to prove they are
installing the same bytes. That is a stronger guarantee than a stale copy.

**Why `--server-side`.** A client-side apply writes the entire submitted
object into a `kubectl.kubernetes.io/last-applied-configuration` annotation.
For ArgoCD's three CRDs that annotation exceeds the apiserver's 262144-byte
metadata limit and the apply fails. `--server-side` uses field management
instead of the annotation and has no such limit. This is a hard requirement of
installing this manifest, not a preference.

**Why no Ingress, no NodePort, no LoadBalancer.** `argocd-server` is left as
the ClusterIP the upstream manifest creates. Exposing it would put a web
console backed by a cluster-admin-capable API server on a lab host's network
for no benefit — phase 7 needs no UI at all, and every observation in its
evidence comes from `kubectl` against the `Application` CR and the live
objects. Access, if a human wants it, is `kubectl -n argocd port-forward
svc/argocd-server 8080:443`.

**No credential was retrieved.** The install creates
`argocd-initial-admin-secret`. It was never read, decoded or used; the UI was
never logged into and the `argocd` CLI was never installed. Rotating that
password and deleting the initial secret is the normal next step for a real
deployment and is **not** done here — which means the default admin
credential is still live in this cluster, behind components that can `delete`,
`get` and `patch` any resource of any kind. That is a known, unremediated gap,
not an oversight.

## Pinned versions (observed)

| What | Value |
| --- | --- |
| Manifest URL | `https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.0/manifests/install.yaml` |
| Manifest sha256 | `a32bf36a437071a1f563ebf9e81c8a39fba9057c17db7d5d041afb7b6e3f4afe` (1917766 bytes, 34050 lines) |
| Tag object | `f8a2c4798f39c36175580f97266ad7ec64d48344` (`refs/tags/v3.5.0`, and `refs/tags/stable` on this date) |
| Peeled commit | `e95e1be88a2da6c06bff5c2fe1791e4d233ed810` |
| argocd image | `quay.io/argoproj/argocd:v3.5.0` (5 of the 7 pods) |
| argocd digest | `sha256:c298cedbaeb31532ba8d4e9904eba9e4987e067293fbd86400c5194e78f743d5` |
| dex image | `ghcr.io/dexidp/dex:v2.45.0` |
| dex digest | `sha256:b8469881d3cb3a73001506f0d3aaefecb9c45d2311c1e0f405d8ac538316c59d` |
| redis image | `public.ecr.aws/docker/library/redis:8.2.3-alpine` |
| redis digest | `sha256:08ad0b1d280850169a790dba1393ff7a90aef951fc19632cf4d3ce4f78e679ba` |

**Read the image rows, not just the digest rows.** Upstream's manifest pins by
TAG — `:v3.5.0`, `:v2.45.0`, `:8.2.3-alpine`. The digests above are what those
tags resolved to on 2026-08-07 in this cluster, read from
`.status.containerStatuses[*].imageID` on the running pods rather than from
the manifest. They are a RECORD, not a CONTROL: nothing here stops the
upstream tags being repointed, and this repo neither mirrors nor re-pins them.
That is a real difference from phase 4, where the repo's own workloads are
digest-pinned in git AND enforced by `restrict-registries` and
`require-keyless-signed-ghcr`. Every ArgoCD pod genuinely pulled on start —
the apiserver runs `--enable-admission-plugins=NodeRestriction,AlwaysPullImages`
— so these digests are what was actually fetched, not what a cached layer
happened to be.

## What the install granted itself

`kubectl get clusterrole argocd-application-controller -o jsonpath='{.rules}'`
returns:

```
[{"apiGroups":["*"],"resources":["*"],"verbs":["*"]},{"nonResourceURLs":["*"],"verbs":["*"]}]
```

That was diffed against `cluster-admin`'s rules rather than eyeballed, and the
two are **byte-identical**. The ServiceAccount `argocd-application-controller`
in namespace `argocd` is cluster-admin: it can read every Secret in every
namespace, including the sealed-secrets controller's private key and every
ServiceAccount token in the cluster. `argocd-server` — the component behind
the web console — separately holds `delete`, `get` and `patch` on `*/*`
cluster-wide.

This makes the threat model's §A2 "compromised GitOps controller" concrete
rather than hypothetical. **An Application in this cluster is scoped by
convention — its `source.path` — never by capability.** Nothing in the RBAC
constrains the blast radius of a mis-scoped or malicious Application, and the
`default` AppProject that could constrain it is wide open out of the box:
`sourceRepos: ["*"]`, `destinations: [{namespace:"*",server:"*"}]`,
`clusterResourceWhitelist: [{group:"*",kind:"*"}]`. Tightening the project, or
running the controller with a namespaced Role instead of the shipped
ClusterRole, is the obvious hardening and is **not** done here.

## Admission note

The `argocd` namespace carries **no Pod Security labels at all** —
`kubectl get ns argocd -o jsonpath='{.metadata.labels}'` returns only
`{"kubernetes.io/metadata.name":"argocd"}` — so it gets the built-in
`privileged` default, and this cluster's apiserver has no
`--admission-control-config-file` that could change that default. All five
Kyverno policies (`disallow-latest-and-bare-tag`,
`disallow-privileged-containers`, `require-drop-all-capabilities`,
`restrict-registries`, `require-keyless-signed-ghcr`) match on
`namespaceSelector` values `[demo, demo-kyverno-only]`, verified by reading
`.spec.matchConstraints.namespaceSelector` off each live policy. `argocd` is
not one of them.

So ArgoCD's 7 pods were admitted with no Pod Security check and no Kyverno
check whatsoever. **This is the third unenforced namespace in the lab, after
`cis-benchmark` and `falco`** — and unlike those two, this one holds a
controller that can write to every object in the cluster. Any pinning applied
to ArgoCD in this repo is self-imposed and self-verified against the live
objects, exactly as phase 6b said of Falco. Unlike the falco namespace, no
`warn: restricted` label was added here, so the install printed no PSA
warnings and this record cannot say which `restricted` categories ArgoCD's
workloads would violate. That was not measured and is not claimed.

## The Application, and the three choices in it

`gitops/application-workloads.yaml` is committed as a topic directory parallel
to `policies/`, `network/`, `rbac/` and `workloads/`, because an `Application`
is durable infrastructure rather than a probe — probes live under
`docs/evidence/`. It deliberately does not live in `workloads/`, which is the
path it syncs: an Application CR placed there would make ArgoCD apply its own
definition into namespace `demo`, where the controller does not read
Application CRs. That is a self-reference bug, not a layout preference.

**`prune: false`.** A drift demo never needs deletion, and the downside of
getting it wrong is severe rather than annoying. The `demo` namespace holds
the `developer` Role and RoleBinding, four NetworkPolicies and a SealedSecret
that are deliberately NOT in `workloads/`. A mis-scoped Application with
pruning on is pointed at exactly those objects. With `prune: false` the blast
radius of a scoping mistake is capped at "does nothing".

**`targetRevision: main`.** `workloads/` is unchanged on `main`, so the demo
runs against merged code rather than chasing an in-flight branch. The repo is
public, so the clone is anonymous — there is no credential and no repository
Secret anywhere in this phase.

**`directory.recurse: true`.** This one is a correction, and it is recorded
because the failure mode is dangerous. The Application was first applied
without it. All seven manifests live one level down
(`workloads/nginx/`, `workloads/signed-app/`) and a plain directory source
does not recurse, so ArgoCD found zero manifests, had zero desired state, and
reported **`Synced / Healthy` while managing nothing at all**. A green
Application that is protecting nothing is indistinguishable from a green
Application that is protecting everything unless you count
`.status.resources`. After the fix it reports exactly 7 resources — the 7
objects in `workloads/` and nothing else in the namespace.

**No `resources-finalizer.argocd.argoproj.io` finalizer**, deliberately. With
it, deleting the Application cascades a delete to all 7 managed objects,
including the `demo` Namespace itself. Teardown should remove the GitOps
controller, not the workloads it happened to be watching.

**`selfHeal: true`, and how stage 1 is reached without committing it.** The
committed file carries `selfHeal: true`, which is the posture the cluster is
left in, so the manifest and the live object agree and re-applying the file is
idempotent. That direction was chosen deliberately: the file is the intended
end state, and a repo that shipped `selfHeal: false` would describe a weaker
posture than the one actually running, which is the failure this phase is
about. Phase 7's stage-1 detect-only observation is reproduced by patching the
LIVE Application down —
`kubectl -n argocd patch application demo-workloads --type=merge -p '{"spec":{"syncPolicy":{"automated":{"selfHeal":false}}}}'`
— and restored by patching back or re-applying the file; see
`runbooks/phase-7-argocd.md` sections 3 and 4. **The agreement is maintained by
hand, not by a controller**: nothing reconciles
`gitops/application-workloads.yaml` itself, because the Application is not
managed by itself. On 2026-08-07 the file still carried `selfHeal: false` and
step 7's patch is what raised the live object; the file was corrected
afterwards, which is why the transcript in `docs/evidence/phase-7-argocd/`
captures a `{"prune":false,"selfHeal":false}` starting state.

## Rollback

`kubectl -n argocd delete application demo-workloads` removes the GitOps
control without touching the 7 workloads, because of the omitted finalizer
above. Full removal is
`kubectl delete -n argocd -f <the same pinned URL>` followed by
`kubectl delete namespace argocd`; the three ClusterRoles and three
ClusterRoleBindings are cluster-scoped and are removed by the `delete -f`,
**not** by deleting the namespace, so
`kubectl get clusterrole,clusterrolebinding | grep -i argocd` should be
checked afterwards — a leftover cluster-admin binding pointing at a deleted
ServiceAccount is exactly the kind of residue this repo does not tolerate.

**None of the rollback commands were run.** The install succeeded first time
and the cluster is deliberately left with ArgoCD running and `selfHeal: true`
as the final posture, so the commands in this section are written from the
install's own shape and have not been executed against this cluster.
