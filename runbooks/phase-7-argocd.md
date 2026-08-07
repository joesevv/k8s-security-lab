# Runbook — Phase 7: GitOps drift control (ArgoCD detects, then reverts)

A replayable command log for the reconciliation layer: a version-pinned ArgoCD
v3.5.0 installed from an upstream manifest recorded by URL and sha256 rather
than vendored, a single `Application` scoped to the repo's `workloads/` path
and nothing else, and the same security regression run TWICE — once with
`selfHeal: false` to show the drift being NOTICED and left in place for ten
minutes, once with `selfHeal: true` to show it reverted in about a second. The
gap between those two runs is the deliverable. Commands are in execution
order; each has a one-line purpose and the observed output.

Host: Windows 11 + Docker Desktop (WSL2), kind cluster `seclab` (context
`kind-seclab`), Kubernetes v1.35.5, 3 nodes. Commands were run from Git Bash.
Any `kubectl exec` that passes an in-container path needs `MSYS_NO_PATHCONV=1`
in the environment: Git Bash rewrites `/var/cache/nginx/p7-probe` into a
Windows path and the resulting error looks like a missing file inside the
container. It is not.

**Six honesty caveats, up front — they are part of the deliverable, not
footnotes:**

1. **ArgoCD REVERTS. It does not PREVENT.** It is not an admission plugin and
   it is not in the request path. Every correction below happens AFTER the
   apiserver accepted the change and AFTER the kubelet started the resulting
   pod. Section 5c measures the consequence: even with `selfHeal: true`, the
   ReplicaSet controller created a weakened pod, the kubelet pulled its image,
   and the container **started and ran for roughly one second** with a
   writable root filesystem before ArgoCD's revert killed it. Self-healing
   shrank the exposure window from 608 seconds to about one. It did not close
   it. Only admission control can make that number zero, and — see caveat 2 —
   admission control does not look at this field.
2. **The drift chosen is one the admission layer PERMITS.** Removing
   `readOnlyRootFilesystem: true` is a real weakening, and PSA `restricted`
   does not require that field, nor does any of this repo's 5 Kyverno
   policies. Section 4b shows the weakened pod being ADMITTED with every event
   `Normal`. That is deliberate: a drift that Kyverno would have blocked would
   have proved nothing about GitOps.
3. **ArgoCD gave itself cluster-admin, and it lives outside every guardrail
   this lab has.** The `argocd-application-controller` ClusterRole's rules are
   **byte-identical** to the built-in `cluster-admin` (section 2c — diffed,
   not eyeballed), and `argocd-server` can `delete`, `get` and `patch` any
   resource of any kind cluster-wide. The `argocd` namespace carries no Pod
   Security labels at all, so it gets the built-in `privileged` default, and
   all 5 Kyverno policies select only `demo` and `demo-kyverno-only`. **Three
   unenforced namespaces now: `cis-benchmark`, `falco`, `argocd`.** Any
   pinning applied to ArgoCD here is SELF-IMPOSED and unenforced.
4. **Scope is a convention, not a capability.** The Application syncs
   `workloads/` — 7 objects. The `demo` namespace also holds the `developer`
   Role and RoleBinding, 4 NetworkPolicies and a SealedSecret, and **none of
   them get any GitOps protection**; section 6 drifts one and watches ArgoCD
   ignore it for 4 min 57 s while reporting `Synced`. The `default`
   AppProject, whose actual job is to constrain Applications, constrains
   nothing: `sourceRepos: ["*"]`, `destinations: [{namespace:"*",server:"*"}]`.
5. **Nothing here verifies the git content itself.** No commit signature
   verification is configured — no `signatureKeys` on the project, no keys in
   `argocd-gpg-keys-cm` (section 7d of the evidence). ArgoCD applies whatever
   is on `main`, faithfully. With `selfHeal: true` this is strictly worse than
   with it off: a malicious commit would be RE-APPLIED every time an operator
   removed it by hand.
6. **No credential was retrieved and the UI was never opened.** The install
   creates `argocd-initial-admin-secret`; it was never read, decoded or used,
   and the `argocd` CLI was never installed. Every observation in this phase
   comes from `kubectl` against the `Application` CR and the live objects.
   Section 7 gives the port-forward for a human who wants the UI and stops at
   the point where a password would be needed.

**A note on where the manifest lives.** `gitops/application-workloads.yaml` is
a new topic directory, parallel to `policies/`, `network/`, `rbac/` and
`workloads/`, because an ArgoCD `Application` is infrastructure that persists
in the cluster, not a probe — probes belong under `docs/evidence/`. It
deliberately does **not** live in `workloads/`: that is the path this
Application syncs, so an `Application` CR sitting there would make ArgoCD try
to apply its own definition into namespace `demo`, where the controller does
not read Application CRs. That is a self-reference bug, not a layout
preference.

**A note on the committed `selfHeal` value.** The committed manifest carries
`selfHeal: true` and the live Application reports
`{"prune":false,"selfHeal":true}` — **the file and the cluster agree.** That
is the only defensible arrangement in a GitOps phase: the file IS the
intended end state, so applying it lands the posture this phase leaves
behind rather than silently downgrading the cluster to detect-only. Stage 1
is consequently a TEMPORARY detour, not the shipped default: section 3a
patches the LIVE Application down to `selfHeal: false` to observe detection
without correction, and section 4a puts it back. The agreement itself is
maintained BY HAND — nothing reconciles `gitops/application-workloads.yaml`,
because the Application is not managed by itself.

Full transcript: [`docs/evidence/phase-7-argocd/attack-output.txt`](../docs/evidence/phase-7-argocd/attack-output.txt).
Install record: [`clusters/argocd-install.md`](../clusters/argocd-install.md).

## 0. Pre-state — what is true before anything is installed

There is no `argocd` namespace, the live workloads match git for both images,
and the field this phase will drift is set. The last point matters: if live
had already diverged from git, the first sync would have corrected something
and every later "ArgoCD restored it" claim would be muddied.

```bash
kubectl get ns
# NAME                 STATUS   AGE
# cis-benchmark        Active   8d
# default              Active   8d
# demo                 Active   8d
# demo-kyverno-only    Active   8d
# falco                Active   8d
# kube-node-lease      Active   8d
# kube-public          Active   8d
# kube-system          Active   8d
# kyverno              Active   8d
# local-path-storage   Active   8d
# => ten namespaces, none of them `argocd`.                            (exit 0)

kubectl -n demo get deploy nginx \
  -o jsonpath='{.spec.template.spec.containers[0].securityContext}'
# {"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnly
# RootFilesystem":true,"runAsNonRoot":true,"seccompProfile":{"type":"Runtime
# Default"}}                                          (wrapped for width; exit 0)
```

Live image digests compared against the committed manifests — identical for
both Deployments, so there is no pre-existing drift:

```bash
kubectl -n demo get deploy nginx \
  -o jsonpath='{.spec.template.spec.containers[0].image}'
# nginxinc/nginx-unprivileged:1.29.8-alpine@sha256:0c79d56aee561a1d81c63f00e
# ee5fb5fe29279560cdc55e91425133104c7fbe6              (wrapped for width; exit 0)
grep -o 'image: .*' workloads/nginx/deployment.yaml
# image: nginxinc/nginx-unprivileged:1.29.8-alpine@sha256:0c79d56aee561a1d81
# c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6       (wrapped for width; exit 0)
# => same digest; same for signed-app on sha256:7fd13d22d934f4202edc16...
```

**0a. Calibrating the write probe — do NOT aim it at `/tmp`.** The nginx pod
mounts an emptyDir at `/tmp`, and an emptyDir is writable no matter what
`readOnlyRootFilesystem` says. A probe there would pass in both stages and
prove nothing. Read the mount table first and pick a path genuinely on the
root overlay that the container's own uid can write:

```bash
POD=$(kubectl -n demo get pods -l app=nginx -o jsonpath='{.items[0].metadata.name}')
kubectl -n demo exec "$POD" -- id
# uid=101(nginx) gid=101(nginx) groups=101(nginx)                      (exit 0)

kubectl -n demo exec "$POD" -- sh -c 'cat /proc/mounts | grep -E " / | /tmp "'
# overlay / overlay ro,relatime,lowerdir=...                           (exit 0)
# /dev/sdd /tmp ext4 rw,relatime 0 0
# => "/" is a READ-ONLY overlay; "/tmp" is a SEPARATE read-write device.

kubectl -n demo exec "$POD" -- sh -c 'ls -ld / /var/cache/nginx'
# drwxr-xr-x    1 root     root          4096 Aug  7 18:16 /
# drwxrwxr-x    1 nginx    root          4096 May 11 00:52 /var/cache/nginx
# => /var/cache/nginx is on the root overlay AND owned by uid 101.     (exit 0)
```

The probe, run against the pre-state pod. It discriminates — same command,
same pod, same instant, opposite results:

```bash
kubectl -n demo exec "$POD" -- touch /var/cache/nginx/p7-probe
# touch: /var/cache/nginx/p7-probe: Read-only file system
# command terminated with exit code 1                                  (exit 1)

kubectl -n demo exec "$POD" -- touch /tmp/p7-probe
# => the emptyDir accepts the write. This is why /tmp is NOT the probe.(exit 0)
kubectl -n demo exec "$POD" -- rm -f /tmp/p7-probe
```

## 1. Install ArgoCD, pinned to a version rather than to `stable`

**1a. Resolve what to pin.** The documented upstream URL uses the moving
`stable` ref. Pin the tag instead — but check what `stable` actually IS today,
so the pin is a decision rather than a guess. Note that `git ls-remote`
returns the ANNOTATED TAG OBJECT; `^{}` peels it to the commit:

```bash
git ls-remote https://github.com/argoproj/argo-cd.git \
  'refs/tags/stable*' 'refs/tags/v3.5.0*'
# f8a2c4798f39c36175580f97266ad7ec64d48344	refs/tags/stable
# e95e1be88a2da6c06bff5c2fe1791e4d233ed810	refs/tags/stable^{}
# f8a2c4798f39c36175580f97266ad7ec64d48344	refs/tags/v3.5.0
# e95e1be88a2da6c06bff5c2fe1791e4d233ed810	refs/tags/v3.5.0^{}
# => stable and v3.5.0 are the SAME tag object, peeling to the SAME
#    commit. Pinning v3.5.0 installs what stable would install today,
#    and unlike stable it still will next month.                       (exit 0)
```

There is **no** `install.yaml` asset on the GitHub release — only
`cli_checksums.txt` and `sbom.tar.gz` — so the manifest comes from the
`manifests/` path at the pinned tag, and the bytes are hashed:

```bash
curl -sSL https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.0/manifests/install.yaml \
  > install.yaml
sha256sum install.yaml
# a32bf36a437071a1f563ebf9e81c8a39fba9057c17db7d5d041afb7b6e3f4afe *install.yaml
# => 1917766 bytes, 34050 lines. Fetching the same path by the PEELED
#    COMMIT gives a byte-identical file (cmp exit 0), which proves the
#    tag had not moved between the two reads.                          (exit 0)
```

**The manifest is deliberately NOT committed to this repo.** 34050 lines of
vendored upstream YAML would be unreviewable and would rot. URL + sha256 +
the resolved digests in section 1c are the reproducibility record.

**1b. Install.** `--server-side` is required, not stylistic: a client-side
apply stores the whole 1.9 MB manifest in a `last-applied-configuration`
annotation and blows the 262144-byte annotation limit on the CRDs.

```bash
kubectl create namespace argocd
# namespace/argocd created                                             (exit 0)

kubectl apply -n argocd --server-side \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.0/manifests/install.yaml
# customresourcedefinition.apiextensions.k8s.io/applications.argoproj.io serverside-applied
# [... 57 further objects ...]
# networkpolicy.networking.k8s.io/argocd-server-network-policy serverside-applied
# => 59 objects: 3 CRDs, 7 SAs, 6 Roles, 3 ClusterRoles, 6 RoleBindings,
#    3 ClusterRoleBindings, 7 ConfigMaps, 2 Secrets, 8 Services,
#    6 Deployments, 1 StatefulSet, 7 NetworkPolicies.                  (exit 0)

for d in argocd-applicationset-controller argocd-dex-server \
         argocd-notifications-controller argocd-redis \
         argocd-repo-server argocd-server; do
  kubectl -n argocd rollout status deploy/$d --timeout=300s
done
kubectl -n argocd rollout status statefulset/argocd-application-controller --timeout=300s
# deployment "argocd-server" successfully rolled out
# partitioned roll out complete: 1 new pods have been updated...       (exit 0)
# => all 7 workloads up on the first attempt, 17:59:33Z -> 18:00:06Z = 33 s.
```

**1c. Record what the tags actually resolved to.** The apiserver runs
`--enable-admission-plugins=NodeRestriction,AlwaysPullImages`, so every one of
these pods really pulled:

```bash
kubectl -n argocd get pods -o jsonpath='{range .items[*]}{.metadata.name}{"\n"}{range .status.containerStatuses[*]}  image:   {.image}{"\n"}  imageID: {.imageID}{"\n"}{end}{end}'
#   image:   quay.io/argoproj/argocd:v3.5.0
#   imageID: quay.io/argoproj/argocd@sha256:c298cedbaeb31532ba8d4e9904e...
#   image:   ghcr.io/dexidp/dex:v2.45.0
#   imageID: ghcr.io/dexidp/dex@sha256:b8469881d3cb3a73001506f0d3aaefec...
#   image:   public.ecr.aws/docker/library/redis:8.2.3-alpine
#   imageID: public.ecr.aws/docker/library/redis@sha256:08ad0b1d2808501...
# => READ THE `image:` LINES. Upstream pins by TAG. Those digests are a
#    RECORD of what the tags meant on 2026-08-07, NOT a control this
#    repo enforces. Contrast phase 4, where the repo's own workloads
#    are digest-pinned in git AND gated by Kyverno.                    (exit 0)
```

**1d. What the install granted itself — run this before trusting it.**

```bash
kubectl get clusterrole argocd-application-controller -o jsonpath='{.rules}'
# [{"apiGroups":["*"],"resources":["*"],"verbs":["*"]},
#  {"nonResourceURLs":["*"],"verbs":["*"]}]                            (exit 0)
kubectl get clusterrole cluster-admin -o jsonpath='{.rules}'
# [{"apiGroups":["*"],"resources":["*"],"verbs":["*"]},
#  {"nonResourceURLs":["*"],"verbs":["*"]}]                            (exit 0)
# => diffed, not eyeballed: RULES ARE BYTE-IDENTICAL. The ServiceAccount
#    argocd-application-controller in namespace argocd IS cluster-admin.
#    It can read every Secret in every namespace, including the
#    sealed-secrets private key and every ServiceAccount token.
```

And the namespace it lives in is gated by nothing:

```bash
kubectl get ns argocd -o jsonpath='{.metadata.labels}'
# {"kubernetes.io/metadata.name":"argocd"}                             (exit 0)
# => no pod-security labels at all -> built-in `privileged` default,
#    and the apiserver has no --admission-control-config-file to change
#    that. All 5 Kyverno policies select only demo/demo-kyverno-only.
```

## 2. The Application — scoped, and a green status that meant nothing

**2a. The trap. `Synced / Healthy` while managing ZERO resources.** The
Application was first created without `directory.recurse`. It reported both
green within six seconds — and was watching nothing at all:

```bash
kubectl -n argocd get application
# NAME             SYNC STATUS   HEALTH STATUS
# demo-workloads   Synced        Healthy                               (exit 0)

kubectl -n argocd get application demo-workloads -o jsonpath='{.status.resources}'
# => PRINTED NOTHING. Zero managed resources.                          (exit 0)

find workloads -maxdepth 1 -type f
# => no output: workloads/ has NO files at its top level; all 7
#    manifests live in workloads/nginx/ and workloads/signed-app/.     (exit 0)
```

**A `Directory` source does not recurse by default.** ArgoCD found zero
manifests, had zero desired state, compared it against zero tracked resources
and correctly concluded there was no difference. **A green Application that is
protecting nothing looks exactly like a green Application that is protecting
everything.** `.status.resources` is the field that tells them apart. Count it
— never eyeball the colour.

**2b. The fix, and what scoped control actually looks like.**

```bash
kubectl apply -f gitops/application-workloads.yaml
# application.argoproj.io/demo-workloads configured                    (exit 0)

kubectl -n argocd get application demo-workloads \
  -o jsonpath='{range .status.resources[*]}{.kind}{"/"}{.name}{" -> "}{.status}{"\n"}{end}'
# Namespace/demo -> Synced
# Service/nginx -> Synced
# Service/signed-app -> Synced
# ServiceAccount/nginx-sa -> Synced
# ServiceAccount/signed-app-sa -> Synced
# Deployment/nginx -> Synced
# Deployment/signed-app -> Synced                                      (exit 0)
# => SEVEN. Exactly the objects in workloads/. NOT developer-sa, NOT the
#    developer Role, NOT the 4 NetworkPolicies, NOT the SealedSecret —
#    all of which are in the SAME namespace.
```

The sync adopted the 7 pre-existing objects without touching the workload: the
securityContext is unchanged and the pods were not restarted (same names,
still 8 days old). The only live-vs-git difference is the tracking annotation
ArgoCD adds to mark ownership.

## 3. STAGE 1 — detection only (`selfHeal: false`, temporary)

**3a. Patch the LIVE Application down to detect-only, then confirm it.**
Section 2b applied `gitops/application-workloads.yaml`, and that file ships
the final posture, `selfHeal: true`. Stage 1 is the weaker posture on
purpose, so it is produced on the live object and never by editing the file —
committing detect-only would make the repo describe something worse than what
runs:

```bash
kubectl -n argocd patch application demo-workloads --type=merge \
  -p '{"spec":{"syncPolicy":{"automated":{"selfHeal":false}}}}'
```

**That patch is written for a replayer and was NOT run in this form on
2026-08-07.** On the day, the committed file still carried `selfHeal: false`,
so the apply in 2b was itself what produced the stage-1 posture; the file now
ships `true`, corrected after the run so that git describes the end state
instead of an intermediate step. The resulting posture is the same either
way — and it is the verification below, not the route taken to it, that the
rest of this section rests on. The JSON-Patch index for the drift is checked
here too, rather than assumed:

```bash
kubectl -n argocd get application demo-workloads \
  -o jsonpath='{.spec.syncPolicy.automated}'
# {"prune":false,"selfHeal":false}                                     (exit 0)

kubectl -n demo get deploy nginx -o jsonpath='{.spec.template.spec.containers[*].name}'
# nginx
# => ONE container, so containers/0 is the right index.                (exit 0)
```

**3b. The drift — applied to the LIVE object only.**
`workloads/nginx/deployment.yaml` is NEVER edited in this phase; section 6
proves it is untouched in git. This is what "just fixing it in prod" looks
like:

```bash
# DRIFT APPLIED AT 2026-08-07T18:05:59Z
kubectl -n demo patch deploy nginx --type=json \
  -p '[{"op":"remove","path":"/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem"}]'
# deployment.apps/nginx patched                                        (exit 0)

kubectl -n demo get deploy nginx \
  -o jsonpath='{.spec.template.spec.containers[0].securityContext}'
# {"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},
#  "runAsNonRoot":true,"seccompProfile":{"type":"RuntimeDefault"}}     (exit 0)
# => readOnlyRootFilesystem is GONE. Everything else survives, which is
#    what makes this a realistic regression rather than a demolition.
```

**3c. The weakened pod is ADMITTED — this is why the field was chosen.**

```bash
kubectl -n demo rollout status deploy/nginx --timeout=120s
# deployment "nginx" successfully rolled out                           (exit 0)

kubectl -n demo get events --sort-by=.lastTimestamp | tail -15
# => EVERY EVENT IS `Normal`. No Warning, no FailedCreate, no PSA
#    denial, no Kyverno block. `demo` enforces PSA restricted and 5
#    Kyverno policies and the weakened pod sailed through all of them,
#    because `restricted` does not require readOnlyRootFilesystem and
#    no policy in this repo checks it. THE ADMISSION LAYER IS NOT THE
#    CONTROL THAT CATCHES THIS.                                        (exit 0)
```

Proven from the running container, not the spec — the same probe as 0a, now
succeeding:

```bash
POD=$(kubectl -n demo get pods -l app=nginx -o jsonpath='{.items[0].metadata.name}')
kubectl -n demo exec "$POD" -- sh -c 'grep " / " /proc/mounts' | cut -c1-40
# overlay / overlay rw,relatime,lowerdir=/                             (exit 0)
kubectl -n demo exec "$POD" -- touch /var/cache/nginx/p7-probe
kubectl -n demo exec "$POD" -- ls -l /var/cache/nginx/p7-probe
# -rw-r--r--    1 nginx    nginx            0 Aug  7 18:06 /var/cache/nginx/p7-probe
# => the kernel mount flag flipped ro -> rw and a file is on disk.     (exit 0)
```

**3d. ArgoCD notices, and names the resource.**

```bash
kubectl -n argocd get application
# NAME             SYNC STATUS   HEALTH STATUS
# demo-workloads   OutOfSync     Healthy                               (exit 0)

kubectl -n argocd get application demo-workloads \
  -o jsonpath='{range .status.resources[*]}{.kind}{"/"}{.name}{" -> "}{.status}{"\n"}{end}'
# Deployment/nginx -> OutOfSync
# => one of seven, correctly identified. Detection took AT MOST 43 s
#    (drift 18:05:59Z, first observed OutOfSync 18:06:42Z) — an upper
#    bound from a polling loop, not an instrumented latency.           (exit 0)
```

**Read the second column: `Healthy`.** Health and Sync are different
questions. The Deployment is perfectly healthy — 2/2 replicas serving traffic.
It is just not what git says. A dashboard filtered on health alone shows this
cluster as fine.

**3e. THE LOAD-BEARING STEP: wait, and show the drift PERSISTS.** ArgoCD's
default reconcile interval is 180 s, so this watch spans more than three of
them. Poll the LIVE object, not the Application's opinion of it:

```bash
for i in $(seq 1 17); do
  printf '%s  sync=%s  rorfs=%s\n' "$(date -u '+%H:%M:%SZ')" \
    "$(kubectl -n argocd get application demo-workloads -o jsonpath='{.status.sync.status}')" \
    "$(kubectl -n demo get deploy nginx -o jsonpath='{.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}')"
  sleep 30
done
# 18:07:15Z  sync=OutOfSync  rorfs=ABSENT
# [... 15 further samples, all identical ...]
# 18:15:19Z  sync=OutOfSync  rorfs=ABSENT                              (exit 0)
```

And the pod is still writable at the end of it — two probe files, ten minutes
apart, in a root filesystem git says must be read-only:

```bash
kubectl -n demo exec "$POD" -- touch /var/cache/nginx/p7-still-writable
kubectl -n demo exec "$POD" -- ls -l /var/cache/nginx/
# -rw-r--r--    1 nginx    nginx            0 Aug  7 18:06 p7-probe
# -rw-r--r--    1 nginx    nginx            0 Aug  7 18:16 p7-still-writable
# => TOTAL TIME DRIFTED AND UNCORRECTED: 18:05:59Z -> 18:16:07Z
#    = 10 min 8 s, ended by an operator flipping a flag, not by
#    ArgoCD. THIS IS WHAT "DETECTION IS NOT PREVENTION" MEANS.         (exit 0)
```

ArgoCD knew. It knew within 43 seconds. It named the exact resource and wrote
the finding into its own status where any dashboard could read it. And the
weakened container served traffic for ten minutes anyway, because nothing was
configured to act on what it knew. Falco (phase 6) has the same shape: a
correct alert and no hand on the lever.

## 4. STAGE 2 — restore the shipped posture (`selfHeal: true`)

**4a. One boolean, back to what the file already says. The existing drift
disappears on its own.** This step undoes 3a's temporary patch and returns
the Application to the committed posture; `kubectl apply -f
gitops/application-workloads.yaml` reaches the same place, since the file
carries `selfHeal: true`. The patch is what was run, and its timestamp is why
it is the version quoted here. Nothing about the Deployment is touched —
only the Application:

```bash
# SELFHEAL ENABLED AT 2026-08-07T18:16:44Z
kubectl -n argocd patch application demo-workloads --type=merge \
  -p '{"spec":{"syncPolicy":{"automated":{"selfHeal":true}}}}'
# application.argoproj.io/demo-workloads patched                       (exit 0)

# poll loop, 2 s interval, started immediately after the patch:
# 18:16:44.765  sync=Synced  rorfs=true
# => THE VERY FIRST SAMPLE, in the SAME WALL-CLOCK SECOND as the patch,
#    already showed the 10-minute-old drift corrected. The exact
#    latency is BELOW the sampling resolution and is not claimed.      (exit 0)
```

ArgoCD says it did this itself — not an operator, not the CLI, not the UI:

```bash
kubectl -n argocd get application demo-workloads \
  -o jsonpath='{.status.operationState.operation.initiatedBy}{" "}{.status.operationState.startedAt}{" "}{.status.operationState.finishedAt}'
# {"automated":true} 2026-08-07T18:16:44Z 2026-08-07T18:16:44Z         (exit 0)
# => started and finished inside one second.
```

The same probe as 3c, now failing again:

```bash
POD=$(kubectl -n demo get pods -l app=nginx -o jsonpath='{.items[0].metadata.name}')
kubectl -n demo exec "$POD" -- sh -c 'grep " / " /proc/mounts' | cut -c1-40
# overlay / overlay ro,relatime,lowerdir=/                             (exit 0)
kubectl -n demo exec "$POD" -- touch /var/cache/nginx/p7-probe
# touch: /var/cache/nginx/p7-probe: Read-only file system
# command terminated with exit code 1                                  (exit 1)
```

**4b. Re-run the SAME drift — it snaps back.**

```bash
# DRIFT #2 ISSUED 18:17:40.2784Z, patch returned 18:17:40.4242Z
kubectl -n demo patch deploy nginx --type=json \
  -p '[{"op":"remove","path":"/spec/template/spec/containers/0/securityContext/readOnlyRootFilesystem"}]'
# deployment.apps/nginx patched                                        (exit 0)
# poll loop, 1 s interval:
# 18:17:40.502  rorfs=ABSENT     <- the drift really landed
# 18:17:41.710  rorfs=true       <- back on its own
# => REVERT LATENCY 1.29 s (upper bound; 1 s poll resolution).
#    Stage 1: 10 min 8 s. Stage 2: 1.29 s. Same drift, one boolean.
```

**4c. AND YET A WEAKENED CONTAINER STILL RAN.** The ReplicaSet controller does
not wait for ArgoCD. This is the honest limit of stage 2:

```bash
kubectl -n demo get events \
  -o custom-columns='FIRST:.firstTimestamp,OBJ:.involvedObject.name,REASON:.reason' \
  --sort-by=.firstTimestamp | grep t6v8w
# 2026-08-07T18:17:40Z   nginx-6758c84c75-t6v8w   Pulling
# 2026-08-07T18:17:41Z   nginx-6758c84c75-t6v8w   Started
# 2026-08-07T18:17:42Z   nginx-6758c84c75-t6v8w   Killing              (exit 0)
# => a pod from the DRIFTED ReplicaSet was created, pulled its image,
#    and its container STARTED at 18:17:41Z with a writable root
#    filesystem, then was killed at 18:17:42Z. It RAN for ~1 second.
#    (Event stamps are 1-second resolution, so the bound is ~0-2 s.)
#    SELFHEAL SHRANK THE WINDOW FROM 608 s TO ABOUT ONE. IT DID NOT
#    CLOSE IT.
```

## 5. The scope boundary, made concrete

ArgoCD only sees `workloads/`. Drift something in the SAME namespace that is
outside that path and watch it be ignored — with `selfHeal: true` on, the same
setting that reverted the nginx drift in 1.29 s:

```bash
kubectl -n demo get role developer -o jsonpath='{.metadata.labels}'
# {"app.kubernetes.io/part-of":"k8s-security-lab"}                     (exit 0)

# OUT-OF-SCOPE DRIFT APPLIED AT 2026-08-07T18:19:13Z
kubectl -n demo label role developer p7-scope-probe=applied
# role.rbac.authorization.k8s.io/developer labeled                     (exit 0)

for i in $(seq 1 15); do
  printf '%s  app-sync=%s  role-label=%s  nginx-rorfs=%s\n' "$(date -u '+%H:%M:%SZ')" \
    "$(kubectl -n argocd get application demo-workloads -o jsonpath='{.status.sync.status}')" \
    "$(kubectl -n demo get role developer -o jsonpath='{.metadata.labels.p7-scope-probe}')" \
    "$(kubectl -n demo get deploy nginx -o jsonpath='{.spec.template.spec.containers[0].securityContext.readOnlyRootFilesystem}')"
  sleep 20
done
# 18:19:24Z  app-sync=Synced  role-label=applied  nginx-rorfs=true
# [... 13 further samples, all identical ...]
# 18:24:10Z  app-sync=Synced  role-label=applied  nginx-rorfs=true     (exit 0)
```

**For 4 min 57 s, spanning more than one reconcile cycle:** the Application
never left `Synced` — it does not report the drift as a problem because the
drift is not in its world at all; the injected label was never removed; and
the in-scope field stayed correct throughout, proving the controller was alive
the whole time. **An object outside `source.path` has NO GitOps protection,
and a green Application says nothing about it.** Revert it yourself, because
nothing else will:

```bash
kubectl -n demo label role developer p7-scope-probe-
# role.rbac.authorization.k8s.io/developer unlabeled                   (exit 0)
```

## 6. Verifying `workloads/` was never edited

Every drift above was applied to LIVE objects with `kubectl patch`. The files
were not touched — which is what makes "ArgoCD restored it" meaningful, since
the desired state it restored to was never quietly edited to match:

```bash
git diff --stat HEAD -- workloads/
# => no output: zero changes to workloads/                             (exit 0)
git status --short -- workloads/
# => no output: clean, not even untracked files                        (exit 0)
```

## 7. Reaching the UI — and where this runbook stops

Nothing in phase 7 needs the UI; every observation above came from `kubectl`.
For a human who wants it, `argocd-server` is a ClusterIP with no Ingress and
no LoadBalancer — deliberately, since exposing a cluster-admin-backed control
plane on a lab host is not a default worth having. Port-forward is the whole
access story:

```bash
kubectl -n argocd port-forward svc/argocd-server 8080:443
# then browse https://127.0.0.1:8080 (self-signed cert; expect a warning)
```

**The credential is a human step that was NOT taken in this phase.** The
initial admin password lives in `argocd-initial-admin-secret`, it was never
read, decoded or used, and the `argocd` CLI was never installed. A human who
chooses to retrieve it should also read section 1d first: the account behind
that password is backed by components that can `delete`, `get` and `patch` any
resource in the cluster. Rotating it and deleting the initial secret is the
normal next step and is **not** done here.

```bash
kubectl -n argocd get secret --no-headers \
  -o custom-columns='NAME:.metadata.name,TYPE:.type'
# argocd-initial-admin-secret   Opaque
# argocd-notifications-secret   Opaque
# argocd-redis                  Opaque
# argocd-secret                 Opaque                                 (exit 0)
# => names and types only. No value was read.
```

## 8. Teardown

Remove the Application first, then ArgoCD. **The Application carries no
`resources-finalizer.argocd.argoproj.io` finalizer, deliberately**, so
deleting it does NOT cascade a delete to the 7 managed objects — the demo
workloads survive. That is the intended behaviour: teardown should remove the
GitOps controller, not the workloads it happened to be watching.

```bash
kubectl -n argocd delete application demo-workloads
kubectl -n demo get deploy,svc,sa
# => the 7 workloads are still there, now unmanaged.

kubectl delete -n argocd \
  -f https://raw.githubusercontent.com/argoproj/argo-cd/v3.5.0/manifests/install.yaml
kubectl delete namespace argocd
```

The three ClusterRoles and three ClusterRoleBindings are cluster-scoped and
are removed by the `delete -f` above, not by deleting the namespace. Confirm
the cluster-admin grant is actually gone rather than assuming it:

```bash
kubectl get clusterrole,clusterrolebinding | grep -c -i argocd
# => expect 0. If this is non-zero, a cluster-admin binding is still
#    live and pointing at a ServiceAccount that no longer exists.
```

**This teardown was NOT executed.** The cluster is deliberately left with
ArgoCD installed and `selfHeal: true` as the final posture — the commands
above are written from the install record and have not been run, so treat the
expected outputs as expectations rather than observations.

**The file and the cluster now agree** — `gitops/application-workloads.yaml`
and the live Application both carry `{"prune":false,"selfHeal":true}` — so
re-applying the manifest is safe and idempotent rather than a silent
downgrade to detect-only.
