# Runbook — Phase 2b: Admission control (Kyverno CEL ValidatingPolicies)

A replayable command log for the admission layer: installing Kyverno 1.18 via
a version-pinned Helm chart, deploying four CEL `ValidatingPolicy` resources
scoped to the `demo` and `demo-kyverno-only` namespaces, proving them safe in
**Audit** mode before flipping to **Deny**, and proving with nine live attacks
that non-compliant workloads are blocked at admission while the compliant
nginx and signed-app still admit. Commands are listed in execution order; each
has a one-line purpose and the observed output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash
unless noted. Kubernetes node image v1.35.5, Kyverno chart 3.8.2 / app v1.18.2.

---

## 0. The controls

Four `ValidatingPolicy` resources in `policies/`, all
`apiVersion: policies.kyverno.io/v1` (resolved on-cluster — see
`clusters/kyverno-install.md`; the policy-library examples show `v1alpha1`,
but this cluster serves `v1`). Enforcement is `spec.validationActions: [Deny]`
(there is no `validationFailureAction` field on this kind):

- **disallow-privileged-containers** — no container may set
  `securityContext.privileged: true`.
- **disallow-latest-and-bare-tag** — no `:latest` or untagged images. Uses the
  CEL `image()` library; verified on-cluster that it normalizes a bare image
  (no tag) to `tag() == 'latest'`, so one check catches both cases.
- **require-drop-all-capabilities** — every container must set
  `securityContext.capabilities.drop` to include `ALL` **and** must not add
  any capability back via `securityContext.capabilities.add`. Dropping `ALL`
  alone is not sufficient: the kernel applies `drop` before `add`, so
  `drop: [ALL]` together with `add: [SYS_ADMIN]` satisfies a drop-only check
  while still running with a container-escape capability. ATTACK E is that
  case, and it was ADMITTED before this clause existed.
- **restrict-registries** — images only from Docker Hub `nginxinc/*` (the lab
  nginx), `curlimages/*` (the lab curl client), or
  `ghcr.io/joesevv/k8s-security-lab/*` (this lab's own phase-4 signed image).
  Uses `image(c.image).registry()` / `.repository()`; verified on-cluster that
  the literal manifest string `nginxinc/nginx-unprivileged:1.29.8-alpine` (no
  `docker.io/` prefix) normalizes to registry **`index.docker.io`** — not
  `docker.io` — so the policy compares against `index.docker.io`.

### Match scope — what these four policies actually see

Each policy declares explicit `matchConstraints.resourceRules`:

- core `v1`: `pods` **and the `pods/ephemeralcontainers` subresource**
- `apps/v1`: `deployments`, `statefulsets`, `daemonsets`, `replicasets`
- `batch/v1`: `jobs`, `cronjobs`

A `podSpec` CEL variable resolves the three pod-spec shapes those produce
(`spec.jobTemplate.spec.template.spec` for CronJob, `spec.template.spec` for
the other controllers, bare `spec` for a Pod), and an `allContainers` variable
then folds `containers` + `initContainers` + `ephemeralContainers` together so
one expression covers every container in the workload.

That controller coverage is **not** Kyverno autogen.
`spec.autogen.podControllers` is a NO-OP on Kyverno 1.18.2 —
`status.autogen` stays empty and the generated policy still matched `pods`
only, so a privileged **Deployment** was admitted at exit 0 with the denial
surfacing later as a ReplicaSet `FailedCreate` event (both results recorded
in commit `d9d04d0`).
The autogen block was removed rather than left in place implying coverage it did
not provide. The explicit rules are what work; ATTACK F (Deployment) and
ATTACK G (CronJob) are the tests that prove it.

The `pods/ephemeralcontainers` entry matters on its own. `kubectl debug`
attaches a container to an already-running pod through that subresource, not
through `pods`. Until it was listed, an attacker with debug rights could
attach a privileged sidecar to a compliant running pod and **no policy saw
the request at all** — folding `ephemeralContainers` into `allContainers`
did nothing, because the policy was never invoked. ATTACK H demonstrates the
subresource is now in scope: the injection is denied by two policies at exit
1. Adding the subresource also required
`rbac/kyverno-reports-ephemeralcontainers.yaml` — without `get/list/watch` on
it the reports controller left all five policies at `READY=false`
(enforcement worked, reporting did not).

### Two namespaces, and why

- **`demo`** — the workload namespace. Runs nginx and signed-app, and carries
  `pod-security.kubernetes.io/enforce: restricted` +
  `enforce-version: v1.35` + `warn: restricted`.
- **`demo-kyverno-only`** — a demo-only namespace with
  `pod-security.kubernetes.io/warn: restricted` and **no enforce**. It never
  carries real workloads.

Pod Security Admission is an in-process API-server plugin and runs **before**
admission webhooks; when PSA enforce rejects a pod it short-circuits and the
webhook is never called. In `demo`, most of the attack pods below would be
stopped by PSA and the Kyverno denial would never be observable. So the Kyverno
denials are demonstrated in `demo-kyverno-only`, where PSA only warns, and the
PSA layer is demonstrated in `demo`. All four policies (and the phase-4
ImageValidatingPolicy) select both namespaces.

### PSA is a separate, complementary control — not a restatement of Kyverno

**No `ValidatingPolicy` in `policies/` covers `hostPath`, `hostPID`,
`hostNetwork`, `hostIPC` or `runAsUser`.** That gap is real. PSA
`enforce: restricted` on `demo` is the control that closes it. ATTACK I shows
both halves honestly: the node-root `hostPath` pod is `Forbidden` by
PodSecurity in `demo`, and the *same* pod is **admitted** in
`demo-kyverno-only`, where Kyverno inspects it and has nothing to say. Neither
layer is sufficient alone; only `demo` runs both.

**Scoping choice:** all four policies match only `demo` and `demo-kyverno-only`
(`matchConstraints.namespaceSelector` on `kubernetes.io/metadata.name In
[demo, demo-kyverno-only]`), so **nothing outside those two namespaces is
enforced by this layer.** Kyverno's webhook is fail-closed
(`failurePolicy: Fail` by default), so a cluster-wide policy that also matched
`kube-system` or `kyverno` itself could wedge the cluster if the webhook ever
misbehaved. In production you would widen the scope and instead carve out
explicit exclusions (`excludeResourceRules` / namespace exclusions) for system
namespaces — that tradeoff is deliberate here and kept narrow for the lab.

---

## 1. Install Kyverno 1.18 (pinned chart)

```bash
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm search repo kyverno -l | grep -E "1\.18"
# -> kyverno/kyverno 3.8.2  v1.18.2   (chart 3.8.x => app 1.18.x, i.e. app minor = chart minor + 10)
helm install kyverno kyverno/kyverno --namespace kyverno --create-namespace --version 3.8.2
for d in $(kubectl -n kyverno get deploy -o name); do kubectl -n kyverno rollout status "$d" --timeout=180s; done
```
Purpose: install Kyverno pinned by exact chart version and wait for all four
controllers (admission, background, cleanup, reports) to be Ready.

```bash
kubectl get pods -n kyverno
# NAME                                             READY   STATUS    RESTARTS   AGE
# kyverno-admission-controller-7cdf5b9c-8jfcc      1/1     Running   0          62s
# kyverno-background-controller-7b54965bf9-fmt4c   1/1     Running   0          62s
# kyverno-cleanup-controller-59c8fdfb66-ltkqk      1/1     Running   0          62s
# kyverno-reports-controller-5c96886c9-7kfjj       1/1     Running   0          62s

kubectl api-resources | grep -i validatingpolic
# -> validatingpolicies  vpol  policies.kyverno.io/v1  false  ValidatingPolicy
```
Purpose: confirm the served apiVersion before writing any policy. Full install
record: `clusters/kyverno-install.md`.

---

## 2. Safety sequence — Audit first, then Deny

Kyverno's webhook is fail-closed; a wrong policy flipped straight to Deny
could block legitimate workloads (or, if scoped wider, system pods). So the
policies are proven in non-blocking Audit mode first.

**2a. Apply in Audit** (same manifests with `validationActions: [Audit]`).
The policies select `demo-kyverno-only`, so that namespace has to exist first:

```bash
kubectl apply -f policies/00-namespace-kyverno-only.yaml
# The reports controller needs read on pods/ephemeralcontainers, or every
# policy that matches that subresource stays READY=false.
kubectl apply -f rbac/kyverno-reports-ephemeralcontainers.yaml

# Select by kind, NOT by glob. policies/ also holds a Namespace manifest, and a
# bare policies/*.yaml loop would pipe that Namespace through sed and apply it
# as if it were a policy.
for f in $(grep -l '^kind: ValidatingPolicy' policies/*.yaml); do
  sed 's/validationActions: \[Deny\]/validationActions: [Audit]/' "$f" | kubectl apply -f -
done
# -> the four files in policies/: disallow-latest-and-bare-tag,
#    disallow-privileged-containers, require-drop-all-capabilities,
#    restrict-registries. The phase-4 ImageValidatingPolicy lives in
#    policies/supply-chain/ and the shallow glob does not reach it — that is
#    phase 4's runbook, not this one.

kubectl get validatingpolicy
# all four READY=true
```

**2b. Prove the compliant workload passes all four rules under Audit:**

```bash
kubectl rollout restart deploy/nginx -n demo && kubectl rollout status deploy/nginx -n demo
# -> deployment "nginx" successfully rolled out

kubectl get policyreport -n demo
# NAME   KIND  NAME                     PASS  FAIL  WARN  ERROR  SKIP
# ...    Pod   nginx-6d69669665-wr5l6   4     0     0     0      0
# ...    Pod   nginx-6d69669665-nkxfs   4     0     0     0      0
```
Purpose: the rollout proves admission is not disturbed; the PolicyReports
(pass=4 fail=0 error=0 per pod) prove nginx actually satisfies every rule —
especially the registry allow-list against the literal image string. Only
proceed to Deny when both are clean. If nginx failed here, fix the policies —
do not flip to Deny.

**2c. Flip to Deny and re-verify the positive control:**

```bash
kubectl apply -f policies/
kubectl get validatingpolicy -o custom-columns='NAME:.metadata.name,ACTIONS:.spec.validationActions,READY:.status.conditionStatus.ready'
# all four ACTIONS=[Deny] READY=true
kubectl rollout restart deploy/nginx -n demo && kubectl rollout status deploy/nginx -n demo
# -> deployment "nginx" successfully rolled out
```
Purpose: a compliant workload admitting under Enforce proves the control is
precise, not a blanket block.

---

## 3. Attack demo — nine attacks, every one blocked at admission

Each manifest in `docs/evidence/phase-2b-admission/` violates exactly one
control and complies with the rest, so each denial cleanly cites its target.
ATTACKS A–H are run in `demo-kyverno-only` so the Kyverno denial is what
actually fails the request; ATTACK I is run in `demo` because PSA is the
control under test there.

**3a. The four original attacks (A–D).** These manifests pin
`namespace: demo`, so `-n demo-kyverno-only` conflicts with the manifest and
kubectl refuses. Copy them out of tree with only that line changed, and prove
with `diff` that nothing else was touched — modified manifests are never
applied silently in this lab:

```bash
REPO=$(pwd)          # run this block from the repo root
SCRATCH=$(mktemp -d)
cd docs/evidence/phase-2b-admission
for f in attack-privileged.yaml attack-latest-tag.yaml \
         attack-no-drop-caps.yaml attack-bad-registry.yaml; do
  sed 's/^  namespace: demo$/  namespace: demo-kyverno-only/' "$f" > "$SCRATCH/$f"
  diff "$f" "$SCRATCH/$f"
done
# -> each diff is a single line:
#      <   namespace: demo
#      >   namespace: demo-kyverno-only

cd "$SCRATCH"
kubectl apply -f attack-privileged.yaml    # privileged: true
kubectl apply -f attack-latest-tag.yaml    # nginxinc/nginx-unprivileged:latest
kubectl apply -f attack-no-drop-caps.yaml  # capabilities.drop: []
kubectl apply -f attack-bad-registry.yaml  # registry.k8s.io/pause:3.10
```

Expected — every apply exits 1 with a Kyverno webhook denial naming its
policy, e.g. for the registry attack:

```
Error from server: error when creating "attack-bad-registry.yaml": admission webhook
"vpol.validate.kyverno.svc-fail" denied the request: Policy restrict-registries failed:
Image registry not allowed: every container (including init and ephemeral containers)
must use an image from Docker Hub nginxinc/* or curlimages/*, or
ghcr.io/joesevv/k8s-security-lab/*.
```

Some of these also print a `Warning: would violate PodSecurity` line — that is
the warn-only PSA label on `demo-kyverno-only`. It is advisory and blocks
nothing; the `Error from server` line is what fails the request.

**3b. ATTACK E — capability add-back.** Drops `ALL`, then adds `SYS_ADMIN`
back. The kernel applies `drop` before `add`, so the container really runs
with `CAP_SYS_ADMIN`. **This pod was ADMITTED (exit 0) before the
`capabilities.add` clause was added** to require-drop-all-capabilities — that
prior result is recorded in commit `d9d04d0`. E–I apply the committed
manifests directly, so go back to the repo root first:

```bash
cd "$REPO"   # 3a left the shell in $SCRATCH
kubectl apply -f docs/evidence/phase-2b-admission/attack-add-back-caps.yaml
# -> Error from server: ... Policy require-drop-all-capabilities failed: ...
#    must set securityContext.capabilities.drop to include "ALL" AND must not
#    add any capability back via securityContext.capabilities.add.
# exit 1
```

**3c. ATTACKS F and G — pod controllers.** Same privileged container as
ATTACK A, wrapped in a Deployment and in a CronJob. **ATTACK F returned exit 0
— ADMITTED — before the fix**, with kubectl printing
`deployment.apps/... created` and the denial surfacing only later and
invisibly as a ReplicaSet `FailedCreate` event. Adding
`spec.autogen.podControllers` did not change that (NO-OP on Kyverno 1.18.2);
explicit `apps/v1` and `batch/v1` resourceRules plus the `podSpec` CEL
variable did. Both prior results are recorded in commit `d9d04d0`.
ATTACK G specifically exercises the CronJob
`spec.jobTemplate.spec.template.spec` branch of that variable:

```bash
kubectl apply -f docs/evidence/phase-2b-admission/attack-privileged-deployment.yaml
kubectl apply -f docs/evidence/phase-2b-admission/attack-privileged-cronjob.yaml
# -> both: Error from server: ... Policy disallow-privileged-containers failed
# exit 1 at the apply, not later in an event nobody reads
```

**3d. ATTACK H — ephemeral container injection.** `kubectl debug` attaches a
container to an already-running pod via the `pods/ephemeralcontainers`
subresource. `target-pod-for-debug.yaml` is **not** an attack — it is a fully
compliant pod that exists only to be the injection target:

```bash
kubectl apply -f docs/evidence/phase-2b-admission/target-pod-for-debug.yaml
kubectl wait --for=condition=Ready pod/target-pod-for-debug \
  -n demo-kyverno-only --timeout=120s

kubectl debug -n demo-kyverno-only target-pod-for-debug \
  --image=curlimages/curl:8.11.1 --target=target \
  --profile=sysadmin --container=attacker-ephemeral -- sleep 3600
# --profile=sysadmin is what sets privileged: true on the injected container.
# -> Error from server: ... Policy disallow-privileged-containers failed: ...;
#    Policy require-drop-all-capabilities failed: ...
# exit 1 — two policies fire on a subresource request

kubectl get pod target-pod-for-debug -n demo-kyverno-only \
  -o jsonpath='{.spec.ephemeralContainers}'
# -> empty; nothing was attached to the running pod

kubectl delete -f docs/evidence/phase-2b-admission/target-pod-for-debug.yaml
```

**3e. ATTACK I — hostPath / as root, blocked by PSA not Kyverno.** Run in
`demo`. The error names `PodSecurity` and cites no Kyverno policy, because no
`ValidatingPolicy` here covers hostPath or `runAsUser`:

```bash
kubectl apply -f docs/evidence/phase-2b-admission/attack-hostpath-root.yaml
# -> Error from server (Forbidden): ... pods "attack-hostpath-root" is
#    forbidden: violates PodSecurity "restricted:v1.35": restricted volume
#    types (volume "node-root" uses restricted volume type "hostPath"),
#    runAsNonRoot != true ..., runAsUser=0 ...
# exit 1
```

The counter-proof, and it is deliberately unflattering — the *same* pod in
`demo-kyverno-only`, which has PSA warn but no enforce, is **admitted**:

```bash
sed 's/^  namespace: demo$/  namespace: demo-kyverno-only/' \
  docs/evidence/phase-2b-admission/attack-hostpath-root.yaml > "$SCRATCH/attack-hostpath-root.yaml"
kubectl apply -f "$SCRATCH/attack-hostpath-root.yaml" --dry-run=server
# -> Warning: would violate PodSecurity ...
#    pod/attack-hostpath-root created (server dry run)
# exit 0 — Kyverno inspects it and has nothing to say
```

**3f. Post-attack state.** Admission denials happen before persistence, so
nothing is half-created and no ReplicaSet is quietly retrying:

```bash
kubectl get pods,deploy,rs,job,cronjob -n demo-kyverno-only
# -> No resources found in demo-kyverno-only namespace.

kubectl get pods -n demo
# -> only nginx x2 and signed-app, Running, 0 restarts

rm -rf "$SCRATCH"
```

**A note on `--dry-run=server` as a positive control.** A client-side
`kubectl apply --dry-run=server` against an already-applied, *unchanged*
object computes an empty patch and kubectl returns early without sending it —
verified with `-v=8`, the only request issued is a `GET`. That `unchanged`
line is therefore not evidence that any webhook admitted anything. Use
`--server-side --dry-run=server`, which always sends the PATCH with
`dryRun=All`:

```bash
kubectl apply -f workloads/nginx/deployment.yaml --server-side --dry-run=server
kubectl apply -f workloads/signed-app/deployment.yaml --server-side --dry-run=server
# -> both: deployment.apps/... serverside-applied (server dry run), exit 0
# (a "failed to migrate last-applied-configuration" warning is expected here
#  and is cosmetic — both were originally created with client-side apply)
```

Full verbatim captures of all nine denials, the positive control and its
same-object negative control:
`docs/evidence/phase-2b-admission/attack-output.txt`.

---

## 4. Teardown

No attacker objects to delete — the attacks never created any resources (that
is the point of admission control). The only thing section 3 creates is
`target-pod-for-debug`, deleted inline in step 3d. The attack manifests and
captured evidence stay committed. To remove the layer itself (not done for the
lab):

```bash
# Delete the ValidatingPolicies BY NAME. Do NOT use `kubectl delete -f policies/`:
# that directory also holds 00-namespace-kyverno-only.yaml, so the command would
# delete the demo-kyverno-only Namespace and everything in it. Verified with
# --dry-run=client — it reports `namespace "demo-kyverno-only" deleted` first.
kubectl delete validatingpolicy \
  disallow-privileged-containers disallow-latest-and-bare-tag \
  require-drop-all-capabilities restrict-registries

# `kubectl delete -f <dir>` is non-recursive, so policies/supply-chain/ is out of
# scope either way. The phase-4 ImageValidatingPolicy is torn down in its own
# runbook, not here.

kubectl delete -f policies/00-namespace-kyverno-only.yaml  # optional; demo-only ns
kubectl delete -f rbac/kyverno-reports-ephemeralcontainers.yaml
helm uninstall kyverno -n kyverno      # remove Kyverno
kubectl delete ns kyverno
```

Removing the ValidatingPolicies does **not** remove the Pod Security Admission
profile on `demo` — that is namespace labels, a separate control. To drop that
too you would remove the `pod-security.kubernetes.io/*` labels from the `demo`
namespace.
