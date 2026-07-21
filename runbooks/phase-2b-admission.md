# Runbook — Phase 2b: Admission control (Kyverno CEL ValidatingPolicies)

A replayable command log for the admission layer: installing Kyverno 1.18 via
a version-pinned Helm chart, deploying four CEL `ValidatingPolicy` resources
scoped to the `demo` namespace, proving them safe in **Audit** mode before
flipping to **Deny**, and proving with four live attacks that non-compliant
pods are blocked at admission while the compliant nginx still rolls out.
Commands are listed in execution order; each has a one-line purpose and the
observed output.

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
  `securityContext.capabilities.drop` to include `ALL`.
- **restrict-registries** — images only from Docker Hub `nginxinc/*` (the lab
  nginx) or `curlimages/*` (the lab curl client). Uses
  `image(c.image).registry()` / `.repository()`; verified on-cluster that the
  literal manifest string `nginxinc/nginx-unprivileged:1.29.8-alpine` (no
  `docker.io/` prefix) normalizes to registry **`index.docker.io`** — not
  `docker.io` — so the policy compares against `index.docker.io`.

Every policy folds `initContainers` and `ephemeralContainers` into an
`allContainers` variable, so the rules cannot be bypassed via init or debug
containers.

**Scoping choice:** all four policies match only the `demo` namespace
(`matchConstraints.namespaceSelector` on `kubernetes.io/metadata.name In
[demo]`). Kyverno's webhook is fail-closed (`failurePolicy: Fail` by default),
so a cluster-wide policy that also matched `kube-system` or `kyverno` itself
could wedge the cluster if the webhook ever misbehaved. In production you
would widen the scope and instead carve out explicit exclusions
(`excludeResourceRules` / namespace exclusions) for system namespaces — that
tradeoff is deliberate here and kept narrow for the lab.

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

**2a. Apply in Audit** (same manifests with `validationActions: [Audit]`):

```bash
for f in policies/*.yaml; do
  sed 's/validationActions: \[Deny\]/validationActions: [Audit]/' "$f" | kubectl apply -f -
done
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

## 3. Attack demo — four violating pods, each blocked at admission

Each manifest in `docs/evidence/phase-2b-admission/` violates exactly one
policy and complies with the other three, so each denial cleanly cites its
target policy:

```bash
cd docs/evidence/phase-2b-admission
kubectl apply -f attack-privileged.yaml    # privileged: true
kubectl apply -f attack-latest-tag.yaml    # nginxinc/nginx-unprivileged:latest
kubectl apply -f attack-no-drop-caps.yaml  # capabilities.drop: []
kubectl apply -f attack-bad-registry.yaml  # registry.k8s.io/pause:3.10
```

Expected — every apply fails with a Kyverno webhook denial naming its policy,
e.g. for the registry attack:

```
Error from server: error when creating "attack-bad-registry.yaml": admission webhook
"vpol.validate.kyverno.svc-fail" denied the request: Policy restrict-registries failed:
Image registry not allowed: every container (including init and ephemeral containers)
must use an image from Docker Hub nginxinc/* or curlimages/*.
```

The pods are rejected at admission, so nothing is created:

```bash
kubectl get pods -n demo
# only the two nginx replicas, Running
```

Full verbatim captures of all four denials plus the positive control:
`docs/evidence/phase-2b-admission/attack-output.txt`.

---

## 4. Teardown

Nothing to delete — the attacks never created any resources (that is the
point of admission control). The attack manifests and captured evidence stay
committed. To remove the layer itself (not done for the lab):

```bash
kubectl delete -f policies/            # remove the four ValidatingPolicies
helm uninstall kyverno -n kyverno      # remove Kyverno
kubectl delete ns kyverno
```
