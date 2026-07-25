# Runbook — Phase 2a: RBAC hardening (least-privilege ServiceAccounts + Roles)

A replayable command log for the RBAC layer: giving nginx a dedicated no-token
ServiceAccount, defining a least-privilege `developer` Role, and proving with a
live attack that a token-bearing pod bound to that Role is blocked (HTTP 403)
from reading Secrets while it can still list the resources it is allowed to.
Commands are listed in execution order; each has a one-line purpose and the
observed output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash unless
noted. Kubernetes node image v1.35.5, kubectl v1.36.1.

> **Git Bash path note:** MSYS rewrites Unix-looking absolute paths in `exec`
> arguments (e.g. `/var/run/...` becomes `C:/Program Files/Git/var/run/...`).
> Prefix the affected commands with `MSYS_NO_PATHCONV=1` so the in-container
> path is passed through unchanged.

---

## 0. The controls

- **nginx-sa** (`workloads/nginx/01-serviceaccount.yaml`): a dedicated
  ServiceAccount for nginx with `automountServiceAccountToken: false`. nginx
  needs no Kubernetes API access, so no token is projected into its pods. This
  shrinks the blast radius — a compromised nginx pod has no cluster credential
  to steal.
- **developer Role + developer-sa** (`rbac/developer-role.yaml`): a namespaced,
  read-only Role granting only `get/list/watch` on `pods`, `services` and
  `deployments`. No wildcards, no Secrets, no write verbs. `developer-sa` is the
  identity a developer / CI credential would use; it mounts a token so the
  boundary can be exercised.

---

## 1. nginx dedicated ServiceAccount (no token)

```bash
kubectl apply -f workloads/nginx/
kubectl rollout status deploy/nginx -n demo --timeout=180s
```
Purpose: create `nginx-sa`, wire the Deployment to it, and roll out.

Verify the Deployment uses the SA and that no token is mounted in the pod:

```bash
kubectl get deploy nginx -n demo -o jsonpath='{.spec.template.spec.serviceAccountName}'
# -> nginx-sa

POD=$(kubectl get pods -n demo -l app=nginx -o jsonpath='{.items[0].metadata.name}')
MSYS_NO_PATHCONV=1 kubectl exec -n demo "$POD" -- ls /var/run/secrets/kubernetes.io/serviceaccount
# -> ls: /var/run/secrets/kubernetes.io/serviceaccount: No such file or directory
#    command terminated with exit code 1
```
The missing directory proves `automountServiceAccountToken: false` is in effect.

---

## 2. Least-privilege developer Role

```bash
kubectl apply -f rbac/
```
Purpose: create `developer-sa`, the `developer` Role, and the RoleBinding.

Verify with an `auth can-i` matrix (full capture in
`docs/evidence/phase-2a-rbac/can-i-matrix.txt`):

```bash
SA=system:serviceaccount:demo:developer-sa
kubectl auth can-i list pods            -n demo --as=$SA   # -> yes
kubectl auth can-i get  services        -n demo --as=$SA   # -> yes
kubectl auth can-i list deployments.apps -n demo --as=$SA  # -> yes
kubectl auth can-i get  secrets         -n demo --as=$SA   # -> no
kubectl auth can-i list secrets         -n demo --as=$SA   # -> no
kubectl auth can-i create pods          -n demo --as=$SA   # -> no
kubectl auth can-i delete pods          -n demo --as=$SA   # -> no
```

---

## 3. Attack demo — token pod tries to read Secrets

```bash
# A real Secret so the denial is a 403 (forbidden), not a 404 (not found).
kubectl create secret generic demo-flag -n demo --from-literal=flag=do-not-read-me

# Attacker pod: bound to developer-sa, token mounted, restricted securityContext.
kubectl apply -f docs/evidence/phase-2a-rbac/attacker-pod.yaml
kubectl wait --for=condition=Ready pod/attacker -n demo --timeout=120s
```
Purpose: stand up a token-bearing pod that will attempt the Secret read.

The attack — use the mounted SA token to hit the API for Secrets:

```bash
MSYS_NO_PATHCONV=1 kubectl exec -n demo attacker -- sh -c \
  'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
   curl -s -w "\nHTTP_STATUS:%{http_code}\n" \
     --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://kubernetes.default.svc/api/v1/namespaces/demo/secrets'
```
Expected — HTTP 403 with a Forbidden `Status` object:

```
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "secrets is forbidden: User \"system:serviceaccount:demo:developer-sa\" cannot list resource \"secrets\" in API group \"\" in the namespace \"demo\"",
  "reason": "Forbidden",
  "details": {
    "kind": "secrets"
  },
  "code": 403
}
HTTP_STATUS:403
```

Contrast — the same token CAN list pods (proving it is authorization, not
authentication, being denied):

```bash
MSYS_NO_PATHCONV=1 kubectl exec -n demo attacker -- sh -c \
  'TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token); \
   curl -s -o /dev/null -w "pods list HTTP:%{http_code}\n" \
     --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
     -H "Authorization: Bearer $TOKEN" \
     https://kubernetes.default.svc/api/v1/namespaces/demo/pods'
# -> pods list HTTP:200
```

Full captured output: `docs/evidence/phase-2a-rbac/attack-output.txt`.

---

## Note: layering interaction with Phase 2c (NetworkPolicy)

The HTTP 403 capture above was taken **before Phase 2c existed**. Phase 2c later
added a `default-deny` egress NetworkPolicy in `demo` with only a DNS carve-out
(kube-dns:53); it does **not** allow egress to the API server on 443. As a
result, if you replay the token→API attack **today** the attacker pod cannot even
reach the API server: the curl times out (`HTTP_STATUS:000`, ~5s) at the
**network layer, before RBAC ever returns its 403**. The exact 403 in
`attack-output.txt` is therefore not reproducible while Phase 2c is applied.

To reproduce the RBAC 403 specifically, either:

- replay this demo **before** applying Phase 2c, or
- temporarily add a scoped API-server egress allow (443 to the API server) so the
  request reaches the authorization layer.

This is **defense-in-depth working as intended**, not a flaw: the secret-read
path is now blocked by **two independent layers** — RBAC authorization (403) and
NetworkPolicy egress default-deny (no route to the API server at all). See
`docs/evidence/phase-2a-rbac/REPLAY-NOTE.md` for the replay caveat.

Note the RBAC boundary itself remains continuously verifiable, because
`kubectl auth can-i` is evaluated at the API server via your kubeconfig and does
**not** traverse the attacker pod's network:

```bash
kubectl auth can-i list secrets -n demo \
  --as=system:serviceaccount:demo:developer-sa
# -> no   (still works today, even with Phase 2c applied)
```

---

## 4. Teardown

```bash
kubectl delete pod attacker -n demo
kubectl delete secret demo-flag -n demo
kubectl get pod attacker -n demo      # -> Error from server (NotFound)
kubectl get secret demo-flag -n demo  # -> Error from server (NotFound)
```
Purpose: remove the ephemeral attack artifacts. The replayable manifest
(`docs/evidence/phase-2a-rbac/attacker-pod.yaml`) and the captured evidence
`.txt` files stay committed; the live pod and Secret do not.
