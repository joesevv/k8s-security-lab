# Runbook — Phase 1: multi-node kind cluster + nginx target workload

A replayable command log for standing up the lab's baseline cluster and the
hardened nginx workload that later security phases will exercise. Commands are
listed in execution order; each has a one-line purpose and the observed output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash unless
noted. Tool versions used: kind v0.32.0, kubectl v1.36.1, Kubernetes node image
v1.35.5.

---

## 0. Image-pin rationale

- **Kubernetes v1.35.5**: the next phase installs Kyverno 1.18, which supports
  Kubernetes 1.33–1.35 only. v1.35 is the newest supported control plane.
- **Node image pinned by digest**
  (`kindest/node:v1.35.5@sha256:ce977ae6d65918d0b58a5f8b5e940429c2ce42fa3a5619ec2bbc60b949c0ac95`):
  this is the v1.35.5 image published for the kind v0.32.0 release, so the pull
  is byte-identical on every host and cannot drift to another build.
- **nginx image `nginxinc/nginx-unprivileged:1.29.8-alpine@sha256:0c79d56a…`**:
  pinned by digest for immutability (the exact image bytes cannot drift). The
  `1.29.8-alpine` tag is retained alongside the digest for readability and to
  satisfy the no-`latest`/no-bare-tag policy. `1.29.8` was the newest 1.29.x tag
  on Docker Hub at the time; the unprivileged image runs non-root and listens on
  8080, which is what the restricted securityContext requires.

---

## 1. Pre-flight checks

```bash
kind version        # -> kind v0.32.0 go1.26.3 windows/amd64
kubectl version --client   # -> Client Version: v1.36.1
kind get clusters   # -> No kind clusters found.
```
Purpose: confirm tooling is present and no `seclab` cluster already exists.

### inotify limits (Docker Desktop WSL distro)

Kubernetes nodes consume inotify watches/instances; too-low limits cause pods to
crashloop with "too many open files". Check the docker-desktop WSL distro:

```bash
wsl -d docker-desktop sysctl fs.inotify.max_user_watches fs.inotify.max_user_instances
# Observed:
#   fs.inotify.max_user_watches = 1048576
#   fs.inotify.max_user_instances = 8192
```
Purpose: verify limits before creating the cluster.

Result: `max_user_watches = 1048576` (≥ 524288) and `max_user_instances = 8192`
(≥ 512). **Both already above the thresholds — no change was needed.**

> If they had been too low, the ephemeral fix (resets when Docker Desktop /
> the WSL distro restarts) would be:
> ```bash
> wsl -d docker-desktop sysctl -w fs.inotify.max_user_watches=524288
> wsl -d docker-desktop sysctl -w fs.inotify.max_user_instances=512
> ```
> Rerun those after every Docker Desktop restart. Do **not** persist this in
> `.wslconfig` or Docker Desktop settings for this lab.

---

## 2. Create the cluster

```bash
kind create cluster --config clusters/kind-config.yaml
```
Purpose: create the 3-node `seclab` cluster (name comes from the config).
First run pulls the multi-GB node image — allow several minutes.

Observed (trimmed):
```
Creating cluster "seclab" ...
 ✓ Ensuring node image (kindest/node:v1.35.5) 🖼
 ✓ Preparing nodes 📦 📦 📦
 ✓ Starting control-plane 🕹️
 ✓ Installing CNI 🔌
 ✓ Installing StorageClass 💾
 ✓ Joining worker nodes 🚜
Set kubectl context to "kind-seclab"
```

---

## 3. Verify the cluster

```bash
kubectl config current-context        # -> kind-seclab
kubectl wait --for=condition=Ready nodes --all --timeout=300s
kubectl get nodes -o wide
```
Purpose: confirm the active context, that all nodes reach Ready, and that the
topology/version are correct.

Observed:
```
node/seclab-control-plane condition met
node/seclab-worker condition met
node/seclab-worker2 condition met

NAME                   STATUS   ROLES           AGE   VERSION   INTERNAL-IP   OS-IMAGE                       CONTAINER-RUNTIME
seclab-control-plane   Ready    control-plane   44s   v1.35.5   172.18.0.2    Debian GNU/Linux 13 (trixie)   containerd://2.3.1
seclab-worker          Ready    <none>          31s   v1.35.5   172.18.0.4    Debian GNU/Linux 13 (trixie)   containerd://2.3.1
seclab-worker2         Ready    <none>          31s   v1.35.5   172.18.0.3    Debian GNU/Linux 13 (trixie)   containerd://2.3.1
```
3 nodes (1 control-plane + 2 workers), all `Ready`, all `v1.35.5`.

---

## 4. Apply the nginx workload

```bash
kubectl apply -f workloads/nginx/
kubectl rollout status deploy/nginx -n demo --timeout=180s
```
Purpose: create the `demo` namespace, the `nginx-sa` ServiceAccount, the hardened
nginx Deployment (2 replicas), and its ClusterIP Service, then wait for the
rollout.

> **Ordering note:** `kubectl apply -f <dir>` processes files alphabetically, and
> the manifests are numbered so that order matches the dependency order:
> `00-namespace.yaml` → `01-serviceaccount.yaml` → `deployment.yaml` →
> `service.yaml`. So a single apply into a fresh cluster works in one pass — the
> `demo` namespace is created before anything that lives in it, and the
> `nginx-sa` ServiceAccount is created before the Deployment that references it
> via `serviceAccountName: nginx-sa`. No second apply is needed.
>
> `nginx-sa` sets `automountServiceAccountToken: false`, so no API token is
> projected into the nginx pods (nginx serves static content and needs no
> Kubernetes API access). The `01-` prefix guarantees the SA exists before the
> Deployment is admitted.

Expected on a first apply into a fresh cluster (single pass, in numbered order):
```
namespace/demo created
serviceaccount/nginx-sa created
deployment.apps/nginx created
service/nginx created

Waiting for deployment "nginx" rollout to finish: 1 of 2 updated replicas are available...
deployment "nginx" successfully rolled out
```

```bash
kubectl get pods -n demo -o wide
```
Purpose: confirm both replicas are Running and spread across the two workers.

Observed:
```
NAME                     READY   STATUS    RESTARTS   AGE   IP           NODE
nginx-55b9c6bf44-9nkpk   1/1     Running   0          39s   10.244.2.2   seclab-worker2
nginx-55b9c6bf44-fd5gq   1/1     Running   0          39s   10.244.1.2   seclab-worker
```
`readOnlyRootFilesystem: true` with the `/tmp` emptyDir did **not** crashloop —
both pods came up 1/1 and stayed at 0 restarts.

---

## 5. Verify in-cluster reachability

```bash
kubectl run curl-test --rm -i --restart=Never -n demo \
  --image=curlimages/curl:8.16.0 --command -- \
  curl -s -o /dev/null -w "%{http_code}\n" http://nginx.demo.svc.cluster.local
```
Purpose: prove the Service resolves and nginx serves HTTP inside the cluster.

Observed: `200`.

> The `demo` namespace has `pod-security.kubernetes.io/warn: restricted`, so this
> ad-hoc curl pod (which is not hardened) triggers a PodSecurity **warning** —
> expected, and confirms the warn label is active. The nginx Deployment itself
> applies with no such warning because it satisfies the restricted profile.

---

## 6. Teardown / recreate

```bash
kind delete cluster --name seclab
kind create cluster --config clusters/kind-config.yaml
```
Purpose: destroy and rebuild the cluster from scratch. After recreating, re-run
sections 3–5 to re-verify. Reapply the inotify `sysctl -w` values first if
Docker Desktop was restarted in the meantime (see section 1).
