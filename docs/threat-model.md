# Threat model — k8s-security-lab

What this lab defends, what it deliberately does not, and where each claim is
proven. Every control named here has a committed attack transcript; a control
with no captured denial is an intention, not a control, and is listed in §6
instead.

---

## 1. Scope and method

**The system under consideration.** A three-node kind cluster (`seclab`,
Kubernetes v1.35.5) running on a single Windows 11 host via Docker Desktop with
the WSL2 backend. The "nodes" are containers sharing one WSL2 kernel. The
cluster is **single-tenant** — one operator, no untrusted co-tenants — and
holds **no production data**: the only credential in it is a fake-but-realistic
value used to exercise the secrets layer, and it is never printed in any
committed file.

**Method.** Each layer is modelled as a named adversary with a goal and an
assumed starting capability. For each, the model states the exact step where
they are stopped and links the transcript that shows it. Controls are proven
with a positive control too — the compliant workload must still admit — so the
claim is "precise block", not "blanket block".

**Trusted without verification.** These are roots of trust this lab accepts
rather than defends: the Windows host and the Docker/WSL2 daemon; GitHub as a
code host and as the Actions OIDC issuer; the Sigstore public good instance
(Fulcio CA and the Rekor log); the pinned kind node image digest; the Kyverno
1.18.2 and sealed-secrets 0.38.4 controller images; and Docker Hub for the
`nginxinc/*` and `curlimages/*` images. Compromise of any of these defeats
everything below by construction.

**Out of frame entirely.** Physical access; container-runtime or WSL2 kernel
escapes; denial of service and resource exhaustion; the human process (review,
approvals, on-call); and multi-tenancy, which this cluster does not have.

The boundaries below are drawn **at the cluster**, not at the host.

---

## 2. Assets, ranked

Ranked by what an attacker would actually go after, not by what is most
interesting to write about.

1. **The cluster's compute.** Three nodes' worth of CPU. The realistic outcome
   of a compromised Kubernetes cluster is not espionage — it is cryptomining or
   botnet capacity. Any path that ends in "attacker runs a container of their
   choosing" satisfies this goal, which is why admission control is the thickest
   layer in the lab.
2. **The sealing private key.** An RSA key held as a `kubernetes.io/tls` Secret
   in `kube-system` (observed on this cluster as `sealed-secrets-key2t2vk`).
   Compromise here is **retroactive**: whoever reads it can decrypt every
   `SealedSecret` this repo has ever committed, offline, forever, and rotating
   the key does nothing for ciphertext already published in Git history.
3. **The GHCR publishing identity.** Not a file — the *ability to make the
   cluster accept an image*. Concretely it is push access to `refs/heads/main`,
   because `require-keyless-signed-ghcr` pins exactly one subject:
   `.../.github/workflows/supply-chain.yml@refs/heads/main`. Anyone who can land
   a commit on `main` can mint a signature the cluster admits. This asset
   converts a Git permission into in-cluster code execution.
4. **`demo/demo-app-secret`.** The credential the secrets layer exists to
   protect. Low intrinsic value (it is fake), high demonstrative value: it is
   the object every "is the secret safe?" proof resolves against.
5. **Node-level root.** Root inside a kind node container is one shared kernel
   away from the host. `hostPath` mounts of `/`, host namespaces and privileged
   containers all lead here, which is why Pod Security Admission is enforced
   rather than merely warned.
6. **The Git history.** Distinct from the working tree: a secret committed once
   is committed forever, and history is the asset the phase-3 controls are
   really protecting. `git log --all -p` is part of that phase's proof for
   exactly this reason. As of 2026-07-25 this repository is **public**, so the
   history is world-readable and permanently mirrorable by anyone — the exposure
   of this asset changed in kind, not in degree. What now guards it, and what
   does not, is in §6.11.

---

## 3. Trust boundaries

Five boundaries. For each: what crosses it, what guards the crossing, and what
the guard does not cover.

### 3.1 Git → cluster

**Crosses:** the SealedSecret ciphertext in
[`secrets/demo-app-sealedsecret.yaml`](../secrets/demo-app-sealedsecret.yaml).

**Guard:** asymmetric encryption plus strict scope. `kubeseal` encrypts with the
controller's **public** cert (encrypt-only); only the in-cluster private key can
decrypt. Default STRICT scope binds the ciphertext cryptographically to
`demo/demo-app-secret`, so the same bytes re-applied under a different
namespace or name are refused.

**Not covered:** the ciphertext is inert but not confidential-forever — it is
only as strong as the sealing private key (asset 2 in §2), which is itself
stored **unencrypted at rest** in etcd (§6.1). Rotating the sealing key does not
retroactively protect ciphertext already published in Git history.

**A second crossing opened on 2026-08-07.** Until phase 7, every other manifest
in this repo reached the cluster only because a human ran `kubectl apply`. One
set of them now has a standing, automated path across this same boundary, and
it has a different guard and a different uncovered set from the ciphertext
above.

**Crosses:** the 7 objects under [`workloads/`](../workloads/) — Namespace
`demo`, the `nginx-sa` and `signed-app-sa` ServiceAccounts, the `nginx` and
`signed-app` Deployments and their two Services — applied into `demo` by
ArgoCD's `demo-workloads` Application
([`gitops/application-workloads.yaml`](../gitops/application-workloads.yaml))
from `targetRevision: main`. With `syncPolicy.automated` set and the
controller's default reconcile interval of 180 s, that is a standing pull
rather than a one-off apply. The revision the Application reported syncing was
checked against `git ls-remote` and is the tip of `main`.

**Guard:** honestly, very little, and the list is short enough to write out.
The repo is public, so the clone is anonymous — there is no credential and no
Secret in this path at all, which removes a thing to steal but constrains
nothing about what gets pulled. `prune: false` bounds the deletion side: a
manifest that vanishes from `main` leaves the live object standing, so a
mis-scoped Application cannot sweep away the `developer` Role, the four
NetworkPolicies or the SealedSecret that share the namespace. And the scope is
one `source.path`, `workloads`. **Kubernetes RBAC is not on that list.** The
`argocd-application-controller` ServiceAccount's ClusterRole was diffed against
the built-in `cluster-admin` and the two rule sets are byte-identical
(exit code: 0 — no difference), so nothing in the API server's authorization
confines the controller to the 7 objects it syncs; that scoping is convention,
not capability (§6.14 item 2). Admission is not on the list either, as far as
the controller itself goes: namespace `argocd` carries no Pod Security label
and sits outside the `[demo, demo-kyverno-only]` selector all five Kyverno
policies use, so neither layer evaluates it (§6.14 item 3). The gates on `demo`
do still evaluate what ArgoCD applies *there* — but all phase 7 showed is that
a *compliant* spec was admitted and ran; no hostile commit was tested (§A2).

**Not covered:** the content. Commit signature verification is not configured —
no `signatureKeys` on the `default` AppProject and no keys in
`argocd-gpg-keys-cm` — and nothing else inspects what the manifests say either,
the AppProject's `sourceRepos`, `destinations` and `clusterResourceWhitelist`
all being `*`. Whatever is on `main` is applied faithfully, so anyone who can
merge to `main` can change what runs in `demo`. That is not the same as open:
`main` carries the `protect-main` ruleset (`bypass_actors: []`,
`current_user_can_bypass: "never"`), whose `pull_request` rule routes every
change through a pull request instead of a direct push, so this path runs
through review rather than around it. But the counterweight has to be stated at
its real weight — `required_approving_review_count` is **0** and `joesevv` is
the only collaborator, so one account can open a pull request and merge it
seconds later with no second human, and review by a single maintainer is
**a process control, not a technical one** (§6.10). Nothing on the cluster
enforces it. Reconciliation does not close the gap either. It answers after the
fact, so a hostile commit runs until a person notices it; and because a commit
on `main` *is* the desired state, ArgoCD would not revert it at all — with the
shipped `selfHeal: true` it would re-apply it every time an operator removed it
by hand. §6.14 item 4 records the same finding from the cost side.

### 3.2 CI → registry → admission

**Crosses:** the cosign signature — a Fulcio certificate plus a Rekor log entry
bound to an image **digest**.

**Guard:** keyless OIDC identity pinned to one exact subject string (no regex),
verified against the transparency log — see
[`require-signed-images.yaml`](../policies/supply-chain/require-signed-images.yaml)
(`insecureIgnoreTlog: false`, `insecureIgnoreSCT: false`). In CI the signing
privilege is isolated: every third-party action runs in the `build-scan` job,
which has **no** `id-token` permission, so a compromised action cannot mint the
identity the cluster trusts. That last clause is still a **design** claim, read
off the workflow's `permissions:` block. What run 30174855073 (2026-07-25) added
is narrower: it was the first execution of the two-job split and both jobs
passed — `build-scan` (53s) built, scanned and pushed with no `id-token`, and
`sign` (10s) held `id-token: write` and ran nothing but GHCR login,
`cosign sign` and a verify self-check. That is evidence the permission is
genuinely **unnecessary** in `build-scan`, so the split is not paid for in
broken builds. No step attempted to mint an OIDC token from `build-scan` and was
refused, so the blocking half was never exercised; see §6.9.

**Not covered:** the signature attests **provenance, not safety** (§6.5), and
the pinned subject means the boundary is really "who can push to `main`"
(asset 3 in §2). That boundary is now checkable — the repository is public, so
the branch API is no longer plan-gated — and it was checked on 2026-07-25.
Classic branch protection is absent
(`GET /repos/joesevv/k8s-security-lab/branches/main/protection` → HTTP 404
`Branch not protected`), but that endpoint does not see rulesets and a ruleset
**is** active: `protect-main` applies `non_fast_forward`, `deletion` and
`pull_request` to the default branch. So a guard exists — it is just
one-person-satisfiable: zero required approving reviews and no required status
check. The exact configuration and the residual are in §6.10.

### 3.3 Pod → API server

**Crosses:** a projected ServiceAccount token.

**Guard:** three independent things. RBAC — the `developer` Role grants only
`get/list/watch` on pods, services and deployments, with no wildcards, no
Secrets and no write verbs
([`rbac/developer-role.yaml`](../rbac/developer-role.yaml)). No token at all for
the workloads that do not need one — `nginx-sa` and `signed-app-sa` set
`automountServiceAccountToken: false`, so there is no credential in those pods
to steal. And NetworkPolicy egress default-deny, which allows only DNS, so a
pod cannot reach `kubernetes.default.svc:443` in the first place.

**Not covered:** anything running in a namespace other than `demo`. The
NetworkPolicies are namespaced to `demo` and the RBAC Role is namespaced too.

### 3.4 Internet / registry → cluster

**Crosses:** image bytes.

**Guard:** a registry allow-list (`restrict-registries` — Docker Hub
`nginxinc/*`, `curlimages/*`, and `ghcr.io/joesevv/k8s-security-lab/*` only),
an immutable-reference rule (`disallow-latest-and-bare-tag`), digest pinning in
the workload manifests, and signature verification for the GHCR path. The
`ImageValidatingPolicy` also sets `verifyDigest: true` / `mutateDigest: true`,
so a tag reference is resolved and rewritten to the digest that was actually
verified.

**Not covered:** the two Docker Hub prefixes are allow-listed but **unsigned** —
nothing verifies who built `nginxinc/nginx-unprivileged`. Trust there rests on
the digest pin alone.

### 3.5 Pod → pod

**Crosses:** cluster network traffic.

**Guard:** [`network/00-default-deny.yaml`](../network/00-default-deny.yaml)
denies all ingress **and** all egress for every pod in `demo`; a DNS carve-out
allows 53/UDP+TCP to CoreDNS only; and a label-gated pair
(`20-allow-nginx-ingress-from-client`, `30-allow-client-egress-to-nginx`) opens
exactly TCP 8080 between pods labelled `access=nginx` and pods labelled
`app=nginx`. No allow-all rules and no CIDR blocks. Enforcement by kindnet was
confirmed empirically before the phase was built — see the caveat at the top of
[`runbooks/phase-2c-network.md`](../runbooks/phase-2c-network.md).

**Not covered:** the label is the sole discriminator, and any principal who can
create a pod in `demo` can set that label. NetworkPolicy is not authentication.

---

## 4. Adversaries

Five adversaries, one per control phase. Phase 1 adds no control of its own —
the cluster config is deliberately bare, and the consequences are in §6.

### A1 — The borrowed ServiceAccount (phase 2a, RBAC)

**Goal:** read `Secret` objects in `demo` and exfiltrate a credential.
**Capability assumed:** code execution in a pod that mounts a token for
`developer-sa` — i.e. a compromised developer/CI identity, not cluster-admin.
**Stopped at:** API-server authorization. `developer` grants no verb on
`secrets`, so the request returns `403 Forbidden` while the same token still
lists pods with `200` — proving it is authorization being denied, not
authentication.
**Evidence:** [`attack-output.txt`](evidence/phase-2a-rbac/attack-output.txt)
and [`can-i-matrix.txt`](evidence/phase-2a-rbac/can-i-matrix.txt) in
[`evidence/phase-2a-rbac/`](evidence/phase-2a-rbac/).

**Honesty note.** That 403 is a point-in-time capture from 2026-07-21, taken
before phase 2c existed. Replayed today the request never reaches the
authorization layer at all: egress default-deny drops it and curl times out
(`HTTP_STATUS:000`). Two independent layers now block the same path — see
[`REPLAY-NOTE.md`](evidence/phase-2a-rbac/REPLAY-NOTE.md). The boundary itself
stays continuously checkable without traversing the pod's network:

```bash
kubectl auth can-i list secrets -n demo \
  --as=system:serviceaccount:demo:developer-sa
# -> no
```

### A2 — The privileged deploy (phase 2b, admission)

**Goal:** run a container with node-level power — `privileged: true`, a
`hostPath` mount of `/`, added-back capabilities, or a mutable `:latest` tag
that can be repointed later.
**Capability assumed:** permission to create workloads in `demo` (a developer, a
CI service account, or a compromised GitOps controller).
**Stopped at:** admission, before the object is persisted — so there is no
running pod to detect or evict. Two layers, in a fixed order:

1. **Pod Security Admission** (`enforce: restricted`, `v1.35`) is an in-process
   API-server plugin and runs **before** any webhook. It catches privileged,
   `hostPath`, host namespaces, `runAsUser: 0` and un-dropped capabilities.
2. **Four Kyverno `ValidatingPolicy` resources** in `Deny` catch what
   `restricted` does not care about: mutable tags and untrusted registries.

PSA **short-circuits** — when it rejects, the webhook is never called. Verified
today with a server-side dry run: `attack-privileged.yaml` and
`attack-no-drop-caps.yaml` return `violates PodSecurity "restricted:v1.35"`
with no Kyverno message, while `attack-latest-tag.yaml` (which `restricted` has
no opinion on) falls through and is denied by
`vpol.validate.kyverno.svc-fail`. That ordering is why
[`00-namespace-kyverno-only.yaml`](../policies/00-namespace-kyverno-only.yaml)
exists: a `warn`-only namespace where the Kyverno denials stay observable.
**Evidence:** [`attack-output.txt`](evidence/phase-2b-admission/attack-output.txt)
and the `attack-*.yaml` manifests beside it in
[`evidence/phase-2b-admission/`](evidence/phase-2b-admission/).

**Engine limitation worked around.** `spec.autogen.podControllers` is a
**no-op** on Kyverno 1.18.2 — a privileged `Deployment` was admitted at exit 0
with it in place. Pod-controller coverage is therefore explicit `resourceRules`
(`apps/v1` deployments/statefulsets/daemonsets/replicasets, `batch/v1`
jobs/cronjobs) plus `pods/ephemeralcontainers` to close the `kubectl debug`
injection path.

**The compromised GitOps controller in that capability list stopped being
hypothetical on 2026-08-07.** Phase 7 installed ArgoCD v3.5.0 into namespace
`argocd` with a ServiceAccount whose ClusterRole is **byte-identical** to the
built-in `cluster-admin` — `verbs ['*']` on `resources ['*']` in `apiGroups
['*']`, plus `nonResourceURLs ['*']` — and gave it one `Application` holding
standing, automated apply authority over 7 objects in `demo`, sourced from
whatever is on `main`. This section's third assumed capability is therefore a
resident component of this cluster rather than an imagined one, and its RBAC is
not scoped to the 7 objects it syncs. Two things are worth separating. The
gates above are unchanged and still evaluate whatever reaches them, whoever
wrote it — but what phase 7 actually demonstrated is only that a *compliant*
spec ArgoCD wrote into `demo` was applied and its pods ran without incident;
**no hostile commit was tested**, so nothing here shows how PSA and Kyverno
would treat a non-compliant workload delivered through git. And the controller itself is
outside both gates: `argocd` is ungated, no commit signature verification is
configured, and with `selfHeal: true` a bad commit would not merely be applied
once — it would be re-applied every time an operator removed it by hand. §6.14
records the whole of it.

### A3 — The neighbour pod (phase 2c, network)

**Goal:** move laterally — reach `nginx` from another pod in the same namespace,
or reach anything outside it.
**Capability assumed:** code execution in **some** pod in `demo` that is not the
authorized client.
**Stopped at:** the CNI. Default-deny drops the connection: the unlabelled pod's
curl to `nginx.demo.svc.cluster.local` returns `HTTP:000` after a 5-second
timeout, while an otherwise byte-identical pod carrying `access=nginx` gets
`HTTP:200` in ~2 ms. Both resolve DNS successfully, so the failure is the policy
and not the resolver.
**Evidence:** [`attack-output.txt`](evidence/phase-2c-network/attack-output.txt)
in [`evidence/phase-2c-network/`](evidence/phase-2c-network/), alongside the two
pod manifests `attacker-unauthorized.yaml` and `client-authorized.yaml`.

### A4 — The repo reader (phase 3, secrets)

**Goal:** recover `demo-app-secret` from the Git repository.
**Capability assumed:** none beyond internet access. The repository is public as
of 2026-07-25, so a full clone including history is available to anyone,
unauthenticated — A4 is the baseline position of every reader, not a granted
premise. No cluster access.
**Stopped at:** cryptography, twice. Base64-decoding the committed
`encryptedData` yields RSA-OAEP + AES-GCM ciphertext — the fetched cert is
public and encrypt-only, and the private key never leaves the cluster, so
offline unsealing is impossible. Copying the SealedSecret into an attacker-owned
namespace and re-applying it is refused by strict scope
(`ErrUnsealFailed: no key could decrypt secret`) — same ciphertext, one
namespace of difference, no Secret produced. A `git grep --untracked` and a
`git log --all -p` sweep find neither the literal value nor its base64 form.
**Evidence:** [`attack-output.txt`](evidence/phase-3-secrets/attack-output.txt)
in [`evidence/phase-3-secrets/`](evidence/phase-3-secrets/), alongside
`scope-theft-attacker-ns.yaml`.

### A5 — The unsigned image (phase 4, supply chain)

**Goal:** get bytes the trusted pipeline never produced to run in the cluster —
a backdoored build, a retagged image, or an image swapped in after review.
**Capability assumed:** push access to the GHCR namespace, plus permission to
create workloads in `demo`. Notably **not** the ability to run this repo's
signing workflow on `main`.
**Stopped at:** the `ImageValidatingPolicy` webhook. The headline attack uses an
image that genuinely exists in the registry and is genuinely unsigned — cosign's
own signature artifact, published under the OCI referrers-fallback tag
`sha256-<digest>`, which nothing ever signed itself. Verified today with a
server-side dry run:

```
admission webhook "ivpol.validate.kyverno.svc-fail-finegrained-require-keyless-signed-ghcr"
denied the request: Policy require-keyless-signed-ghcr failed: Image must be
cosign keyless-signed by the k8s-security-lab GitHub Actions workflow.
```

The positive control passes in the same breath — but only when the dry run is
the server-side kind. Re-applying the signed-app
[`deployment.yaml`](../workloads/signed-app/deployment.yaml) at the real signed
digest `sha256:7fd13d22…` with `--server-side --dry-run=server` returns
`deployment.apps/signed-app serverside-applied (server dry run)`. The plain
`kubectl apply --dry-run=server` an earlier capture used does **not** count: on
an unchanged object kubectl diffs client-side, computes an empty patch and
issues only a `GET`, so the `unchanged` it prints never reaches admission at all
— the `1b) METHODOLOGY CORRECTION` section of the evidence keeps that `-v=8`
trace. Only the server-side form sends a `PATCH`, which is why the same flag on
the same object type yields a pass here and the denial above.
**Evidence:** [`attack-output.txt`](evidence/phase-4-supply-chain/attack-output.txt)
in [`evidence/phase-4-supply-chain/`](evidence/phase-4-supply-chain/), alongside
`attack-unsigned-existing-artifact.yaml` (the headline — a resolvable but
unsigned image) and `attack-unsigned-image.yaml` (a tag that was never built,
which proves only the weaker fail-closed property).

---

## 5. Control → MITRE ATT&CK for Containers

Mappings are **mitigations**, marked (F) where the control fully blocks the
technique on the enforced scope and (P) where it only raises cost or covers one
variant. Only techniques justified by what is actually enforced are listed;
where a mapping was tempting but not defensible from the manifests, it was left
out.

| Control | Where | ATT&CK technique(s) |
| --- | --- | --- |
| Pod Security Admission `enforce: restricted` on `demo` | [`workloads/nginx/00-namespace.yaml`](../workloads/nginx/00-namespace.yaml) | T1611 Escape to Host (F, for `hostPath` / host-namespace / privileged variants); T1610 Deploy Container (P) |
| Kyverno `disallow-privileged-containers` | [`policies/`](../policies/) | T1611 Escape to Host (P); T1610 Deploy Container (P) |
| Kyverno `require-drop-all-capabilities` | [`policies/`](../policies/) | T1611 Escape to Host (P) |
| Kyverno `restrict-registries` (allow-list) | [`policies/restrict-registries.yaml`](../policies/restrict-registries.yaml) | T1204.003 User Execution: Malicious Image (P — prefix matching constrains *where* an image comes from, not *what is in it*: a malicious image pushed **inside** an allow-listed prefix is admitted, and §3.4 concedes the two Docker Hub prefixes are unsigned. The (F) for this technique is earned by the `ImageValidatingPolicy` row below, which is what actually checks the bytes — and only on the GHCR path); T1610 Deploy Container (P) |
| Kyverno `disallow-latest-and-bare-tag` + digest pins in the workload manifests | [`policies/`](../policies/), [`workloads/`](../workloads/) | T1525 Implant Internal Image (P — a moved tag can no longer silently change the bytes a manifest resolves to) |
| Kyverno `ImageValidatingPolicy` — cosign keyless identity + Rekor | [`policies/supply-chain/require-signed-images.yaml`](../policies/supply-chain/require-signed-images.yaml) | T1525 Implant Internal Image (F, for the GHCR path); T1204.003 Malicious Image (F, same scope) |
| Explicit `resourceRules` covering `batch/v1` jobs and cronjobs | [`policies/`](../policies/), [`policies/supply-chain/`](../policies/supply-chain/) | T1053.007 Scheduled Task/Job: Container Orchestration Job (P) |
| `resourceRules` covering `pods/ephemeralcontainers` | [`policies/`](../policies/) | T1610 Deploy Container (P — closes the `kubectl debug` injection path) |
| Least-privilege `developer` Role — no `secrets`, no write verbs, no wildcards | [`rbac/developer-role.yaml`](../rbac/developer-role.yaml) | T1552.007 Unsecured Credentials: Container API (F, for `secrets` in `demo`); T1078 Valid Accounts (P); T1613 Container and Resource Discovery (P — the Role deliberately *permits* read on pods/services/deployments, so it narrows discovery to three resource types rather than blocking it) |
| `automountServiceAccountToken: false` on `nginx-sa` / `signed-app-sa` | [`workloads/nginx/01-serviceaccount.yaml`](../workloads/nginx/01-serviceaccount.yaml) | T1552.007 Container API (F — no token exists in the pod to abuse); T1078 Valid Accounts (P) |
| NetworkPolicy default-deny ingress **and** egress + label-gated allows | [`network/`](../network/) | T1046 Network Service Discovery (F, within `demo` — a pod may reach only CoreDNS:53 and, if labelled `access=nginx`, nginx:8080; the (F) is for *connection-based* discovery: [`network/10-allow-dns.yaml`](../network/10-allow-dns.yaml) opens 53/UDP+TCP to CoreDNS for every pod in `demo`, so cluster-wide service **name** enumeration survives — A3 notes both pods resolve DNS); T1613 Container and Resource Discovery (P — removes the API-server path); T1496 Resource Hijacking (P — a miner in `demo` has no egress to reach a pool) |
| sealed-secrets: only ciphertext in Git, strict namespace/name scope | [`secrets/demo-app-sealedsecret.yaml`](../secrets/demo-app-sealedsecret.yaml) | T1552.001 Unsecured Credentials: Credentials In Files (F, for this repo's committed set and its history) |
| Kubelet `seccompDefault: true` — the runtime's default syscall filter applied by the kubelet rather than by a namespace label (phase 5b, 2026-07-30) | [`clusters/kind-config.yaml`](../clusters/kind-config.yaml) | T1611 Escape to Host (P — it narrows the syscall surface an escape can reach, and it does so on all three nodes rather than in `demo` only: the field is set in every node's kubelet config and `/configz`, and a probe pod that requested **no** profile was measured loading a second filter, `Seccomp_filters` 1 → 2. No escape was tested against it, and §6.3 still stands — this is not a MAC profile and not a second kernel) |

Outside this table: the CI signing path also addresses **T1195.002 Compromise
Software Supply Chain**, which is an Enterprise technique (Linux/Windows/macOS)
and has no place in the ATT&CK for Containers matrix above.

Not claimed: runtime-behaviour techniques. Since 2026-07-29 a runtime sensor
does exist and does observe them (§6.4), but observing is not mitigating and
this table lists mitigations only. Also not claimed: any technique in a
namespace the policies do not select (§6.7).

Phase 5 has deliberately **no row here.** kube-bench is an assessment, not a
mitigation: it blocks no technique, and this table's rule is that only
techniques justified by what is actually enforced get listed. A scan that
changed no manifest mitigates nothing, so the findings it produced are recorded
as residual risk in §6.12 instead.

Phase 5b earns exactly **one** row, and the count is the interesting part. It
did change the cluster's configuration on 2026-07-30, so the reasoning above
does not dispose of it — but of the eight settings it landed (§6.12) only
`seccompDefault` clears this table's bar, which is a technique ID this document
can defend inside the ATT&CK for Containers matrix *and* an enforced effect
this lab measured. The rest were considered and left out rather than rounded
up. `podPidsLimit` bounds PID exhaustion, which is Endpoint Denial of Service —
an Enterprise technique whose place in the Containers matrix this document is
not sure enough of to cite, and T1496 Resource Hijacking is not what a PID
ceiling stops. `--kubelet-certificate-authority` with `serverTLSBootstrap` is
the strongest of the eight in security terms and still gets no row: what it
answers is adversary-in-the-middle on the API server → kubelet path, nothing of
that kind was demonstrated here, and the same matrix-membership doubt applies.
`AlwaysPullImages` forces a pull rather than refusing a deployment, so neither
T1610 nor T1204.003 would be honest, and reading it as T1525 would stretch
"implant internal image" to cover a node's local image cache. `--profiling=false`
closes an endpoint no technique in this matrix names. A wrong technique ID is
worse than a missing row.

Phases 6 and 6b have deliberately **no row here either**, for a different
reason. Falco does engage with runtime techniques — it matches the syscalls and
names what it saw — but the only artifact it produces is an alert, and since
2026-08-03 that alert is routed to a store and queryable there rather than left
on a pod's stdout (§6.4). Nothing still acts on it. A (P) marking is the easiest
overclaim available in this document: (P) is defined above as "raises cost or
covers one variant", and an alert nobody reads does neither, whether it is read
out of a log or out of a dashboard. An attacker who spawned the shell in `demo`
on 2026-07-29 kept the shell, and the one who spawned the marked shell on
2026-08-03 kept that one too. ATT&CK keeps
detections separate from mitigations for exactly this reason, and this table
has no detection column; adding one would mean re-deriving every row above
against a standard they were not written to. What the sensor saw, what it did
not see, and what nothing does about either are in §6.4 and §6.13.

Phase 7 takes **no row here either**, and the blocker is a technique ID rather
than a doubt about effect. What ArgoCD answers is out-of-band modification of a
running workload's security configuration — a `kubectl patch` that removed
`readOnlyRootFilesystem` from the live `demo/nginx` Deployment — and unlike an
alert nobody reads, this genuinely raises an attacker's cost: the change was
undone automatically in 1.29 s, and with `selfHeal: true` it would be undone
again every time it was re-made, so a (P) is arguable on the merits in a way it
never was for phase 6. What is not arguable is which technique that maps to. No
technique in the ATT&CK for Containers matrix cleanly names "modify the spec of
a running workload"; the nearest candidates describe something else — T1610
Deploy Container is the creation of a new container to evade defences rather
than the weakening of an existing one, and reading this as T1562.001 Impair
Defenses would mean treating a workload's own `securityContext` as a security
tool being disabled. This document's standing rule decides it: **a wrong
technique ID is worse than a missing row.** There is a second reason for care.
Every row above is a mitigation that acts before or instead of the technique it
names, and ArgoCD acts after — the weakened pod was admitted, started, and ran
for roughly a second before the revert killed it (§6.14) — so even a defensible
ID would need a marking this table does not have. The measured effect is
recorded in §6.14 and in the README's attack → control table instead.

---

## 6. Residual risk and what is deliberately out of scope

These are engineering decisions with reasons, not apologies. Each states the
consequence plainly, so a reader can judge the gap rather than discover it.

**6.1 No encryption at rest for etcd.** Verified: the `kube-apiserver` static
pod carries no `--encryption-provider-config` flag. Every `Secret` — including
the sealing private key (asset 2 in §2) — is stored base64-encoded, not
encrypted, in etcd. **Why:** etcd is a process in a container on the same host
would hold the encryption key. Encrypting against a key stored beside the data
defends a threat this deployment does not have (offline disk theft) while adding
key-management surface that would obscure the layers the lab is actually about.
In production this is table stakes and would be a KMS provider, not a local key.

**6.2 No audit logging.** Verified: no `--audit-policy-file` and no
`--audit-log-path` on the API server — 1.2.16–1.2.19 were still FAIL on the
2026-07-30 run, after the phase-5b rebuild (§6.12).
[`clusters/kind-config.yaml`](../clusters/kind-config.yaml) is no longer bare:
since 2026-07-30 it carries `kubeadmConfigPatches`, the ones phase 5b used to
set control-plane flags and kubelet fields. It still carries no `extraMounts`.
**Why:** wiring audit into kind means patching kubeadm **and** host-mounting a
policy file and a log path into the control-plane node; phase 5b did the first
half and deliberately not the second, because the mount is where the failure
mode is — a control plane that will not boot. **That weakens the reason this
item used to give, and the weakening is written down rather than deleted:** the
old argument was that audit was excluded because it is cluster-lifecycle
plumbing rather than a security control, and that argument is thinner now that
the file does carry kubeadm patches. What is left of it is the mount, not the
patch. **Consequence, stated
plainly:** there is no record of *who did what* to this cluster. Every denial in
this document is a preventive control; none of them is detective. Phase 5's
kube-bench run (§6.12) does not change that: a point-in-time configuration scan
is neither preventive nor detective — it observes posture once, on request, and
would not notice an action taken against this cluster a second later. Phase 5b
changed configuration, not logging, so it does not change it either. Phase 6's
Falco (§6.4, §6.13) changes that only in part, and not in the direction this
item is about: it is genuinely detective, but it watches syscalls on the nodes,
not requests at the API server, so it still records nothing about *who called
what*. Deleting a NetworkPolicy or reading a Secret through the API leaves no
trace on this cluster either way, and Falco's own output — routed to a store
and queryable there since 2026-08-03 (§6.4) — is a record of syscalls on the
nodes, not of who called what at the API server, so it is not an audit trail.

**6.3 No node or kernel hardening.** No AppArmor or SELinux profile beyond
`seccompProfile: RuntimeDefault`, no gVisor or Kata, and all three nodes are
containers on one shared WSL2 kernel. CIS remediation is no longer none. A
benchmark still measures a gap rather than closing it, so what closed anything
here was a configuration change and not the scan: on 2026-07-30 phase 5b set
`seccompDefault: true` and `podPidsLimit: 4096` in the kubelet configuration of
every node (§6.12), which is exactly the pair of results that landed on this
item — 4.2.14 and 4.2.13, both WARN → PASS. The seccomp half is the meaningful
one here, and the change is narrow enough to state exactly. `RuntimeDefault`
used to be applied only where a PSA `restricted` label put it — that is `demo`
alone, per §6.7 — and it is now the kubelet's **default** on all three nodes:
the profile a pod gets when it asks for none. Read as ground truth
rather than off the flag: a probe pod declaring no profile goes from
`Seccomp_filters: 1` to `Seccomp_filters: 2`, a second filter loaded above the
one every process in a kind node inherits from Docker. The PID half bounds
fork-bomb blast radius at the pod cgroup slice. **Both narrow this gap; neither
closes it.** A default syscall filter is not a mandatory-access-control profile
and not a second kernel, and no escape was tested against it. **Consequence:** a
kernel-level escape that gets past PSA and past that filter lands on the host
directly — there is no second wall.
Since 2026-07-29 a kernel-level eBPF probe watches that same shared kernel
(§6.4), so such an escape would stand a chance of being *seen*. It is still not
a second wall: seeing is not stopping, nothing acts on what is seen — since
2026-08-03 the alert is routed to a store and no further (§6.4) — and the probe
itself is a privileged component on the kernel it watches (§6.13).

**6.4 Runtime behaviour is now observed and filed, and nothing responds to what
is observed.** Every *control* in this document still fires at admission time or
at connection time. A workload that is admitted and *then* misbehaves — a shell
spawned in a container, a miner started inside an allow-listed and correctly
signed image — is still not **stopped** by anything here, and signature
verification remains explicitly not a behavioural control. What changed on
2026-07-29 is the other half of the old concession, and only that half. Falco
0.44.1 runs as a DaemonSet on all three nodes, reading syscalls through a
modern eBPF probe, so such misbehaviour is now **detected**: an interactive
shell in the hardened `demo/nginx` pod produced `A shell was spawned in a
container with an attached terminal` at priority Notice, and a busybox copy
executed out of `/dev/shm` produced `File execution detected from /dev/shm` at
priority Warning — both inside the attack window, with pod name, namespace,
image and uid 101 resolved on the alert. Message text and priority are what
those 2026-07-29 alert lines carry; `json_output` was off then, so the stock
rule names behind them are an identification against the shipped ruleset and
not a captured field — which changed on 2026-08-03 and is the smaller half of
what phase 6b bought, below. **Both attacks succeeded.**
The shell returned exit 0; the staged binary ran (`evt_res=SUCCESS`); afterwards
the pod was still Running with its restart count unchanged and the payload
still sitting in `/dev/shm` until it was cleaned up by hand.

**What happens to a Falco alert on this cluster is: it gets filed, and then
nothing.** Until 2026-08-03 it was written to the falco container's stdout and
no further. Phase 6b changed the routing half of that, and only that half:
`falcosidekick.enabled=true` on the existing release flipped Falco's own
`http_output.enabled` to `true` with `url: http://falco-falcosidekick:2801`
and `json_output` to `true` — read back out of a running container, not off the
chart — so an alert now POSTs to falcosidekick, which writes it into the Web
UI's Redis. **Two things improved, and they are worth naming exactly.** An
alert now outlives the container that produced it: all three Falco pods were
deleted, `grep -c` on every replacement pod's log returned 0, and the marked
event was still retrievable from the store under the same UUID. And it is
queryable in one place, with the rule name (`"rule":"Terminal shell in
container"`) and the ruleset's own ATT&CK tags (`T1059`, `mitre_execution`)
travelling with it — enrichment phase 6 could not capture.

**Nothing else improved, and one thing acquired a new failure mode.**
`responseActions.enabled` is still `false` and no responder — Falco Talon or
anything else — is installed, so no action follows an alert. Exactly one
falcosidekick output is enabled and it is the in-cluster Web UI (`Enabled
Outputs: [WebUI]`, from the component's own startup line): no credential was
entered anywhere, so the UI keeps the chart's default one, no output in this
release is configured to reach outside the cluster, and the UI is served only
through `kubectl port-forward`. There is still no rota, no
owner and no notification, and **a dashboard nobody opens is still an alert
nobody reads.** `file_output` and `program_output` remain off. One channel is
nominally on and is worth naming rather than omitting: `syslog_output` is
`true`, but it writes to the container's syslog socket and no syslog daemon
runs in that image, so nothing consumes it either. And the store the alert now
lives in is not durable: deleting the Redis pod took it from four events to
zero, and ingest then stayed broken until the Web UI was restarted by hand
(§6.13 items 6 and 7).
**Detection without response is not mitigation, and routing is not response.**
That is why this item stays in residual risk instead of being closed, why
neither phase 6 nor phase 6b takes a row in §5, and why what the sensor and its
new plumbing introduce is written up separately in §6.13.

**6.5 The CVE gate is report-only.** Trivy runs with `exit-code: '0'`
([`.github/workflows/supply-chain.yml`](../.github/workflows/supply-chain.yml)),
so `CRITICAL`/`HIGH` findings never fail the build. The SARIF is uploaded with
`actions/upload-artifact`, not `github/codeql-action/upload-sarif`, so the
findings are retrievable only by downloading a build artifact: GitHub code
scanning has never ingested them (`GET /code-scanning/alerts` → HTTP 404
`no analysis found`, checked 2026-07-25). This pipeline **produces a SARIF
artifact**; it does not report to the repository's Security tab. A
signature attests **provenance, not the absence of vulnerabilities**: a signed,
admitted image may carry a critical CVE and this lab will run it. Making the
gate blocking is a one-line change; it is left report-only so the pipeline
always produces a signed artifact for the demo to consume.

**6.6 The SBOM is attested for future builds only, and nothing verifies it at
admission.** Syft produces an SPDX-JSON SBOM and the workflow uploads it as a
**CI artifact**. Since 2026-07-29 the `sign` job also runs `cosign attest
--type spdxjson --predicate sbom.spdx.json` against the build digest, so a
build from that date on binds its SBOM to its own immutable digest and
records the attestation in Rekor. The step **ran green once**, on
2026-07-29: run `30480411426`, a push to `main`, in which `cosign attest`
and the `cosign verify-attestation` self-check both concluded success. Its
transcript is committed as
[`cosign-verify-attestation.txt`](evidence/phase-4-supply-chain/cosign-verify-attestation.txt).
That is ONE run binding ONE build's SBOM to ONE digest, not a guarantee
about runs that have not happened. Three limits keep this on the
residual-risk list. The digest the cluster runs today
(`b8483c58...@sha256:7fd13d22...`) predates the step and stays
**unattested by design**, because the repo pins the digest it actually
verified. **The attestation's integrity extends trust to the build job that
produced the SBOM:** `build-scan` generates `sbom.spdx.json` and `sign`
attests it verbatim, so a compromised build job yields a forged-but-signed
predicate — the digest is content-addressed and cannot be swapped, but the
predicate is free-form JSON, and cosign **binds** it rather than **vouching**
for it. And **no admission policy requires or verifies an attestation** — the
`ImageValidatingPolicy` checks signatures only. The SBOM is documentation of
that build, not a control — it still proves **nothing at admission time**. A
Kyverno attestation check is a deliberate follow-up, deferred until an
attested digest is actually deployed.

**6.7 Policies are namespace-scoped, not cluster-wide.** All four
`ValidatingPolicy` resources and the `ImageValidatingPolicy` select only
`demo` and `demo-kyverno-only`; PSA `enforce: restricted` is set only on `demo`
(`demo-kyverno-only` is `warn` only, on purpose, so Kyverno denials stay
observable behind PSA's short-circuit). **Why:** Kyverno's webhook is
fail-closed (`failurePolicy: Fail`); a cluster-wide policy that also matched
`kube-system` or the `kyverno` namespace itself could wedge the cluster if the
webhook ever misbehaved. **Consequence:** workloads in any other namespace,
including `default` and `kube-system`, are constrained by neither PSA nor
Kyverno here. Production would invert this — match cluster-wide and carve out
explicit system-namespace exclusions. Three namespaces now make that concrete
rather than hypothetical: `cis-benchmark` (§6.12); `falco`, since 2026-07-29,
which is labelled `pod-security.kubernetes.io/enforce: privileged` and holds
the most privileged workload on this cluster (§6.13); and `argocd`, since
2026-08-07, which carries **no** `pod-security.kubernetes.io/*` label of any
kind, so it falls to the built-in `privileged` default — the apiserver has no
`--admission-control-config-file` to move that — and is likewise outside the
`[demo, demo-kyverno-only]` selector all five Kyverno policies use (§6.14). The
third is a difference in kind rather than degree: the components in the first
two namespaces are a scanner and a sensor, and the one in the third is a
controller whose job is to write, holding `verbs ['*']` on `resources ['*']` to
do it with. Phase 5b does not
bear on this item, and it is worth saying so rather than letting a reader infer
otherwise: `seccompDefault` and `podPidsLimit` are set on every node rather than
in one namespace, but they are kubelet settings and not policies — no namespace
selector changed, no scanner-shaped exception was built, and kube-bench still
runs in `cis-benchmark` outside both layers.

**6.8 kind is not production.** One host, one kernel, one etcd, a single
non-HA control plane, and no real multi-tenancy. Nothing here says anything
about behaviour under node failure, control-plane partition, or a hostile
co-tenant — the 2026-07-30 rebuild was a deliberate teardown, not a failure,
and it tests recovery from git rather than resilience. `NodeRestriction` is
enabled and authorization is `Node,RBAC` (verified), and `Node,RBAC` is
kubeadm's default rather than a hardening decision this lab made.
`NodeRestriction` is now written by name in
[`clusters/kind-config.yaml`](../clusters/kind-config.yaml), but it is restated
there only to keep kubeadm's default alive while `AlwaysPullImages` is added
beside it (§6.12) — the lab owns the line without having chosen the plugin.
What the lab did choose in that file, on 2026-07-30, is `AlwaysPullImages`,
`--profiling=false`, `--kubelet-certificate-authority` and three kubelet
fields. That is a small set of real hardening decisions in a file that
previously made none; it does not make kind production.

**6.9 As of 2026-07-25 the two-job CI split has run five times, all on one day;
the build is not reproducible.** Run `30174855073` (2026-07-25) was the **first
ever** execution
of the `build-scan` / `sign` split; four more followed the same day —
`30179122521`, `30179345902`, `30179460564`, `30179497251` — and all five are
green, `build-scan` and `sign` both succeeding in every one. On the first of
them the `Verify signature (self-check vs the identity Kyverno pins)` step
validated that run's digest
`sha256:7fd13d22d934f4202edc164e525436e190498590b62c41e348b1a4092eb3337b`
against certificate-identity
`https://github.com/joesevv/k8s-security-lab/.github/workflows/supply-chain.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`, confirming the
transparency-log entry offline and the code-signing certificate against the
trusted CA certificates — transcript in
[`cosign-verify.txt`](evidence/phase-4-supply-chain/cosign-verify.txt). The
`id-token` isolation in §3.2 is therefore **runnable**: the split builds, scans,
signs and verifies with `build-scan` holding no `id-token`, which establishes
that the permission is not needed there. **What that does not buy.** It does not
make the isolation an observed *control*, and five runs buy no more of that than
one did. Nothing in any of them tried to mint an OIDC token from `build-scan`
and was refused, so "a compromised third-party action cannot mint the identity
the cluster trusts" is still inferred from the `permissions:` block — exactly as
readable before the first run executed as after the fifth. Nor do five runs
establish durability. They span about two and a half hours of a single day, over
application source unchanged since the pipeline was written, and three of them
are the merges of PRs #1–#3 (§6.11), which touched nothing but the workflow
file. That is repeatable evidence the shape works, not evidence that it keeps
working. The build is **not byte-reproducible**: an unchanged application
produces a different digest on every build — `sha256:b4cb133e…` before the
split, then a distinct digest on each of the five runs, ending
`sha256:551f01a6…` on `30179497251` — which is expected from layer-metadata
timestamps but means the digest the cluster pins cannot be independently
re-derived from source; the signature is the only link back to the pipeline.
And the `sign` job still carries `contents: read` although it runs no checkout;
all five runs had that scope present, so whether it is genuinely removable is
untested.

**6.10 The signing identity's trust root is push access to `main`, and the guard
on `main` is one-person-satisfiable.** The pinned subject makes exactly one
workflow file on exactly one ref able to produce an admissible signature — which
is the point — but it also means the real boundary is branch permission on
`main`. That is now checkable on a public repository, and it was checked on
2026-07-25. Classic branch protection is absent
(`GET /repos/joesevv/k8s-security-lab/branches/main/protection` → HTTP 404
`Branch not protected`), but the classic endpoint does not report rulesets and
one exists: ruleset `protect-main` (id 19744535, `enforcement: active`,
`conditions.ref_name.include: ["~DEFAULT_BRANCH"]`, `bypass_actors: []`,
`current_user_can_bypass: "never"`) with three rules — `non_fast_forward`,
`deletion` and `pull_request`. Force-push and branch deletion are blocked, and
per that configuration every change to `main`, the sole admin's included, must
arrive via a pull request. **The residual.** This was read from the ruleset API,
not demonstrated by a rejected push. And the rule set is thin where it matters:
`required_approving_review_count` is **0**, there is no `required_status_checks`
rule, and there is no `required_signatures` rule. One account can therefore open
a pull request and merge it seconds later with no second human and with
`build-scan` / `sign` red — and that merge mints a signature this cluster
admits. The gate stops an accidental force-push; it does not stop whoever holds
the one set of credentials. Requiring the `build-scan` and `sign` status checks
is the cheapest remaining hardening, and it is the one that would actually bind,
since a review requirement is hollow while `joesevv` is the only collaborator.

**6.11 The repository is public; the GitHub-native controls are partly on.**
Since 2026-07-25 the entire history is world-readable and permanently
mirrorable by anyone (asset 6 in §2). Checked the same day on
`GET /repos/joesevv/k8s-security-lab` → `security_and_analysis`: secret scanning
is `enabled`, secret-scanning push protection is `enabled`, Dependabot security
updates are `enabled`, and Dependabot alerts are on
(`GET /vulnerability-alerts` → HTTP 204); `GET /secret-scanning/alerts` returns
`[]`. **The pin-plus-track loop in `.github/dependabot.yml` has closed end to
end.** PRs #1–#3 (2026-07-25) each bumped a SHA-pinned action
(`docker/login-action` 3.7.0→4.5.1, `actions/upload-artifact` 4.6.2→7.0.1,
`actions/checkout` 4.4.0→7.0.1) and all three were merged the same day: the
tracking half detects a stale pin, proposes the exact replacement, and the
merge is what proves the replacement builds. Because each merge touched
`.github/workflows/supply-chain.yml`, which is a trigger path, each one rebuilt,
re-scanned, re-signed and re-verified green — runs `30179345902`, `30179460564`
and `30179497251` (§6.9). Dependabot rewrote **both halves** of every pin, the
40-char SHA and its trailing version comment
(`actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1`), which is
the part that keeps a pin auditable: an immutable SHA carrying a stale comment
is a pin no reviewer can read. The bumps also cleared what motivated them —
earlier runs carried a warning annotation naming exactly these three actions as
targeting Node.js 20 and being forced onto Node.js 24, and the annotations API
returns **zero** annotations for both jobs of run `30179497251`. **What that
does and does not settle.** It is one cycle, three actions, one workflow: the
mechanism is demonstrated, the design is not stress-tested. All three bumps
happened to be compatible, two of them across three major versions, so nothing
here shows what a breaking upstream change does to this pipeline. The
consolation is that the failure mode of a *breaking* bump is a red CI run rather
than a compromised signature — the signing identity is the workflow's OIDC
subject and does not depend on which action versions ran. What CI cannot catch
is a bump that is hostile rather than merely incompatible, and §6.10's gate lets
one account merge it unreviewed. **Still off, and each is a real gap.**
`secret_scanning_non_provider_patterns` and `secret_scanning_validity_checks`
are both `disabled`, so a credential in a custom or non-provider format is not
matched. Private vulnerability reporting is `{"enabled": false}` and there is no
`SECURITY.md` on `main` (HTTP 404), so a finder has no private disclosure
channel. `sha_pinning_required` is `false` with `allowed_actions: "all"`, so the
workflow's SHA pins are a convention this repo keeps, not a rule GitHub
enforces. And push protection guards only **future** pushes — nothing already
public can be retracted, the same retroactive property that makes asset 2
dangerous.

**6.12 The CIS benchmark surfaced real gaps; phase 5b closed the subset that is
one line of cluster configuration each, and the rest are still open.** On
2026-07-26 kube-bench v0.15.6, pinned to `--benchmark
cis-1.12`, scored the cluster 63 PASS / 12 FAIL / 56 WARN. Take none of those
three numbers at face value: 38 of the WARNs were never evaluated (27 are
`type: manual` checks with no audit command, 11 shell out to `kubectl` from a
Pod holding no ServiceAccount token), leaving 30 checks that actually ran and
did not pass, and 4.2.5 is a demonstrable false PASS — it compares `noteq 0`
against the string `0s`, and `0s` is what `/var/lib/kubelet/config.yaml` really
contains on every node. So the honest reading of the PASS column
is "checks kube-bench scored as passing", not "controls verified compliant".
Two separate facts live in that one check: the scoring is wrong, and what that
file value means for the running kubelet is a second question this section used
to answer with more confidence than the evidence supports — item 5 below.
Seven results restate gaps
already conceded here — audit logging (1.2.16–1.2.19, 3.2.1 → §6.2) and
encryption at rest (1.2.27, 1.2.28 → §6.1) — which is corroboration, not news.
Three more are artifacts of kind rather than findings (1.1.10, 4.1.3, 4.1.4:
kube-proxy runs from `--config` and the CNI paths the checks probe do not
exist, so the audit emits nothing and the check warns for an absence). 1.1.9
was first triaged into that same group and should not have been: its audit
reads the kubelet's `--cni-conf-dir` flag (kind's kubelets set none) and
`/var/lib/cni/networks` (which does not exist here), so it never looked at the
file kind actually writes. Reading that file directly turns an absence of data
into a real finding — item 7. The remainder were genuinely undocumented before
this scan.

**What changed on 2026-07-30.** Phase 5b wrote eight settings into
[`clusters/kind-config.yaml`](../clusters/kind-config.yaml) and rebuilt the
cluster from that file as a full DR drill
([evidence](evidence/phase-5b-cis-remediation/attack-output.txt),
[runbook](../runbooks/phase-5b-cis-remediation.md)). Seven of the eight checks
it targeted flipped to PASS; the eighth, 4.2.9, was predicted in writing not to
move and did not. The master target went from 46 PASS / 10 FAIL / 50 WARN / 0
INFO to **51 / 6 / 49 / 0** and each worker from 17 / 2 / 6 / 0 to
**19 / 2 / 4 / 0**, and with the seven intended checks masked out a status-line
diff of the before and after reports is empty on all three targets — nothing
else moved in either direction. Each item below carries its own status and the
date it was read. None of it was closed by the scan; the scan is only what
measured it.

The ones that matter, loudest first:

1. **The API server did not verify kubelet serving certificates. Since
   2026-07-30 it does.** `--kubelet-certificate-authority` was absent (1.2.5,
   FAIL, confirmed on the control-plane node) and each kubelet presented a
   serving certificate it had signed itself, under a per-node ad-hoc CA
   (`issuer=CN=seclab-worker-ca@1784637429` and two like it), so the
   apiserver → kubelet channel was encrypted but not authenticated in the
   direction that matters. That was the most serious thing the scan found, and
   it is the one phase 5b answered most completely: the flag is now
   `--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt` on the apiserver
   process line, 1.2.5 is PASS, and with `serverTLSBootstrap: true` every
   kubelet serves a certificate issued by the cluster CA `CN=kubernetes` with an
   `O=system:nodes` subject. The proof is behavioural rather than textual:
   between the rebuild and the CSR approvals `kubectl logs` failed on all three
   nodes with `remote error: tls: internal error`, and each node's logs started
   working the moment that node's kubelet-serving CSR was approved. **Two
   residuals.** The approvals are manual — nothing in this repo and nothing in
   the cluster approves a kubelet-serving CSR — so every rebuild has a window in
   which logs, exec and top are down cluster-wide, and the drill found four
   Pending CSRs on three nodes rather than the three it expected. And 4.2.9
   still WARNs, correctly: the check reads `tlsCertFile` / `tlsPrivateKeyFile`
   out of the kubelet config file, and `serverTLSBootstrap` removes those fields
   rather than writing them. The scanner number stood still while the trust root
   under it changed; neither reading on its own is the whole truth, which is why
   both are recorded here.
2. **Anonymous auth is on** (1.2.1) — observed, not inferred: unauthenticated
   `GET /version` and `GET /healthz` both return HTTP 200 and disclose exact
   `gitVersion`, `gitCommit` and `buildDate`, which is enough to match this
   cluster against public CVE lists. It is bounded — `GET /api/v1/secrets`
   returns 403, so RBAC still holds on real resources — and it is kubeadm's
   default, but it is free reconnaissance and this lab has not turned it off.
   **Unchanged by phase 5b**, and left alone on purpose: kubeadm's own bootstrap
   and kind's readiness probing lean on anonymous auth while the cluster comes
   up, so turning it off is a real risk to a rebuild rather than a one-line
   patch. The rebuilt apiserver's process line carries no `--anonymous-auth`
   flag (2026-07-30), so kubeadm's default still applies; the unauthenticated
   HTTP 200s themselves were observed on 2026-07-26 and were not re-run after
   the rebuild.
3. **`AlwaysPullImages` was not enabled** (1.2.11); since 2026-07-30 it is. The
   finding was a wrong-*value* one rather than a missing flag —
   `--enable-admission-plugins=NodeRestriction` was already there and simply did
   not list the plugin — and the value now reads
   `NodeRestriction,AlwaysPullImages`, with 1.2.11 PASS. What proves the plugin
   is live rather than merely named: a pod created with no `imagePullPolicy`
   field is now stored with `Always`, where the identical pod on the old cluster
   was defaulted to `IfNotPresent`. The gain is narrow and worth stating
   narrowly. It bears on phase 4 because a pod could previously run an image
   already cached on a node without a pull, so the registry allow-list and the
   signature gate assumed a pull that might not happen; that pull now happens.
   It does not widen what the signature gate checks, and it costs availability —
   a cluster with this plugin on can only start pods whose images a registry
   will actually serve, which is why the setting was gated on first pulling
   kind's four side-loaded system images (CNI, local-path provisioner,
   kube-proxy, CoreDNS) from a real registry, with a bogus tag pulled first as
   the negative control. Had any of the four failed, the entry would have been
   omitted entirely.
4. **`--service-account-extend-token-expiration` is not false** (1.2.30), so
   service-account tokens outlive the bound lifetime their manifests imply —
   directly relevant to §3.3 and to A1, whose whole premise is a borrowed
   token. **Unchanged by phase 5b:** still FAIL on the 2026-07-30 run, and
   outside that phase's scope by decision rather than by oversight.
5. **Three kubelet settings left a protection off; two of them are now on.**
   `seccompDefault` and `podPidsLimit` were unset (4.2.14, 4.2.13) — the first
   is §6.3's gap, the second left per-pod PID-exhaustion denial of service
   unbounded. Both are set on every node since 2026-07-30 (`seccompDefault:
   true`, `podPidsLimit: 4096`) and both checks are PASS on both workers. Where
   the PID limit binds is worth recording, because the obvious probe reads the
   wrong number: 4096 is on the **pod cgroup slice**, while each container scope
   inside that slice still reads 18999 — systemd's `DefaultTasksMax` in the kind
   node image, not a kubelet value at all. cgroup v2 enforces the limit
   hierarchically, so the pod as a whole is capped at 4096; it was the
   disagreement between a passing check and a failing in-container probe that
   found this. **The third is unchanged, and its consequence is now stated with
   less confidence than before, because two readings of it disagree.**
   `/var/lib/kubelet/config.yaml` contains `streamingConnectionIdleTimeout: 0s`
   on all three nodes (4.2.5, read 2026-07-29 and read again on the cluster
   rebuilt 2026-07-30). The kubelet's own `/configz` reports the effective value
   as `4h0m0s` on all three nodes, on the old cluster and on the new one, and
   the kubelet is not started with a `--streaming-connection-idle-timeout` flag
   that would explain the difference. Both readings are recorded; neither is
   discarded. What is **no longer claimed** is the consequence this item used to
   assert — that an idle `exec`, `attach` or `port-forward` stream is never
   reaped. The file value says that, `/configz` contradicts it, and no
   experiment was run on a live stream to settle which governs. (That a
   zero-duration value is defaulted away by the kubelet is a plausible reading
   and is **unverified inference**, not a finding.) The false PASS is a separate
   fact and stands unchanged: kube-bench compares `noteq 0` against the string
   `0s`, which is a scoring defect whatever the kubelet does with the value.
6. **Profiling endpoints were exposed** on the API server (1.2.15), controller
   manager (1.3.2) and scheduler (1.4.1). The latter two were mitigated by
   `--bind-address=127.0.0.1`; the API server's was not. **Closed 2026-07-30:**
   `--profiling=false` is on all three process lines and all three checks are
   PASS. One limit on that claim, since it is the easiest place here to say more
   than was done — the flags were read off the process lines and scored by
   kube-bench, and **no request was made to a profiling endpoint before or
   after**. This is a configuration change verified as configuration, not an
   endpoint observed to have gone away.
7. **Lower severity, recorded for completeness, and none of it remediated:** no
   `EventRateLimit` admission
   plugin (1.2.9); the kubelet service file and `config.yaml` are mode 644 where
   CIS asks for 600 (4.1.1, 4.1.9 — still FAIL on both workers on 2026-07-30),
   and `/etc/cni/net.d/10-kindnet.conflist` is
   mode 644 on all three nodes for the identical reason (1.1.9, read directly
   off the nodes 2026-07-29 — owner `root:root`, which is what 1.1.10 asks for,
   and the directory above it is mode 700 `root:root`, so only root on the node
   reaches the file today); the etcd data directory is `root:root` rather than
   `etcd:etcd` (1.1.12 — still FAIL on 2026-07-30; mode 700 passes, so the
   intent is met, and kubeadm runs
   etcd as a root static pod); `DenyServiceExternalIPs` is off (1.2.3); and
   `--request-timeout`, both cipher-suite checks and
   `--terminated-pod-gc-threshold` sit at defaults (1.2.20, 1.2.29, 4.2.12,
   1.3.1). Every one of these checks reported the same status before and after
   the rebuild. The 1.1.9 file-mode reading is from the pre-rebuild cluster and
   was not repeated afterwards, and the defect behind it is unchanged: that
   check's audit never reads the file kind actually writes.

**Consequence, stated plainly:** items 2, 4 and 7 are still true of the running
cluster; items 1, 3, 5 and 6 are now wholly or partly closed, by a
configuration change committed to `clusters/kind-config.yaml` and applied by
rebuilding the cluster from it on 2026-07-30 — not by anything the benchmark
did. This section is therefore a changelog and a list of open gaps at the same
time, and the open half is the larger one: **6 FAIL and 49 WARN remain on the
master target and 2 FAIL / 4 WARN on each worker as of 2026-07-30**. Item 2,
anonymous auth, is now the first thing to fix on a cluster that mattered, with
audit logging (§6.2) the gap that would hurt most during an incident. Nothing
here was granted an exception to move a number: no scanner-shaped exception was
built, and kube-bench still runs in `cis-benchmark` outside both enforcement
layers (§6.7). Every count and status in this section is the 2026-07-30
reading, so a later scan or a later rebuild makes them incomplete rather than
false.
**Two scope caveats, one of them now closed.** The node scan of 2026-07-26
produced a single Pod, which ran on `seclab-worker`; `seclab-worker2` was not
scanned by kube-bench at all, so the node-level findings rested on the scanner
having seen one of two workers. **Closed 2026-07-29:** the `node` target was
re-run as a DaemonSet
(`docs/evidence/phase-5-cis/daemonset-kube-bench-node.yaml`), which schedules
one Pod per eligible node. Both workers were scanned, and both returned 17 PASS
/ 2 FAIL / 6 WARN / 0 INFO — reports that are byte-identical to the 2026-07-26
Job's once glog timestamps are stripped (evidence §8) — those are the
pre-remediation figures, and the same DaemonSet returns 19 / 2 / 4 / 0 on both
workers after the 2026-07-30 rebuild. That closed a
**coverage** gap and nothing else: no item above was remediated by it, and a
DaemonSet of scanners enforces nothing. The second caveat stands, amended:
4.2.5 and 1.1.9, which items 5 and 7 record from a **direct read** of all three
nodes rather than from the scan, are still direct reads. The DaemonSet run
reproduced 4.2.5's false PASS on both workers without re-testing the value
behind it, and it says nothing at all about 1.1.9, which is a `master`-target
check. 4.2.5's direct read was repeated on the cluster rebuilt 2026-07-30 and
reproduced exactly — the file's `0s` and `/configz`'s `4h0m0s`, on all three
nodes — while 1.1.9's was not repeated at all. And per §6.8, a kind cluster
passes and fails a great many CIS checks
because of what kubeadm chose, not because of a hardening decision this lab
made — the scan measures the substrate at least as much as it measures the lab,
and the eight settings phase 5b added are a narrow exception to that rather
than a rebuttal of it.

**6.13 The runtime sensor is itself privileged, ungated and unwatched — and so
is the alert pipeline now bolted to it.** §6.4 records what phases 6 and 6b
bought and what they do not do with it; this item records what the sensor and
its pipeline *cost*, because installing Falco added the largest new attack
surface this lab has taken on and phase 6b put five more pods behind the same
exemption on 2026-08-03. Seven things, none of them remediated.

1. **It runs `privileged: true`.** That is the chart's default for
   `driver.kind=modern_ebpf` (`driver.modernEbpf.leastPrivileged` defaults to
   `false`) and this install did not reduce it. The probe needs roughly
   `CAP_BPF`, `CAP_PERFMON`, `CAP_SYS_RESOURCE` and `CAP_SYS_PTRACE`; it was
   given everything instead. It also host-mounts `/proc`, `/sys/kernel`,
   `/boot`, `/lib/modules`, `/usr`, `/etc` and six container-runtime socket
   paths — at least one of which really is connected, since the alerts resolve
   container and pod names through it. A compromise of this pod would in
   practice be a compromise of the node. That was not demonstrated here and
   does not need to be to be worth writing down. One thing is narrower than the
   obvious assumption: `hostPID`, `hostNetwork` and `hostIPC` are **not** set,
   and that costs visibility — the startup log records `libpman: disabled BPF
   iterators (not running in the root PID namespace)`, so no claim of full host
   process-tree visibility is made.
2. **Nothing on this cluster gates it.** Namespace `falco` is labelled
   `pod-security.kubernetes.io/enforce: privileged` and sits outside the
   `[demo, demo-kyverno-only]` namespace selector every Kyverno policy uses, so
   neither PSA nor admission control evaluates anything in it — the second
   concrete instance of §6.7 after `cis-benchmark`. The exemption is at least
   written out in
   [`evidence/phase-6-falco/00-namespace-falco.yaml`](evidence/phase-6-falco/00-namespace-falco.yaml)
   rather than inherited silently, and the same spec submitted to `demo` is
   refused — by PSA as a Pod, by Kyverno as a DaemonSet. Documentation is not
   enforcement, and a refusal elsewhere is not a control here.
   **Phase 6b enlarged this hole rather than leaving it alone.** Since
   2026-08-03 the same ungated namespace also holds five falcosidekick, Web UI
   and Redis pods from three more images, two of them network services rather
   than a read-only agent, and nothing on this cluster evaluated any of them —
   which also means nothing compelled the manifest-list digest pins those
   images carry; that discipline is self-imposed and self-verified. The
   apiserver priced it for free during the upgrade: the namespace still carries
   `warn: restricted`, so it emitted **four PSA `restricted` warnings**, three
   of them about the new workloads, and as rendered none of those pods would be
   admitted by `restricted`. They fail on four categories —
   `allowPrivilegeEscalation`, capabilities, `runAsNonRoot`,
   `seccompProfile` — not the sensor's six: none is privileged, none
   host-mounts anything, none asks for a host namespace, and the chart exposes
   every field they are missing. **"Could be gated and is not" is the honest
   sentence**, and closing it was deliberately kept out of a routing-only
   upgrade so that one change could be attributed to one cause.
3. **The sensor's own supply chain is unverified in the sense phase 4 means.**
   All four OCI artifacts are pinned by digest — the Falco and falcoctl images
   plus the ruleset and container-plugin artifacts — and falcoctl **reported**
   `Signature successfully verified!` for the two `ghcr.io/falcosecurity/*`
   artifacts at pull time. That is falcoctl's own claim about its own pull, not
   an independent check: nobody re-derived it, and there is no cosign binary on
   this host to re-derive it with, so it is taken on trust. What *is*
   independently true of those two artifacts is the digest pin. The two images
   come from Docker Hub, are outside the `ImageValidatingPolicy`'s glob, and had
   no signature checked at all; the pins prove the bytes are stable, not that
   they are trustworthy. The first install also
   left the container-metadata plugin on a floating tag
   (`plugin/container:0.7.1`), because it is a chart value rather than a
   falcoctl ref. It was found and pinned, and the miss is recorded in
   [`../clusters/falco-install.md`](../clusters/falco-install.md) rather than
   tidied away.
   **Phase 6b widened this too.** falcosidekick 2.32.0, falcosidekick-ui 2.2.0
   and `redis/redis-stack` 7.2.0-v11 are each pinned by manifest-list digest
   across four chart value paths, and not one was signature-verified: they are
   Docker Hub images, outside the `ImageValidatingPolicy`'s glob, with no
   falcoctl init container to check them and still no cosign binary on this
   host. Seven digest-pinned artifacts now run in `falco` — two carrying a
   verification claim made by the component that pulled them, five carrying
   none. An eighth is dormant rather than absent: the falcosidekick subchart
   ships a `helm.sh/hook: test-success` Pod running `appropriate/curl` with no
   registry, no tag and no digest. `helm upgrade` never creates it and it is not
   on the cluster, but `helm test falco` would pull `:latest`, so that command
   must not be run while this repo's thesis is immutability.
4. **The false-negative rate is unknown and was not measured.** Two behaviours
   were fired and each produced an alert; that says nothing about what would
   slip past. One counter-example is already on record: the textbook
   `cat /etc/shadow` demo produces **no alert** against this lab's non-root
   workload, because the open fails `EACCES` and the stock rule matches
   successful opens only — the lab's own hardening defeats the demo and the
   rule stays silent on the blocked attempt. The ruleset is the stock
   `falco-rules` artifact, frozen at a digest with the update sidecar
   disabled. That is deliberate, so the committed evidence describes what is
   really running, but it also means the detections never improve on their own.
   No custom rule was written against this lab's own threat model.
5. **A detection here is counted three times.** All three kind nodes are
   containers on one shared WSL2 kernel (§6.3, §6.8), so a single syscall
   event is reported by all three Falco pods within microseconds of one
   another, and only the pod co-located with the target's containerd resolves
   `k8s_pod_name`, `container_name` and the image; the other two print `<NA>`.
   Any figure drawn from these logs must be divided by three, and on a real
   cluster with three kernels the enrichment behaviour would be different.
6. **Retention exists now, and it is fragile.** This item read "nothing retains
   the alerts" until 2026-08-03, and phase 6b is what changed it — which is a
   different claim from "solved". What is now true: an alert survives the death
   of every sensor that saw it. All three Falco pods were deleted and the marked
   event was still retrievable from the Web UI's Redis under the same UUID,
   while `grep -c` on all three replacement pods' logs returned 0. What is still
   not true: the store keeps nothing across its own restart. `appendonly` is
   `no`, the RDB configuration is redis-stack's default `save 3600 1 300 100 60
   10000`, `/data` held no `dump.rdb`, and deleting the Redis pod took `DBSIZE`
   from 4 to 0 with the 1Gi PVC still Bound to the same volume — reattached
   empty, because nothing had ever been written to it. The only one of those
   thresholds this lab's alert volume can reach is `3600 1`, which comes due
   3600 s after a change, so a snapshot trails the writes it protects by up to
   an hour; this store had been alive about six minutes and had taken none.
   That is a window, not a permanent condition, and the distinction is
   corrected in the evidence file's own corrections section.
   **The record this item was written for stands.** Each pod's log held three
   alert lines from the 2026-07-29 attack window — the two documented in §6.4
   plus an earlier, unrecorded shell-spawn rehearsal at `15:12:42.954798594` —
   and every one of them survived exactly as long as a container log does,
   which the 2026-07-30 rebuild then demonstrated instead of arguing: `kind
   delete` destroyed the Falco pods and the logs that were the alerts' only
   home. On the reinstalled sensor, the co-located pod's log was enumerated
   whole and holds exactly two lines, both of them the DR drill's own re-run.
   The 2026-07-29 lines went with the containers that wrote them, and by that
   term there was nowhere else for them to be. The 6b upgrade did it once more
   on the way past: the four alerts that existed immediately before it were
   enumerated whole, and afterwards the three replacement pods each counted
   zero. Neither loss is prevented by what runs today — a `kind delete` takes
   the PVC's backing directory inside the `seclab-worker2` node container with
   it, which is reasoned from the local-path volume's path and node affinity
   rather than demonstrated, and a restart of one Redis pod is already enough.
7. **The alert pipeline fails silently, and nothing watches it.** The data loss
   in item 6 was not the worst of that test. After the Redis pod was deleted,
   ingest did not resume: falcosidekick's POSTs were rejected and it logged
   `exceeding post rate limit (500)`, which names the wrong cause. The real one
   is in the Web UI's own log — `Unknown index name`. The `eventIndex`
   RediSearch index the UI queries is created once, at UI startup ("Index does
   not exist / Create Index"), so the restart took the index with the data and
   the UI never rebuilt it; every subsequent alert was detected by all three
   sensors, POSTed, and dropped. **Nothing self-healed and nothing raised the
   alarm.** Recovery took a manual
   `kubectl rollout restart deployment/falco-falcosidekick-ui`, and the only
   thing that noticed the outage was a human running `grep` on purpose. The
   single point of failure is unguarded in the other direction too: one Redis
   pod holds the whole history, its RWO PVC pins it to `seclab-worker2` so it
   can schedule nowhere else, and it runs with **no password and no
   NetworkPolicy** — anything that can reach its Service on 6379 can read the
   alert history or delete it, which this phase demonstrated is a one-command
   operation by doing it accidentally. There is no monitoring of the
   monitoring.

**Consequence, stated plainly:** this cluster can now see a category of attack
it previously could not, and can now file what it saw somewhere that outlives
the sensor — and it can still do nothing about it, while carrying a privileged,
ungated component plus five ungated pods of plumbing to get that far. This
paragraph used to say that wiring an alert router and a response action, even
one that merely annotates the offending pod, is what would turn this into a
control. Half of that is now done, and only half: the router exists and is
proved (§6.4), the response action does not exist at all,
`responseActions.enabled` is still `false`, and nothing is configured to tell
a person that any of it happened. A record that outlives its sensor is a better
record; it is not a control. Until something acts on an alert, §6.4 stays open
and no §5 row is earned — not by phase 6 and not by phase 6b.

**6.14 The reconciliation layer arrives after the fact, and its price is
cluster-admin in an ungated namespace.** Phase 7 (2026-08-07) added ArgoCD
v3.5.0 in namespace `argocd`, running one `Application`, `demo-workloads`,
which syncs this repo's `workloads/` path — 7 objects — into `demo` at
`targetRevision: main` with `prune: false`. What it buys is real, and it is the
first thing in this lab that acts on an attack rather than measuring, watching
or filing one; this item records what that cost and what it does not reach.
Five things, none of them remediated.

1. **It corrects; it does not prevent, and the window never closes.** ArgoCD is
   not an admission plugin and is not in the request path, so every correction
   happens after the API server accepted the change and after the kubelet
   started the resulting pod. The drift used to demonstrate it — removing
   `readOnlyRootFilesystem: true` from the live `demo/nginx` Deployment, with
   the file in git left untouched — was **admitted**: every rollout event
   `Normal`, no PSA denial and no Kyverno denial, because `restricted` does not
   require that field and none of the five Kyverno policies checks it. The
   weakening was then confirmed at the kernel rather than off the spec, the
   container's root mount going `overlay / overlay ro` → `rw` and a write into
   `/var/cache/nginx` going from `Read-only file system` (exit code: 1) to
   (exit code: 0). With `selfHeal: false` the Application reported
   `OutOfSync / Healthy` and named `Deployment/nginx` correctly, and then did
   nothing: the drift stood **10 min 8 s (608 s)** across 17 consecutive
   samples and ended only because a human flipped a flag. With `selfHeal: true`
   the standing drift was reverted by the controller itself —
   `initiatedBy: {"automated":true}`, quicker than the 2 s poll could resolve,
   so **no latency figure is claimed for that revert** — and the same drift
   re-run was reverted in **1.29 s**, an upper bound at 1 s poll resolution and
   not an instrumented latency. A pod from the drifted ReplicaSet was still
   created, its image pulled, its container started (18:17:41Z) and killed
   (18:17:42Z): a container with a writable root filesystem really ran, for
   roughly **1 s**, bounded at about 0–2 s by the 1 s event resolution. 608 s
   down to about one second is a smaller window, not a closed one, and
   admission control — the layer that does not look at this field — is the only
   one that could make it zero.
2. **ArgoCD granted itself cluster-admin.** The `argocd-application-controller`
   ClusterRole is `apiGroups ['*'] resources ['*'] verbs ['*']` plus
   `nonResourceURLs ['*'] verbs ['*']`, and that was not summarised but diffed
   against the built-in `cluster-admin` ClusterRole: the two rule sets are
   **byte-identical** (exit code: 0 — no difference). The ServiceAccount bound
   to it can therefore read every Secret in every namespace, including the
   sealing private key that asset 2 in §2 rests on and every ServiceAccount
   token on the cluster. `argocd-server` — the component behind the web UI —
   separately holds `delete`, `get` and `patch` on every resource of every kind
   cluster-wide, and whoever holds the initial admin password holds that. This
   phase never retrieved that password and never opened the UI, but that is a
   choice made here rather than a limit the install imposes. An Application on
   this cluster is scoped by **convention** — its `source.path` — never by
   capability.
3. **Nothing on this cluster gates it.** Namespace `argocd` carries no
   `pod-security.kubernetes.io/*` label at all, so it gets the built-in
   `privileged` default and the apiserver has no
   `--admission-control-config-file` to change that; and it sits outside the
   `[demo, demo-kyverno-only]` namespace selector all five Kyverno policies
   use. ArgoCD's 7 pods were admitted with no Pod Security check and no Kyverno
   check, which makes `argocd` the third concrete instance of §6.7 after
   `cis-benchmark` and `falco`. Two consequences follow rather than one. Any
   pinning applied to ArgoCD here is self-imposed and unenforced — and it is
   thinner than elsewhere in this repo, because the upstream manifest pins its
   own images by **tag**, so the three digests recorded in the transcript are
   what those tags meant on 2026-08-07 and not a control this repo enforces.
   And the pattern is now a habit worth naming: every operational component
   this lab has installed — a scanner, a sensor, an alert pipeline, and now a
   controller that can write to anything — has been installed outside the
   controls the lab exists to demonstrate.
4. **Nothing verifies the content it syncs.** There are no `signatureKeys` on
   the AppProject and no keys in `argocd-gpg-keys-cm`, so commit signature
   verification is not configured and any commit that reaches `main` is applied
   faithfully, signed or not. The `default` AppProject — the object whose job
   is to constrain what Applications may do — constrains nothing:
   `sourceRepos: ["*"]`, `destinations: [{namespace:"*",server:"*"}]`,
   `clusterResourceWhitelist: [{group:"*",kind:"*"}]`. Every bit of scoping in
   this phase comes from one Application's `source.path` field, so a second
   Application, or an edit to this one, could target any namespace and any
   cluster-scoped kind without tripping a guard. **`selfHeal: true` makes this
   strictly worse rather than better:** a malicious or mistaken commit is not
   applied once, it is re-applied automatically every time an operator removes
   it by hand.
5. **It only covers `workloads/`.** The Application manages exactly 7 objects —
   Namespace `demo`, the `nginx-sa` and `signed-app-sa` ServiceAccounts, the
   `nginx` and `signed-app` Deployments and their two Services. The rest of
   `demo` is outside it: the `developer` Role and RoleBinding, the four
   NetworkPolicies and the SealedSecret have **no drift control of any kind**.
   That was measured rather than assumed — with `selfHeal` on, a label injected
   onto the `developer` Role survived **4 min 57 s (297 s)** across 15
   consecutive samples, spanning more than one 180 s reconcile cycle, while the
   Application never left `Synced` and the in-scope field stayed correct
   throughout, which is what proves the controller was alive rather than stuck.
   A human removed the label, because ArgoCD was never going to. A green
   Application says nothing about anything outside its `source.path` — and what
   sits there is exactly what phases 2a, 2c and 3 built.

**Consequence, stated plainly:** this cluster can now put back a change it had
no way to refuse, in about a second instead of ten minutes, for 7 objects in
one namespace — and it bought that with a cluster-admin-equivalent controller
in a namespace nothing evaluates, syncing from a branch whose commits nothing
verifies. Correction is a genuinely stronger answer than detection: phases 6
and 6b end with an alert and an attacker who keeps what they took, and this
phase ends with the state restored and the restoration timed. It is still not
prevention, and the distance is measurable — 608 seconds, or about one, but
never zero. What would close the remainder is not more GitOps: it is an
admission policy requiring the field this drift removed, a one-policy change
this lab has not made, together with a ClusterRole narrower than the one the
upstream manifest ships.

---

## Related documents

- [`architecture.md`](architecture.md) — diagrams of the admission path and the
  two artifact paths into the cluster.
- Runbooks, one per phase: [`../runbooks/`](../runbooks/).
- Captured attack transcripts: [`evidence/`](evidence/).
