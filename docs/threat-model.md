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

Phase 6 has deliberately **no row here either**, for a different reason.
Falco does engage with runtime techniques — it matches the syscalls and names
what it saw — but the only artifact it produces is a line on a pod's stdout
that nothing routes, stores or acts on (§6.4). A (P) marking is the easiest
overclaim available in this document: (P) is defined above as "raises cost or
covers one variant", and an alert nobody reads does neither. An attacker who
spawned the shell in `demo` on 2026-07-29 kept the shell. ATT&CK keeps
detections separate from mitigations for exactly this reason, and this table
has no detection column; adding one would mean re-deriving every row above
against a standard they were not written to. What the sensor saw, what it did
not see, and what nothing does about either are in §6.4 and §6.13.

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
`--audit-log-path` on the API server.
[`clusters/kind-config.yaml`](../clusters/kind-config.yaml) is bare by design —
no `kubeadmConfigPatches`, no `extraMounts`. **Why:** wiring audit into kind
means patching kubeadm and host-mounting a policy file and a log path into the
control-plane node, which is cluster-lifecycle plumbing rather than a security
control, and it would dominate the phase-1 runbook. **Consequence, stated
plainly:** there is no record of *who did what* to this cluster. Every denial in
this document is a preventive control; none of them is detective. Phase 5's
kube-bench run (§6.12) does not change that: a point-in-time configuration scan
is neither preventive nor detective — it observes posture once, on request, and
would not notice an action taken against this cluster a second later. Phase 6's
Falco (§6.4, §6.13) changes that only in part, and not in the direction this
item is about: it is genuinely detective, but it watches syscalls on the nodes,
not requests at the API server, so it still records nothing about *who called
what*. Deleting a NetworkPolicy or reading a Secret through the API leaves no
trace on this cluster either way, and Falco's own output is a container's
stdout — not queryable, not retained, not an audit trail.

**6.3 No node or kernel hardening.** No AppArmor or SELinux profile beyond
`seccompProfile: RuntimeDefault`, no gVisor or Kata, and no CIS remediation: as
of 2026-07-26 kube-bench does now report against CIS (§6.12), but a benchmark
measures a gap and does not close it, and not one finding it raised has been
remediated. Two of its results land directly on this item and were not
documented before the scan: the kubelets set no `seccompDefault` (4.2.14), so
`RuntimeDefault` is applied only where a PSA `restricted` label puts it — that
is `demo` alone, per §6.7 — and no `podPidsLimit` is set (4.2.13). All three
nodes are containers on one shared WSL2 kernel. **Consequence:** a kernel-level
escape that gets past PSA lands on the host directly — there is no second wall.
Since 2026-07-29 a kernel-level eBPF probe watches that same shared kernel
(§6.4), so such an escape would stand a chance of being *seen*. It is still not
a second wall: seeing is not stopping, nothing reads the alert, and the probe
itself is a privileged component on the kernel it watches (§6.13).

**6.4 Runtime behaviour is now observed, and nothing responds to what is
observed.** Every *control* in this document still fires at admission time or at
connection time. A workload that is admitted and *then* misbehaves — a shell
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
image and uid 101 resolved on the alert. Message text and priority are what an
alert line carries here; `json_output` is off, so the stock rule names behind
them are an identification against the shipped ruleset and not a captured
field. **Both attacks succeeded.**
The shell returned exit 0; the staged binary ran (`evt_res=SUCCESS`); afterwards
the pod was still Running with its restart count unchanged and the payload
still sitting in `/dev/shm` until it was cleaned up by hand. **What happens to
a Falco alert on this cluster is: nothing.** It is written to the falco
container's stdout and no further — `file_output`, `http_output`,
`program_output` and `json_output` are all disabled, `responseActions.enabled`
is `false`, and no falcosidekick, Talon, log shipper or alert router is
installed anywhere on the cluster — so the alert lives in a container log
until rotation or pod restart and is read only by someone who already went
looking for it. One channel is nominally on and is worth naming rather than
omitting: `syslog_output` is `true`, but it writes to the container's syslog
socket and no syslog daemon runs in that image, so nothing consumes it either.
There is no routing, no persistence, no on-call and no automated response.
**Detection without response is not mitigation.** That is why this
item stays in residual risk instead of being closed, why phase 6 takes no row
in §5, and why what the sensor itself introduces is written up separately in
§6.13.

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
--type spdxjson --predicate sbom.spdx.json` against the build digest (commit
pending merge), so every FUTURE build binds its SBOM to its own immutable
digest and records the attestation in Rekor. Four limits keep this on the
residual-risk list. The step has **never run** — the workflow fires only on
`push` to `main`, so this records a static change to the YAML, not observed
behaviour; the first green run on main owes a `cosign verify-attestation`
transcript to `docs/evidence/phase-4-supply-chain/`. The digest the cluster
runs today (`b8483c58...@sha256:7fd13d22...`) predates the step and stays
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
explicit system-namespace exclusions. Two namespaces now make that concrete
rather than hypothetical: `cis-benchmark` (§6.12) and, since 2026-07-29,
`falco`, which is labelled `pod-security.kubernetes.io/enforce: privileged` and
holds the most privileged workload on this cluster (§6.13).

**6.8 kind is not production.** One host, one kernel, one etcd, a single
non-HA control plane, and no real multi-tenancy. Nothing here says anything
about behaviour under node failure, control-plane partition, or a hostile
co-tenant. `NodeRestriction` is enabled and authorization is `Node,RBAC`
(verified), but that is kubeadm's default, not a hardening decision this lab
made.

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

**6.12 The CIS benchmark surfaced real gaps, and recording them is all this lab
did about them.** On 2026-07-26 kube-bench v0.15.6, pinned to `--benchmark
cis-1.12`, scored the cluster 63 PASS / 12 FAIL / 56 WARN. Take none of those
three numbers at face value: 38 of the WARNs were never evaluated (27 are
`type: manual` checks with no audit command, 11 shell out to `kubectl` from a
Pod holding no ServiceAccount token), leaving 30 checks that actually ran and
did not pass, and 4.2.5 is a demonstrable false PASS — it compares `noteq 0`
against the string `0s` while every node really does set
`streamingConnectionIdleTimeout: 0s`. So the honest reading of the PASS column
is "checks kube-bench scored as passing", not "controls verified compliant".
Two separate facts live in that one check: the scoring is wrong, and the value
it mis-scores is itself an open gap — item 5 below. Seven results restate gaps
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
this scan. The ones that matter, loudest first:

1. **The API server does not verify kubelet serving certificates.**
   `--kubelet-certificate-authority` is absent (1.2.5, FAIL, confirmed on the
   control-plane node) and the kubelets present self-signed serving certs
   (4.2.9 — no `tlsCertFile` / `tlsPrivateKeyFile`). The apiserver → kubelet
   channel is therefore encrypted but not authenticated in the direction that
   matters, and anything able to occupy that path can present any certificate.
   This is the most serious thing the scan found.
2. **Anonymous auth is on** (1.2.1) — observed, not inferred: unauthenticated
   `GET /version` and `GET /healthz` both return HTTP 200 and disclose exact
   `gitVersion`, `gitCommit` and `buildDate`, which is enough to match this
   cluster against public CVE lists. It is bounded — `GET /api/v1/secrets`
   returns 403, so RBAC still holds on real resources — and it is kubeadm's
   default, but it is free reconnaissance and this lab has not turned it off.
3. **`AlwaysPullImages` is not enabled** (1.2.11), which bears on phase 4: a pod
   can run an image already cached on a node without holding credentials to
   pull it, so both the registry allow-list and the signature gate assume a
   pull that may not occur.
4. **`--service-account-extend-token-expiration` is not false** (1.2.30), so
   service-account tokens outlive the bound lifetime their manifests imply —
   directly relevant to §3.3 and to A1, whose whole premise is a borrowed
   token.
5. **Three kubelet settings leave a protection off.** `seccompDefault` and
   `podPidsLimit` are unset (4.2.14, 4.2.13) — the first is §6.3's gap, the
   second leaves per-pod PID-exhaustion denial of service unbounded. And
   `streamingConnectionIdleTimeout` is `0s`, read out of
   `/var/lib/kubelet/config.yaml` on all three nodes on 2026-07-29 (4.2.5):
   `0s` disables the timeout, so an idle `exec`, `attach` or `port-forward`
   stream is never reaped and stays open until something else closes it. This
   is the check kube-bench scores as a false PASS; the mis-scoring and the gap
   are two facts, and this is the gap.
6. **Profiling endpoints are exposed** on the API server (1.2.15), controller
   manager (1.3.2) and scheduler (1.4.1). The latter two are mitigated by
   `--bind-address=127.0.0.1`; the API server's is not.
7. **Lower severity, recorded for completeness:** no `EventRateLimit` admission
   plugin (1.2.9); the kubelet service file and `config.yaml` are mode 644 where
   CIS asks for 600 (4.1.1, 4.1.9), and `/etc/cni/net.d/10-kindnet.conflist` is
   mode 644 on all three nodes for the identical reason (1.1.9, read directly
   off the nodes 2026-07-29 — owner `root:root`, which is what 1.1.10 asks for,
   and the directory above it is mode 700 `root:root`, so only root on the node
   reaches the file today); the etcd data directory is `root:root` rather than
   `etcd:etcd` (1.1.12 — mode 700 passes, so the intent is met, and kubeadm runs
   etcd as a root static pod); `DenyServiceExternalIPs` is off (1.2.3); and
   `--request-timeout`, both cipher-suite checks and
   `--terminated-pod-gc-threshold` sit at defaults (1.2.20, 1.2.29, 4.2.12,
   1.3.1).

**Consequence, stated plainly:** every item above is still true of the running
cluster. Nothing was remediated, no manifest changed, and no evidence directory
shows any of them closed. That is the correct outcome for a measurement phase,
but it makes this section a list of open gaps rather than a changelog, and
items 1 and 2 would be the first things to fix on a cluster that mattered.
**Two scope caveats, one of them now closed.** The node scan of 2026-07-26
produced a single Pod, which ran on `seclab-worker`; `seclab-worker2` was not
scanned by kube-bench at all, so the node-level findings rested on the scanner
having seen one of two workers. **Closed 2026-07-29:** the `node` target was
re-run as a DaemonSet
(`docs/evidence/phase-5-cis/daemonset-kube-bench-node.yaml`), which schedules
one Pod per eligible node. Both workers were scanned, and both returned 17 PASS
/ 2 FAIL / 6 WARN / 0 INFO — reports that are byte-identical to the 2026-07-26
Job's once glog timestamps are stripped (evidence §8). That closed a
**coverage** gap and nothing else: no item above was remediated by it, and a
DaemonSet of scanners enforces nothing. The second caveat stands unchanged:
4.2.5 and 1.1.9, which items 5 and 7 record from a **direct read** of all three
nodes rather than from the scan, are still direct reads. The DaemonSet run
reproduced 4.2.5's false PASS on both workers without re-testing the value
behind it, and it says nothing at all about 1.1.9, which is a `master`-target
check. And per §6.8, a kind cluster passes and fails a great many CIS checks
because of what kubeadm chose, not because of a hardening decision this lab
made — the scan measures the substrate at least as much as it measures the lab.

**6.13 The runtime sensor is itself privileged, ungated and unwatched.** §6.4
records what phase 6 bought and what it does not do with it; this item records
what the sensor *costs*, because installing Falco added the largest new attack
surface this lab has taken on. Six things, none of them remediated.

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
6. **Nothing retains the alerts.** Restated from §6.4 because it is the
   load-bearing limit and the easiest one to forget: stdout only, no shipper,
   no store, no page. Each pod's log holds three alert lines from the
   2026-07-29 attack window — the two documented above plus an earlier,
   unrecorded shell-spawn rehearsal at `15:12:42.954798594` — and every one of
   them survives exactly as long as a container log does.

**Consequence, stated plainly:** this cluster can now see a category of attack
it previously could not, and can still do nothing about it — while carrying a
privileged, ungated new component to get that visibility. Wiring an alert
router and a response action, even one that merely annotates the offending pod,
is what would turn this into a control, and that work is not done. Until it is,
§6.4 stays open and no §5 row is earned.

---

## Related documents

- [`architecture.md`](architecture.md) — diagrams of the admission path and the
  two artifact paths into the cluster.
- Runbooks, one per phase: [`../runbooks/`](../runbooks/).
- Captured attack transcripts: [`evidence/`](evidence/).
