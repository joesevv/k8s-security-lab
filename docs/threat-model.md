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

Not claimed: runtime-behaviour techniques (there is no runtime sensor — §6.4),
and any technique in a namespace the policies do not select (§6.7).

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
this document is a preventive control; none of them is detective.

**6.3 No node or kernel hardening.** No AppArmor or SELinux profile beyond
`seccompProfile: RuntimeDefault`, no gVisor or Kata, no CIS remediation
(kube-bench is a later phase). All three nodes are containers on one shared WSL2
kernel. **Consequence:** a kernel-level escape that gets past PSA lands on the
host directly — there is no second wall.

**6.4 No runtime detection until Falco lands.** Every control in this document
fires at admission time or at connection time. A workload that is admitted and
*then* misbehaves — a shell spawned in a container, a miner started inside an
allow-listed and correctly signed image — is neither detected nor stopped.
Signature verification is explicitly not a behavioural control.

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

**6.6 The SBOM is unattested.** Syft produces an SPDX-JSON SBOM, and the
workflow uploads it as a **CI artifact**. It is not a `cosign attest`
attestation bound to the image digest, so no admission policy can require or
verify it. The SBOM is documentation of that build, not a control — it proves
nothing at admission time.

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
explicit system-namespace exclusions.

**6.8 kind is not production.** One host, one kernel, one etcd, a single
non-HA control plane, and no real multi-tenancy. Nothing here says anything
about behaviour under node failure, control-plane partition, or a hostile
co-tenant. `NodeRestriction` is enabled and authorization is `Node,RBAC`
(verified), but that is kubeadm's default, not a hardening decision this lab
made.

**6.9 The two-job CI split is proven once; the build is not reproducible.** Run
`30174855073` (2026-07-25) was the **first ever** execution of the `build-scan` /
`sign` split. Both jobs succeeded, every step included, and the
`Verify signature (self-check vs the identity Kyverno pins)` step validated the
new digest `sha256:7fd13d22d934f4202edc164e525436e190498590b62c41e348b1a4092eb3337b`
against certificate-identity
`https://github.com/joesevv/k8s-security-lab/.github/workflows/supply-chain.yml@refs/heads/main`
and issuer `https://token.actions.githubusercontent.com`, confirming the
transparency-log entry offline and the code-signing certificate against the
trusted CA certificates — transcript in
[`cosign-verify.txt`](evidence/phase-4-supply-chain/cosign-verify.txt). The
`id-token` isolation in §3.2 is therefore **runnable**: the split builds, scans,
signs and verifies with `build-scan` holding no `id-token`, which establishes
that the permission is not needed there. **What that does not buy.** It does not
make the isolation an observed *control*. Nothing in the run tried to mint an
OIDC token from `build-scan` and was refused, so "a compromised third-party
action cannot mint the identity the cluster trusts" is still inferred from the
`permissions:` block — exactly as readable before the run executed as after it.
And one green run of one workflow shape is evidence that it works, not that it
is durable. The build is **not byte-reproducible**: an unchanged application
produced a different digest from the previous build (`sha256:b4cb133e…` →
`sha256:7fd13d22…`), which is expected from layer-metadata timestamps but means
the digest the cluster pins cannot be independently re-derived from source —
the signature is the only link back to the pipeline. And the `sign` job still
carries `contents: read` although it runs no checkout; the green run had that
scope present, so whether it is genuinely removable is untested.

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
`[]`. Dependabot version updates are **firing**, not merely configured — PRs
#1–#3 (2026-07-25) each bump a SHA-pinned action (`docker/login-action`
3.7.0→4.5.1, `actions/upload-artifact` 4.6.2→7.0.1, `actions/checkout`
4.4.0→7.0.1), so the tracking half of the pin-plus-track design in
`.github/dependabot.yml` does detect stale pins and propose exact replacements.
That is where it stops: all three PRs are still **open**, none is merged, and
`gh pr checks` reports no checks on any of them, since the workflow triggers
only on push to `main`. Detection and proposal are demonstrated; the loop has
never been closed by a merged bump that then built, signed and verified.
**Still off, and each is a real gap.**
`secret_scanning_non_provider_patterns` and `secret_scanning_validity_checks`
are both `disabled`, so a credential in a custom or non-provider format is not
matched. Private vulnerability reporting is `{"enabled": false}` and there is no
`SECURITY.md` on `main` (HTTP 404), so a finder has no private disclosure
channel. `sha_pinning_required` is `false` with `allowed_actions: "all"`, so the
workflow's SHA pins are a convention this repo keeps, not a rule GitHub
enforces. And push protection guards only **future** pushes — nothing already
public can be retracted, the same retroactive property that makes asset 2
dangerous.

---

## Related documents

- [`architecture.md`](architecture.md) — diagrams of the admission path and the
  two artifact paths into the cluster.
- Runbooks, one per phase: [`../runbooks/`](../runbooks/).
- Captured attack transcripts: [`evidence/`](evidence/).
