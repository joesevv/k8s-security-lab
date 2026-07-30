# Runbook — Phase 5b: CIS remediation as config-as-code, proved by a full DR drill

Phase 5 scanned this cluster and triaged every FAIL and WARN, and changed
nothing — it said so on every page. Phase 5b is the other half: it takes the
part of that triage which is fixable in cluster configuration (threat model
§6.12), fixes it in `clusters/kind-config.yaml`, and then **destroys the
cluster and rebuilds it from that file**. The remediation and the disaster
recovery are the same operation on purpose. A config-as-code claim that has
never survived a `kind delete` is an untested claim, and every control this
lab has built in six phases has to come back from git afterwards or the claim
is false.

Sections 0-4 are complete and carry real observed output, captured 2026-07-30
against the live pre-remediation cluster. **Sections 5-9 are procedure that
has NOT been run yet** — their `Observed:` blocks read `(pending — filled by
the drill)` and must be filled from real output, never from the expectation
written above them.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash
unless noted. Kubernetes node image v1.35.5, kube-bench v0.15.6
(`docker.io/aquasec/kube-bench:v0.15.6@sha256:861900910eec...`), CIS config
`cis-1.12` — the same digest and pin as phase 5, so the before/after delta
measures the cluster and not the scanner.

Evidence file: `docs/evidence/phase-5b-cis-remediation/attack-output.txt`.

---

## 0. What is being changed, and what is deliberately left alone

Eight CIS checks are targeted. Each is one line of cluster configuration:

| CIS | Component | Change | Tier |
| --- | --- | --- | --- |
| 1.2.15 | apiserver | `--profiling=false` | 1 |
| 1.3.2 | controller-manager | `--profiling=false` | 1 |
| 1.4.1 | scheduler | `--profiling=false` | 1 |
| 1.2.11 | apiserver | `--enable-admission-plugins=NodeRestriction,AlwaysPullImages` | 1, gated |
| 4.2.14 | kubelet | `seccompDefault: true` | 1 |
| 4.2.13 | kubelet | `podPidsLimit: 4096` | 1 |
| 1.2.5 | apiserver | `--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt` | 2 |
| 4.2.9 | kubelet | `serverTLSBootstrap: true` | 2 |

**The tiering is a risk statement, not a schedule.** Tier 1 changes are
independently safe: if `--profiling=false` is wrong the control plane still
boots. Tier 2 is a matched pair that can break the cluster's observability —
`--kubelet-certificate-authority` makes the apiserver *verify* kubelet serving
certificates, and `serverTLSBootstrap` is what makes those certificates
verifiable. Ship one without the other and `kubectl logs`, `exec` and `top`
stop working cluster-wide. Even shipped together they leave a window where
logs are broken until each node's CSR is approved by hand — see §5.

**1.2.11 is gated on a live pull test, not assumed.** `AlwaysPullImages` makes
the kubelet re-pull every image on every pod create, so a cluster built with
it only boots if the registry really serves the images kind side-loads. The
gate ran 2026-07-30 and passed; see §1c.

### What phase 5b does NOT fix, and why

This list is part of the deliverable. These are decisions, not oversights.

- **Audit logging (1.2.16-1.2.19).** Needs an audit policy file and a log
  volume mounted into the apiserver static pod. On kind that is hostPath
  plumbing whose failure mode is a control plane that does not come up. The
  cost is a rebuild loop; the benefit is a log nothing in this lab reads.
- **Encryption at rest (1.2.29-1.2.30).** Needs an `EncryptionConfiguration`
  file mounted into the apiserver. Same failure mode, same reason. Note also
  that this lab's secrets story is sealed-secrets, which is about what is in
  **git**, not what is in **etcd** — 1.2.30 is a real gap and is left as one.
- **Anonymous auth (1.2.1).** kubeadm's bootstrap and kind's readiness
  probing lean on it during boot. Turning it off is not a one-line patch and
  has a real chance of bricking the rebuild.
- **Node/kubelet file-mode findings (4.1.1, 4.1.9).** These come from the kind
  node image itself, not from anything this repo controls. Phase 5 already
  classified them as kind-inherent.
- **No scanner exception is added.** kube-bench keeps running in
  `cis-benchmark` under its existing documented PSA exemption. Nothing is
  granted an exception in order to move a number.

**And the honest framing of the whole phase:** the eight items above are the
ones that were cheap. Fixing what is cheap and documenting what is not is a
defensible position; presenting the resulting counts as "the cluster is now
CIS compliant" is not. The scan is still a scan of a kind cluster on one
laptop, and threat model §6.8's point stands — most of the PASSes are
kubeadm's defaults, not decisions this lab made.

---

## 1. Pre-flight

### 1a. The MSYS `--raw` trap — read this before running anything from Git Bash

```bash
export MSYS_NO_PATHCONV=1
kubectl get --raw='/readyz'
```

**Purpose:** Git Bash (MSYS2) rewrites arguments that look like absolute POSIX
paths into Windows paths. It mangles `kubectl get --raw` targets and in-container
paths passed to `kubectl exec` / `docker exec`. The failure is silent and it is
exactly this repo's false-verification class: a `kubectl get --raw /readyz` can
print a **NotFound-shaped error while still exiting 0**, so an `if` on the exit
code passes and a human skimming the output sees an error and assumes the check
ran. Both readings are wrong. Export `MSYS_NO_PATHCONV=1` in **every** shell that
uses `--raw`, `kubectl exec` or `docker exec` with absolute paths — each shell is
fresh, so it must be re-exported every time. If it still misbehaves, also
`export MSYS2_ARG_CONV_EXCL='*'` and re-verify before trusting anything.

**Observed:** `ok`, exit code 0. The sanity check passed on the first form, so
`MSYS2_ARG_CONV_EXCL` was not needed. Every capture in §4 was taken from a
shell with `MSYS_NO_PATHCONV=1` exported.

### 1b. inotify limits

```bash
wsl -d docker-desktop sysctl fs.inotify.max_user_watches fs.inotify.max_user_instances
```

**Purpose:** phase 1 §1 documents that a kind cluster of this size needs
`max_user_watches` ≥ 524288 and `max_user_instances` ≥ 512, and that the fix
is **not persistent** across a Docker Desktop restart. Docker Desktop restarted
on the morning of 2026-07-30, so the values were re-read rather than assumed.

**Observed:**

```
fs.inotify.max_user_watches = 1048576
fs.inotify.max_user_instances = 8192
```

(exit code: 0) — already 2x and 16x above the thresholds. **No `sysctl -w` was
run**, so there is no after-value. The restart did not reset them on this host.
Re-check anyway before the recreate in §5; a rebuild is exactly when a low
value bites.

### 1c. The pull-gate — this decides whether `AlwaysPullImages` ships

```bash
export MSYS_NO_PATHCONV=1
docker exec seclab-worker crictl pull <ref>     # for each ref below
```

**Purpose:** prove the registry actually serves every image a rebuilt cluster
must pull, before committing a config that forces it to. Three groups: GATE
(kind's preloaded system images — all four must pass or `AlwaysPullImages` is
omitted entirely), PREREQ (images side-loaded today with TAG `<none>`, which a
fresh cluster must pull regardless of the plugin — a failure here blocks the
whole recreate), and SANITY.

A negative control runs first, because "Image is up to date" is only evidence
if `crictl` really contacts the registry rather than short-circuiting locally.

**Observed:** negative control `docker.io/kindest/kindnetd:v20260528-DOES-NOT-EXIST`
→ `failed to resolve reference ... not found` (exit code: 1), so the tool does
go to the registry. All four GATE refs, both PREREQ refs and both SANITY refs
returned `Image is up to date for sha256:...` (exit code: 0 each). Full
transcript in evidence §1.

**Decision: all four GATE refs passed, so `AlwaysPullImages` IS included.** Had
any failed, the rule was to omit the whole `enable-admission-plugins` entry and
leave kubeadm's default `NodeRestriction` untouched — not to write
`NodeRestriction` back by hand, which would be the same value by a longer route
and would imply a decision nobody made.

**This result has a shelf life.** It is a statement about one host on one day
with working access to docker.io, registry.k8s.io and ghcr.io. Re-run the gate
before any later rebuild rather than trusting this page.

---

## 2. The configuration change, annotated

The entire remediation is `clusters/kind-config.yaml`. The file previously
claimed, in its own header, "No extraPortMappings and no `kubeadmConfigPatches`
by design" — that sentence is now false and has been removed. The
`extraPortMappings` half is still true and is still stated.

```yaml
kubeadmConfigPatches:
  - |
    kind: ClusterConfiguration
    apiServer:
      extraArgs:
      - name: runtime-config
        value: ""
      - name: profiling
        value: "false"
      - name: enable-admission-plugins
        value: NodeRestriction,AlwaysPullImages
      - name: kubelet-certificate-authority
        value: /etc/kubernetes/pki/ca.crt
    controllerManager:
      extraArgs:
      - name: enable-hostpath-provisioner
        value: "true"
      - name: profiling
        value: "false"
    scheduler:
      extraArgs:
      - name: profiling
        value: "false"
  - |
    kind: KubeletConfiguration
    seccompDefault: true
    podPidsLimit: 4096
    serverTLSBootstrap: true
```

**Purpose of the two entries that are not remediation at all** —
`runtime-config: ""` and `enable-hostpath-provisioner: "true"`. The live
kubeadm-config ConfigMap is `kubeadm.k8s.io/v1beta4`, in which `extraArgs` is a
**list** of name/value pairs rather than a map, and kind injects those two
entries itself. A patch against a list may **replace** it wholesale rather than
merge into it, and which happens is not something this file controls. Restating
kind's own entries makes the outcome identical either way: under replace
semantics they survive because they are written here; under append semantics
they are already present and are not duplicated into a conflict. Dropping them
would silently remove the hostpath provisioner and change the apiserver's
runtime-config on every rebuild — a self-inflicted regression disguised as a
hardening change.

**Observed:** both entries are confirmed present on the **pre-change** cluster
(evidence §2e): the apiserver ps line ends `--runtime-config=` and the
controller-manager ps line ends `--enable-hostpath-provisioner=true`. That is
the baseline the §5 assertion checks against.

**Purpose of `podPidsLimit: 4096`:** check 4.2.13 requires only that a limit be
**set**, with no comparison on the value — 4096 is a lab choice, high enough
that nothing here approaches it and low enough to bound a fork bomb. It is not
derived from anything and should not be presented as if it were.

**Validation, before the file is trusted:**

```bash
npx --yes js-yaml@4 clusters/kind-config.yaml            # outer document
npx --yes js-yaml@4 <each extracted kubeadmConfigPatches entry>
```

**Observed:** the outer document parses (exit code: 0) and yields
`kubeadmConfigPatches` as a 2-element array of strings. Each of the two strings
was written to a temp file and parsed on its own — patch 1 yields
`ClusterConfiguration` with `apiServer.extraArgs` of 4 name/value objects,
`controllerManager.extraArgs` of 2 and `scheduler.extraArgs` of 1; patch 2
yields `{kind: KubeletConfiguration, seccompDefault: true, podPidsLimit: 4096,
serverTLSBootstrap: true}` with `true` parsed as boolean and `4096` as integer
(exit code: 0 for both). The three node `image:` lines are byte-identical to
the previous revision — `git diff` shows no changed line containing `image:` or
the digest — and the file contains zero CR bytes, as `.gitattributes` requires
for `*.yaml`.

**Note the `#` comments inside the block scalars.** They are literal text as far
as the outer YAML is concerned and comments as far as kubeadm's and the
kubelet's parsers are concerned. That is intended, and it is why the parse was
run against the *extracted* strings and not only the outer file.

---

## 3. Predictions — written before the cluster is destroyed

`docs/evidence/phase-5b-cis-remediation/attack-output.txt` §0 carries the
prediction table: for each of the eight checks, the cfg stanza that decides it,
the predicted post-remediation status, and the ground-truth probe that proves
the fix **regardless of what kube-bench prints**. It is committed before the
recreate specifically so it can be wrong in public, and §9 reconciles against
it without editing it.

Three results from that analysis are load-bearing for §5 and §9 and are
repeated here because skipping them causes false verification:

1. **4.2.9 is predicted NOT to move.** `serverTLSBootstrap` does not write
   `tlsCertFile`/`tlsPrivateKeyFile` into the kubelet config file — it does the
   opposite — and that file is what the check reads. The posture improves while
   the scanner output stays `[WARN]`. The **only** evidence for 4.2.9 will be
   the serving-certificate issuer flip, so if that is not captured, 4.2.9 has
   no evidence at all.
2. **The obvious seccomp probe is invalid on kind.** `Seccomp: 0` is
   unreachable — the kind "node" is a Docker container carrying Docker's own
   seccomp profile and every process inside inherits it. The before value is
   already `Seccomp:` 2 (the field is tab-separated in `/proc/1/status`; the
   byte-exact capture is in evidence §2g). The working discriminator, established by control
   against an existing `RuntimeDefault` pod, is **`Seccomp_filters`**: 1 means
   nothing above the inherited profile, 2 means Kubernetes applied
   RuntimeDefault. Asserting `Seccomp: 2` after the change proves nothing.
3. **1.2.11 is not a missing-flag finding.** `--enable-admission-plugins` is
   already present today with value `NodeRestriction`; the check WARNs because
   `AlwaysPullImages` is not in the value. Predicted `[WARN]` → `[PASS]`.

Predicted summary counts, conditional on the above:

| target | before | predicted after |
| --- | --- | --- |
| master | 46 PASS / 10 FAIL / 50 WARN | 51 PASS / 6 FAIL / 49 WARN |
| node (each worker) | 17 PASS / 2 FAIL / 6 WARN | 19 PASS / 2 FAIL / 4 WARN |

**And the stronger claim, which is the one worth checking:** every check *not*
in the target list must be unchanged. Five master checks and two node checks
are supposed to move. Anything else that moves is a finding.

---

## 4. Before-capture — the baseline §9 is measured against

Full transcript in evidence §2. Method and results, in order:

```bash
kubectl apply -f docs/evidence/phase-5-cis/job-kube-bench-master.yaml
kubectl apply -f docs/evidence/phase-5-cis/daemonset-kube-bench-node.yaml
kubectl -n cis-benchmark wait --for=condition=complete job/kube-bench-master --timeout=300s
kubectl -n cis-benchmark logs job/kube-bench-master
kubectl -n cis-benchmark logs <each node-ds pod>
```

**Purpose:** re-run the phase-5 scan on the unchanged cluster so the after-run
has a same-day, same-method baseline rather than being diffed against a
four-day-old committed report.

**Observed:** master 46 PASS / 10 FAIL / 50 WARN / 0 INFO; both workers 17 PASS
/ 2 FAIL / 6 WARN / 0 INFO (exit code: 0 throughout). Identical counts to the
committed phase-5 evidence.

### 4a. Drift check — and it is not clean

```bash
diff <(sed -n '<committed range>' docs/evidence/phase-5-cis/attack-output.txt | tr -d '\r' \
        | grep -v -e '^I07' -e '^Warning: Kubernetes version') \
     <(kubectl -n cis-benchmark logs <pod> | grep -v -e '^I07' -e '^Warning: Kubernetes version')
```

**Purpose:** phase 5's own mechanical method (evidence §8f) — strip the glog
lines and the client-version warning, then diff — to confirm the cluster is
still the cluster phase 5 measured.

**Observed:**

| report | committed range | exit code |
| --- | --- | --- |
| node, `seclab-worker` vs §8d | 1481,1569 | **0** — identical, no output |
| node, `seclab-worker2` vs §8e | 1588,1676 | **0** — identical, no output |
| master vs §3 | 265,678 | **1** — 18 changed lines in 9 hunks |

The master diff is recorded rather than normalised away, and it decomposes
exactly:

- Restricted to status lines and counts (`grep -E '^(\[|== |[0-9]+ checks)'`)
  the diff is **empty, exit code 0** — no check changed status.
- Every one of the 18 changed lines is a tab-indented `ps` line; filtering
  those out leaves nothing.
- Normalising the volatile `ps` columns (pid, ppid, c, stime, time) leaves one
  distinct difference: `--advertise-address=172.18.0.2` → `172.18.0.3`.
  Normalising that too makes the two reports byte-identical (exit code: 0).
- Cause: Docker Desktop restarted and the bridge reassigned addresses —
  `seclab-control-plane` is now 172.18.0.3 and `seclab-worker` holds .2.

**Verdict: no posture drift, but the byte-diff is not zero.** This matters for
§9 far more than it matters here: a recreated cluster gets new PIDs, new start
times and quite possibly new addresses on all three nodes, so a raw §8f-style
diff of after-vs-before **will** be non-empty for reasons unrelated to the
remediation. §9 must diff status lines and counts, and treat `ps`-detail
differences as noise to inspect by eye. A drill that reports "the diff was
non-empty, remediation failed" has misread its own instrument.

### 4b. The rest of the baseline

| capture | result |
| --- | --- |
| kubelet `/configz` ×3 | `seccompDefault:false`, `podPidsLimit:-1`, `serverTLSBootstrap` absent on all three |
| control-plane `ps` ×3 | `--profiling` **absent** ×3; `--kubelet-certificate-authority` absent; `--enable-admission-plugins=NodeRestriction` **present** |
| kind-injected entries | `--runtime-config=` and `--enable-hostpath-provisioner=true` both present |
| kubelet serving cert issuer ×3 | `CN=seclab-control-plane-ca@1784637412`, `CN=seclab-worker-ca@1784637429`, `CN=seclab-worker2-ca@1784637429` — every kubelet is its own CA |
| probe pod `Seccomp_filters` | `1` |
| probe pod `pids.max` | `18999` (not `max`; origin undetermined — see evidence §2g) |
| probe pod `imagePullPolicy` | `IfNotPresent` (admission-defaulted) |
| re-seal sources | `secrets/plain/demo-app-secret-plain.yaml` and `controller-cert.pem` present, both gitignored — existence only, neither read |

One capture contradicts a committed claim and is recorded rather than fixed:
the kubelet config **file** says `streamingConnectionIdleTimeout: 0s` on all
three nodes (as threat model §6, the phase-5 runbook and the README all state),
but `/configz` reports the effective value as `"4h0m0s"` and the kubelet runs
with no `--streaming-connection-idle-timeout` flag that would explain it. Both
readings are on the record; the reconciliation is **not** resolved here and no
committed document was edited by this phase. 4.2.5 is not one of the eight
targets. See evidence §2d.

**Cleanup observed:** Job and DaemonSet deleted, `kubectl -n cis-benchmark get
jobs,ds,pods` → `No resources found in cis-benchmark namespace.` (exit code: 0,
re-checked after the DS pods finished terminating). Namespace retained per the
phase-5 convention. Probe pod deleted; `demo-kyverno-only` empty.

---

## 5. Recreate, and the Tier-2 fast-fail gate

> **HUMAN GATE — NEVER RUN THIS SECTION UNATTENDED.** `kind delete` destroys
> every workload, policy, secret and sensor in the lab. Everything is
> recoverable from git *except* the sealed-secret plaintext sources in
> `secrets/plain/`, which are gitignored — §4b confirms they exist on this host
> and that confirmation is a precondition, not a formality. Do not start unless
> you can finish §5-§9 in one sitting.

```bash
kind delete cluster --name seclab
kind create cluster --config clusters/kind-config.yaml
```

**Purpose:** rebuild the entire cluster from the committed config, which is the
remediation and the DR drill in one step.

**Expected:** cluster creates; three nodes. Note that with `AlwaysPullImages`
active the first pod creations really do pull, so CNI and DNS coming up is
itself the first proof the §1c gate was correct.

**Observed:** (pending — filled by the drill)

### 5a. The Tier-2 gate, IMMEDIATELY after create

Do this before anything else is installed. Tier 2 is the pair that can break
the cluster's observability, and the failure is easiest to diagnose on an
otherwise empty cluster.

```bash
kubectl get csr
```

**Purpose:** `serverTLSBootstrap: true` makes each kubelet request a serving
certificate from the CSR API instead of self-signing. Nothing approves these
automatically.

**Expected:** three Pending CSRs with `signerName: kubernetes.io/kubelet-serving`
— one per node. Zero CSRs means the KubeletConfiguration patch did not land and
you are in contingency (ii).

**Observed:** (pending — filled by the drill)

```bash
kubectl -n kube-system logs <any pod on any node>        # BEFORE approving
```

**Purpose:** the negative control, and it is the whole point of the gate.
Capture the failure **before** approval. With
`--kubelet-certificate-authority` set, the apiserver now verifies kubelet
serving certs against the cluster CA; until a node's CSR is approved its
kubelet is still presenting an unverifiable cert, so this must FAIL. A drill
that approves first and then shows logs working has proved nothing — it cannot
distinguish "the fix works" from "it was never broken".

**Expected:** an x509 / certificate-verification error, non-zero exit.

**Observed:** (pending — filled by the drill)

```bash
kubectl certificate approve <each kubelet-serving CSR>
kubectl -n kube-system logs <a pod on EVERY node>        # after approving
```

**Purpose:** the positive control, on every node — one node working does not
establish the other two.

**Expected:** all three succeed, exit 0.

**Observed:** (pending — filled by the drill)

### 5b. Assert the flags actually landed

```bash
export MSYS_NO_PATHCONV=1
docker exec seclab-control-plane sh -c 'ps -ef | grep kube-apiserver | grep -v grep'
docker exec seclab-control-plane sh -c 'ps -ef | grep kube-controller-manager | grep -v grep'
docker exec seclab-control-plane sh -c 'ps -ef | grep kube-scheduler | grep -v grep'
```

**Expected:** `--profiling=false` on all three; `--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt`
and `--enable-admission-plugins=NodeRestriction,AlwaysPullImages` on the
apiserver. **And the regression check that matters more than any of them:**
`--runtime-config=` must still be on the apiserver line and
`--enable-hostpath-provisioner=true` still on the controller-manager line. If
either is gone, the patch replaced kind's list instead of merging and the
restatement in §2 failed — record it, because it is a real finding about how
v1beta4 patches behave.

**Observed:** (pending — filled by the drill)

```bash
kubectl -n kube-system get cm kubeadm-config -o yaml
```

**Purpose:** confirm the same thing at the source rather than only in `ps`.

**Expected:** the `ClusterConfiguration` carries all four apiServer entries and
both controllerManager entries.

**Observed:** (pending — filled by the drill)

```bash
export MSYS_NO_PATHCONV=1
for n in seclab-control-plane seclab-worker seclab-worker2; do
  kubectl get --raw "/api/v1/nodes/$n/proxy/configz"
done
```

**Expected:** `seccompDefault: true`, `podPidsLimit: 4096`,
`serverTLSBootstrap: true` on all three.

**Observed:** (pending — filled by the drill)

```bash
export MSYS_NO_PATHCONV=1
for n in seclab-control-plane seclab-worker seclab-worker2; do
  docker exec $n sh -c 'echo | openssl s_client -connect localhost:10250 2>/dev/null | openssl x509 -noout -issuer -subject'
done
```

**Purpose:** the ground truth for 4.2.9, which kube-bench will not show.

**Expected:** issuer is the cluster CA on all three, replacing the per-node
`CN=<node>-ca@<epoch>` self-signed issuers recorded in §4b.

**Observed:** (pending — filled by the drill)

### 5c. Contingency ladder

Each step: **record honestly, no silent retries.** A failed attempt that is
re-run until it works and only the working run is written down is the exact
fabrication class this repo exists to avoid. Both attempts go in the evidence
file.

- **(i) `kind create` errors on patch syntax.** Add an explicit `apiVersion` to
  the failing patch document — `kubeadm.k8s.io/v1beta4` for the
  ClusterConfiguration patch, `kubelet.config.k8s.io/v1beta1` for the
  KubeletConfiguration patch — and retry. Record **both** the failing and the
  succeeding attempt, including the verbatim error.
- **(ii) Tier-2 gate fails** — no CSRs appear, or `kubectl logs` is still
  broken minutes after approving all three. Recreate Tier-1-only: drop the
  `kubelet-certificate-authority` entry and the `serverTLSBootstrap` field,
  leave everything else. Record the failed attempt verbatim, and mark 1.2.5 and
  4.2.9 as not-remediated rather than quietly dropping them from the table.
- **(iii) `AlwaysPullImages` bring-up failure** — nodes stuck NotReady on image
  pulls, CNI or CoreDNS never Ready. Recreate without that `extraArgs` entry
  (leaving kubeadm's default `NodeRestriction`), record the failure, and mark
  1.2.11 not-remediated. This would also mean the §1c gate gave a false green,
  which is worth writing up on its own.

---

## 6. Re-bootstrap order

Pointers only — the bodies live in the phase runbooks and are not duplicated
here. **Order matters**, and one item is load-bearing: the default-deny
NetworkPolicy must go last of the demo controls, because its egress deny kills
the API probes later steps depend on.

1. **Workloads + `demo` namespace with PSA labels + nginx** — phase-1 runbook
   §4 (*Apply the nginx workload*), manifests in `workloads/nginx/`. Verify
   with phase-1 §5.
2. **RBAC** — phase-2a runbook §1 (nginx dedicated ServiceAccount, no token)
   and §2 (least-privilege developer Role), from `rbac/developer-role.yaml`.
3. **Kyverno 1.18, pinned chart** — phase-2b runbook §1. Chart is pinned;
   resolve it with `helm search repo` rather than guessing, as that section
   documents.
4. **`demo-kyverno-only` namespace + reports RBAC** — `policies/00-namespace-kyverno-only.yaml`
   and `rbac/kyverno-reports-ephemeralcontainers.yaml`.
5. **Policies, Audit first** — phase-2b runbook §2 (*Safety sequence — Audit
   first, then Deny*). Apply the four ValidatingPolicies from `policies/` in
   Audit, confirm the **PASS=4 gate**, then flip to Deny. Do not skip the Audit
   leg; it is what makes the Deny flip a decision rather than a hope.
6. **Attack re-verify set** — phase-2b runbook §3 (nine attacks, every one
   blocked at admission).
7. **Supply chain** — phase-4 runbook §2 (apply the ImageValidatingPolicy and
   confirm it is enforcing) then the signed-app workload from
   `workloads/signed-app/`; re-verify with phase-4 §3. Policy lives in
   `policies/supply-chain/`.
8. **NetworkPolicy, LAST of the demo controls** — phase-2c runbook §1 (*Safety
   sequence — deny baseline first, then the allows*): `network/00-default-deny.yaml`,
   then `10-allow-dns.yaml`, `20-allow-nginx-ingress-from-client.yaml`,
   `30-allow-client-egress-to-nginx.yaml`. Re-verify with phase-2c §2.
9. **Namespace manifests for the two remaining phases.** `falco` and
   `cis-benchmark` each need their committed namespace manifest applied before
   their workload — `docs/evidence/phase-6-falco/00-namespace-falco.yaml` and
   `docs/evidence/phase-5-cis/00-namespace-cis-benchmark.yaml`. Both carry PSA
   exemptions that are deliberately written down rather than inherited; do not
   let `helm install` or `kubectl apply` create these namespaces implicitly.

**Observed:** (pending — filled by the drill)

---

## 7. Re-seal the sealed secret from its sources

Phase-3 runbook §2 (*Seal a secret — plaintext never touches Git*), sub-steps
2b→2d. The controller is reinstalled per phase-3 §1 first; its keypair is new,
so **the committed ciphertext cannot be reused** — it must be re-sealed against
the new controller cert.

**Preserve the file's hand-written header.** `secrets/demo-app-sealedsecret.yaml`
carries 20 lines of `#` comment above `apiVersion:` that `kubeseal` will not
reproduce. Re-prepend it verbatim:

```
# SealedSecret — Phase 3 secrets management (sealed-secrets).
#
# WHY THIS FILE EXISTS: it replaces a plaintext Kubernetes Secret in Git.
# A normal Secret's `data` is only base64 ENCODED (not encrypted), so
# committing one leaks the credential to anyone who can read the repo. The
# `spec.encryptedData` below is RSA-OAEP CIPHERTEXT produced by kubeseal
# against the in-cluster controller's PUBLIC cert. It is SAFE TO COMMIT: it
# can only be decrypted by the controller's PRIVATE key, which never leaves
# the cluster (it lives as a Secret in kube-system).
#
# SCOPE: sealed with the DEFAULT strict scope — this ciphertext will ONLY
# unseal into namespace `demo` with Secret name `demo-app-secret`. Copying
# it into another namespace/name (attacker theft) is refused by the
# controller. See runbooks/phase-3-secrets.md and
# docs/evidence/phase-3-secrets/attack-output.txt.
#
# Apply:   kubectl apply -f secrets/demo-app-sealedsecret.yaml
# Result:  the controller materializes Secret demo/demo-app-secret (owned by
#          this SealedSecret). The plaintext original + fetched cert stay in
#          the gitignored secrets/plain/ directory and are never committed.
```

**Purpose of the round-trip proof:** show the re-sealed ciphertext unseals to
the same value as the source without ever printing that value. Compare
`sha256` of the source value against `sha256` of the materialised Secret's
decoded value; compare hashes, never contents.

**The no-plaintext-in-git gate, with its guard:** the check that the plaintext
value does not appear in the repo is only meaningful if the value being
searched for is non-empty. An unset `$VAL` or `$B64` makes `grep` search for
nothing, find nothing, and report a clean bill of health — a false pass. Assert
both are non-empty **before** the grep, and record the assertion.

**Expected:** hashes match; the plaintext value appears nowhere in tracked
files; the header is present above `apiVersion:` in the re-sealed file.

**Observed:** (pending — filled by the drill)

---

## 8. Reinstall Falco

Use `clusters/falco-install.md` **verbatim** — the pinned flags there are the
install record and must not be re-derived from memory. That includes
`--set driver.kind=modern_ebpf`, the digest-pinned `image.tag` and
`falcoctl.image.tag`, the digest-pinned rules refs on both
`falcoctl.config.artifact.install.refs[0]` and `...follow.refs[0]`,
`falcoctl.artifact.follow.enabled=false`, the digest-pinned container plugin
ref, `collectors.kubernetes.enabled=false`, both `falcosidekick` flags off, and
`tty=true`. Namespace first, from
`docs/evidence/phase-6-falco/00-namespace-falco.yaml`.

**Purpose of re-proving the driver:** phase-6 §2's driver proofs exist because
the tool's own word is not evidence. Repeat them rather than citing the old
run: BTF present on all three nodes (`stat /sys/kernel/btf/vmlinux`), the
running pod's own `engine.kind` read out of `/etc/falco/falco.yaml`, the
`Opening 'syscall' source with modern BPF probe.` startup line, `lsmod | grep
-E 'falco|scap'` empty cluster-wide, and live BPF objects in Falco PID 1's
`/proc/1/fd`. Zero restarts, i.e. no silent fallback to another driver.

**Purpose of the detection markers:** re-prove that the sensor actually sees
events on the rebuilt cluster, using **new** markers so a grep cannot match a
stale log line from before the rebuild. Use `R3-DR-PRIMARY-MARKER` for the
interactive-shell detection and `R3-DR-SHM-MARKER` for the write-and-execute
detection, following the phase-6 §3 procedure that used
`PHASE6-PRIMARY-MARKER` / `PHASE6-SHM-MARKER`.

**Expected:** driver resolves to `modern_ebpf` with no fallback; both markers
appear in the Falco pod log on the node where the behaviour was triggered.
Remember phase-6's own caveat — one kernel, three sensors, so divide event
counts by three.

**Observed:** (pending — filled by the drill)

---

## 9. The after-run, the delta, and the final state

### 9a. Run the scan again, unchanged

```bash
kubectl apply -f docs/evidence/phase-5-cis/job-kube-bench-master.yaml
kubectl apply -f docs/evidence/phase-5-cis/daemonset-kube-bench-node.yaml
kubectl -n cis-benchmark wait --for=condition=complete job/kube-bench-master --timeout=300s
kubectl -n cis-benchmark logs job/kube-bench-master
kubectl -n cis-benchmark logs <each node-ds pod>
```

**Purpose:** same manifests, same digest, same benchmark pin as the before-run.
Nothing about the scanner changes, so the delta is the cluster.

**Observed:** (pending — filled by the drill)

### 9b. The delta method — and the trap §4a already found

```bash
# status lines and counts only — this is the authoritative comparison
diff <(grep -v -e '^I07' -e '^Warning: Kubernetes version' before-master-job.log \
        | grep -E '^(\[|== |[0-9]+ checks)') \
     <(grep -v -e '^I07' -e '^Warning: Kubernetes version' after-master-job.log \
        | grep -E '^(\[|== |[0-9]+ checks)')
```

**Purpose:** the same glog-strip diff phase 5 documented, but restricted to
status and count lines. §4a established why: a rebuilt cluster gets new PIDs,
new start times and quite possibly new node addresses, so the tab-indented `ps`
detail lines **will** differ for reasons that have nothing to do with the
remediation. Run the full-text diff too, but read it as a change log to inspect
by eye, not as a pass/fail.

**Expected:** exactly five changed status lines on master (1.2.5, 1.2.11,
1.2.15, 1.3.2, 1.4.1) and exactly two per worker (4.2.13, 4.2.14), plus the
count lines. **Every other check must be unchanged** — that is the real
assertion. 4.2.9 must still read `[WARN]`; if it flipped to `[PASS]`, the
prediction in §3 was wrong and the reason needs finding, not celebrating.

**Observed:** (pending — filled by the drill)

### 9c. Reconcile against the predictions

**Purpose:** walk the §0 table of the evidence file check by check and mark
each prediction hit or missed. Do not edit §0. A missed prediction is a result
and stays on the page next to what actually happened.

**Expected:** master 51/6/49, node 19/2/4 per worker. Plus the ground-truth
probes, which are what actually prove the remediation:

| check | ground-truth probe | expected |
| --- | --- | --- |
| 1.2.15 / 1.3.2 / 1.4.1 | control-plane `ps` lines | `--profiling=false` ×3 |
| 1.2.5 | apiserver flag + the §5a logs-broken→CSR-approved→logs-work flip | both |
| 1.2.11 | new probe pod with **no** `imagePullPolicy` field | mutated to `Always` (was `IfNotPresent`) |
| 4.2.13 | probe pod `/sys/fs/cgroup/pids.max` | `4096` (was `18999`) |
| 4.2.14 | probe pod `grep Seccomp /proc/1/status` | `Seccomp_filters:` **2** (was 1) — NOT `Seccomp: 2`, see §3 |
| 4.2.9 | serving-cert issuer ×3 | cluster CA (was per-node self-signed) |

Recreate the probe pod exactly as §4b's — `demo-kyverno-only`,
`docker.io/curlimages/curl:8.16.0`, no `seccompProfile` field, no
`imagePullPolicy` field — so the three readings are comparable. Delete it
afterwards.

**Observed:** (pending — filled by the drill)

### 9d. Cleanup and whole-lab final state

```bash
kubectl -n cis-benchmark delete job kube-bench-master
kubectl -n cis-benchmark delete ds kube-bench-node-ds
kubectl -n cis-benchmark get jobs,ds,pods
```

**Expected:** `No resources found in cis-benchmark namespace.` Namespace
retained, per the phase-5 convention. Probe pod gone.

**Observed:** (pending — filled by the drill)

Then the whole-lab final state in the phase-6 §5 style: every namespace, every
policy, every DaemonSet and Deployment, with the point being that a cluster
destroyed and rebuilt from git is back to the same posture. **State honestly
what did not come back.** Anything that needed a manual step (the CSR
approvals, the re-seal against a new controller keypair) is not
config-as-code, and the drill's value is partly in naming those.

**Observed:** (pending — filled by the drill)
