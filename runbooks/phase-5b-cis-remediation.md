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

**Observed — and it took four attempts. The committed config did not build a
cluster.** Full transcript in evidence §3.

`kind delete` succeeded in 4 seconds (exit code: 0). Then:

1. **Attempt 1 FAILED** (exit code: 1). `kubeadm init` rejected the patch:
   `error: json: cannot unmarshal array into Go struct field
   APIServer.apiServer.ControlPlaneComponent.extraArgs of type
   map[string]string`, preceded by
   `your configuration file uses a deprecated API spec: "kubeadm.k8s.io/v1beta3"`.
2. **Attempt 2** re-ran the same command with `--retain` so the failed node
   survived and `/kind/kubeadm.conf` could be read rather than guessed at. Same
   failure. The render shows **kind v0.32.0 emits `kubeadm.k8s.io/v1beta3`**,
   in which `extraArgs` is a `map[string]string` — so §2's list form, chosen
   because the live *ConfigMap* is v1beta4, was the wrong shape. kubeadm
   converts on write; the ConfigMap says nothing about what kind feeds it. The
   `KubeletConfiguration` patch landed fine on every attempt, because kind's own
   kubelet document already is `kubelet.config.k8s.io/v1beta1`.
3. **Attempt 3 applied contingency (i) verbatim and that made things worse.**
   With `apiVersion: kubeadm.k8s.io/v1beta4` added, `kind create` exited **0**,
   three nodes went Ready — and the patch matched no document, so kind
   discarded it silently. The rendered config carried only kind's own
   `runtime-config` and `enable-hostpath-provisioner`, and the running
   apiserver had `--profiling` count 0, `--kubelet-certificate-authority`
   count 0 and `--enable-admission-plugins=NodeRestriction`. That is the
   pre-remediation control plane. **See the correction to §5c below.**
4. **Attempt 4 succeeded** (exit code: 0, 28 seconds) after rewriting the
   `extraArgs` blocks in the v1beta3 **map** form, which is now what
   `clusters/kind-config.yaml` carries. Three nodes Ready.

`AlwaysPullImages` did not obstruct bring-up — CNI, CoreDNS, kube-proxy and
local-path-provisioner all pulled and ran, so contingency (iii) was never
reached and §1c's green was real.

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

**Observed: FOUR Pending `kubelet-serving` CSRs, not three** (exit code: 0).
`seclab-control-plane` filed **two** of them (`csr-bx9x5` and `csr-httth`, 27s
and 29s old); each worker filed one. The expectation above is therefore not a
safe gate — **the safe gate is "at least one Pending `kubelet-serving` CSR per
node, and approve every Pending one."** Three additional
`kubernetes.io/kube-apiserver-client-kubelet` CSRs were already
`Approved,Issued`; those are auto-approved by the controller manager and are
not part of this gate. Evidence §4a.

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

**Observed: it fails on all three nodes, but NOT with an x509 error — and the
real mechanism is stronger than the expected one.**

```
Error from server: Get "https://172.18.0.4:10250/containerLogs/kube-system/kube-proxy-66hvw/kube-proxy?tailLines=1": remote error: tls: internal error
```

(exit code: 1 — same shape on all three nodes, with each node's own IP;
`kubectl top nodes` also fails, `error: Metrics API not available`.)

The apiserver never gets as far as rejecting an untrusted certificate, because
**there is no certificate to reject.** Probed directly on each node before any
approval:

```
$ docker exec <node> sh -c 'echo | openssl s_client -connect localhost:10250 2>/dev/null | openssl x509 -noout -issuer -subject'
Could not find certificate from <stdin>
```

(exit code: 1 on all three.) `serverTLSBootstrap: true` stops the kubelet
self-signing and it has nothing to serve until its CSR is approved — contrast
§4b, where every kubelet served a cert issued by its own ad-hoc CA. So the
window between `kind create` and the approvals is a **hard cluster-wide outage**
of logs/exec/top, not a degradation. Evidence §4b.

```bash
kubectl certificate approve <each kubelet-serving CSR>
kubectl -n kube-system logs <a pod on EVERY node>        # after approving
```

**Purpose:** the positive control, on every node — one node working does not
establish the other two.

**Expected:** all three succeed, exit 0.

**Observed: all four CSRs approved, and logs work on every node.** The same
three commands that had just failed:

```
$ kubectl -n kube-system logs kube-proxy-66hvw --tail=1     # seclab-control-plane
I0730 13:49:11.765540       1 shared_informer.go:356] "Caches are synced" controller="endpoint slice config"
$ kubectl -n kube-system logs kube-proxy-tn8bm --tail=1     # seclab-worker
I0730 13:49:19.320539       1 shared_informer.go:356] "Caches are synced" controller="service config"
$ kubectl -n kube-system logs kube-proxy-jhq54 --tail=1     # seclab-worker2
I0730 13:49:18.963807       1 shared_informer.go:356] "Caches are synced" controller="endpoint slice config"
```

(exit code: 0 each; nothing changed between the two captures except the
approvals.) All three nodes then Ready.

**Two failed approval attempts are recorded in evidence §4c rather than
dropped.** The first selected the CSR names with a Windows `python` one-liner,
which emitted CRLF, and the CR rode into the resource name —
`certificatesigningrequests.certificates.k8s.io "csr-5vgxk\r" not found`
(exit code: 1) on three of four. The second stripped the CR but indexed the
signer as awk `$2`; under `--no-headers` the columns are `NAME AGE SIGNERNAME
...`, so it selected nothing and **exited 0** — the shape of a false pass, and
the reason it is written down. The third, with `$3`, approved all three
remaining CSRs at exit 0.

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

**Observed: every flag landed, and both regression checks pass.** Mechanical
count over the three `ps` captures (full lines in evidence §5a):

| item | count / value |
| --- | --- |
| `--profiling` | 3 |
| `--profiling=false` | 3 |
| `--kubelet-certificate-authority=/etc/kubernetes/pki/ca.crt` | 1 |
| `--enable-admission-plugins` value | `NodeRestriction,AlwaysPullImages` |
| **regression** `--runtime-config=` | 1 — still present |
| **regression** `--enable-hostpath-provisioner=true` | 1 — still present |

(exit code: 0 on all three.) The restatement in §2 **worked, and it was
load-bearing**: evidence §3b shows the patch using *replace* semantics against
kind's block, so without restating them both kind-injected entries would have
been dropped and the rebuild would have silently removed the hostpath
provisioner.

Note the correction §2 needs: the merge semantics question was real, but the
*format* reasoning was not. The patch has to match kind's **v1beta3** render,
not the v1beta4 ConfigMap. See §5's Observed and evidence §3.

```bash
kubectl -n kube-system get cm kubeadm-config -o yaml
```

**Purpose:** confirm the same thing at the source rather than only in `ps`.

**Expected:** the `ClusterConfiguration` carries all four apiServer entries and
both controllerManager entries.

**Observed: all four apiServer entries, both controllerManager entries and the
scheduler entry are present** (exit code: 0) — `enable-admission-plugins`,
`kubelet-certificate-authority`, `profiling`, `runtime-config` on the
apiServer; `enable-hostpath-provisioner` and `profiling` on the controller
manager; `profiling` on the scheduler.

**And the two documents side by side are the whole §2 lesson.** The ConfigMap
kubeadm *stored* is `kubeadm.k8s.io/v1beta4` with `extraArgs` as a **list**;
the file kind *wrote* (`/kind/kubeadm.conf`) is `kubeadm.k8s.io/v1beta3` with
`extraArgs` as a **map**. kubeadm converts on write. Reading the ConfigMap to
decide the patch format — which is what §2 did — reads the output of the
conversion, not its input. Evidence §5b.

```bash
export MSYS_NO_PATHCONV=1
for n in seclab-control-plane seclab-worker seclab-worker2; do
  kubectl get --raw "/api/v1/nodes/$n/proxy/configz"
done
```

**Expected:** `seccompDefault: true`, `podPidsLimit: 4096`,
`serverTLSBootstrap: true` on all three.

**Observed:** all three, on all three nodes (exit code: 0 each).

| field | control-plane | worker | worker2 | before (§4b) |
| --- | --- | --- | --- | --- |
| `seccompDefault` | true | true | true | false |
| `podPidsLimit` | 4096 | 4096 | 4096 | -1 |
| `serverTLSBootstrap` | true | true | true | absent |
| `streamingConnectionIdleTimeout` | "4h0m0s" | "4h0m0s" | "4h0m0s" | "4h0m0s" |
| `tlsCertFile` | **absent** | **absent** | **absent** | `/var/lib/kubelet/pki/kubelet.crt` |
| `tlsPrivateKeyFile` | **absent** | **absent** | **absent** | `/var/lib/kubelet/pki/kubelet.key` |

The kubelet config **file** — which is what kube-bench's 4.2.x checks actually
read — carries `seccompDefault: true` and `podPidsLimit: 4096` on all three
nodes, and carries **neither** `tlsCertFile` nor `tlsPrivateKeyFile`. That is
precisely why 4.2.13 and 4.2.14 can move and 4.2.9 cannot.

**`streamingConnectionIdleTimeout` reproduces the §4b contradiction exactly**:
the file says `0s`, `/configz` says `"4h0m0s"`, on all three nodes of a cluster
built from scratch this morning. So it is not drift and not staleness — it is
how this kubelet behaves. Still not resolved here, still no committed document
edited by this phase. Evidence §5c.

```bash
export MSYS_NO_PATHCONV=1
for n in seclab-control-plane seclab-worker seclab-worker2; do
  docker exec $n sh -c 'echo | openssl s_client -connect localhost:10250 2>/dev/null | openssl x509 -noout -issuer -subject'
done
```

**Purpose:** the ground truth for 4.2.9, which kube-bench will not show.

**Expected:** issuer is the cluster CA on all three, replacing the per-node
`CN=<node>-ca@<epoch>` self-signed issuers recorded in §4b.

**Observed: the issuer flipped to the cluster CA on all three nodes.**

```
issuer=CN=kubernetes
subject=O=system:nodes, CN=system:node:seclab-control-plane
issuer=CN=kubernetes
subject=O=system:nodes, CN=system:node:seclab-worker
issuer=CN=kubernetes
subject=O=system:nodes, CN=system:node:seclab-worker2
```

(exit code: 0 on all three.) And that the issuer really is the cluster CA is
checked rather than inferred — `openssl x509 -in /etc/kubernetes/pki/ca.crt
-noout -subject -issuer` returns `subject=CN=kubernetes` /
`issuer=CN=kubernetes` (exit code: 0).

Before: `CN=seclab-control-plane-ca@1784637412`,
`CN=seclab-worker-ca@1784637429`, `CN=seclab-worker2-ca@1784637429` — three
unrelated self-signed roots. **This is the only evidence 4.2.9 will ever have**,
and §9b confirms the check itself did not move. Evidence §4e.

### 5c. Contingency ladder

Each step: **record honestly, no silent retries.** A failed attempt that is
re-run until it works and only the working run is written down is the exact
fabrication class this repo exists to avoid. Both attempts go in the evidence
file.

- **(i) `kind create` errors on patch syntax.** ~~Add an explicit `apiVersion`
  to the failing patch document — `kubeadm.k8s.io/v1beta4` for the
  ClusterConfiguration patch, `kubelet.config.k8s.io/v1beta1` for the
  KubeletConfiguration patch — and retry.~~ **THIS STEP IS WRONG AND WAS
  CORRECTED BY THE 2026-07-30 DRILL. DO NOT DO IT.** Adding
  `apiVersion: kubeadm.k8s.io/v1beta4` makes the patch match **no document** in
  kind's render, so kind drops the entire patch, `kind create` exits **0**, all
  three nodes go Ready, and the cluster comes up with **none** of the
  apiServer/controllerManager/scheduler remediation. It converts a loud failure
  into a silent one. Observed in full in evidence §3c.

  **Do this instead.** Read the rendered config before changing anything:
  re-run the failing create with `--retain`, then
  `docker exec seclab-control-plane cat /kind/kubeadm.conf`, and write the
  patch in the form that file actually uses. On kind v0.32.0 with this node
  image that is `kubeadm.k8s.io/v1beta3`, where `extraArgs` is a
  `map[string]string`, **not** the v1beta4 name/value list. Leave the
  KubeletConfiguration patch alone — kind's own kubelet document is already
  `kubelet.config.k8s.io/v1beta1` and it merges correctly with no `apiVersion`.

  **And whatever the fix, verify the patch LANDED, not that the create
  succeeded.** A green `kind create` is not evidence. Check
  `/kind/kubeadm.conf`, the `kubeadm-config` ConfigMap, and the `ps` lines —
  §5b does all three, and on the bad path §5b is the only thing that catches it.
  Record **both** the failing and the succeeding attempt, including the verbatim
  error.
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

**Observed: every control came back, and every one was re-probed rather than
assumed from a clean `apply`.** Full transcript in evidence §6.

| # | control | bootstrap | the real probe |
| --- | --- | --- | --- |
| 1 | nginx + `demo` PSA | 4 objects created, rollout OK (0) | hardened curl pod → `200` (0) |
| 2 | RBAC | `rbac/` applied (0) | no token dir in nginx pod (1); can-i matrix yes/yes/yes/no/no/no/no |
| 3 | Kyverno 3.8.2 / v1.18.2 | 4 controllers 1/1, 0 restarts (0) | `policies.kyverno.io/v1` served |
| 4-5 | 4 ValidatingPolicies | Audit → **PASS=4 FAIL=0** gate → Deny, all READY=true (0) | nginx still admits under Deny |
| 6 | nine attacks | — | all 9 denied at exit 1; A–H name their Kyverno policy, I names `PodSecurity "restricted:v1.35"` |
| 7 | supply chain | ivpol READY=true (0); signed-app on `sha256:7fd13d22…` | unsigned-but-real artifact denied (1); fail-closed 404 denied (1); nginx out-of-glob applies (0) |
| 8 | NetworkPolicy | 4 policies, pods stayed Running (0) | `unauth` `HTTP:000 time=5.002283` exit 28; `authorized` `HTTP:200 time=0.002518` exit 0 |
| 9 | `falco` + `cis-benchmark` ns | both from committed manifests (0) | PSA labels as written |

Ordering held: `demo-kyverno-only` and the reports RBAC before the policies (no
policy sat READY=false), Audit before Deny with the PASS=4 gate, and all of
`network/` **after** the admission and supply-chain probes.

One retry is recorded in evidence §6c: the ATTACK I counter-proof first failed
with `error: the path "/tmp/tmp.vubDTd0Drg/attack-hostpath-root.yaml" does not
exist` (exit code: 1) — the MSYS trap in reverse, an MSYS `/tmp` path handed to
a Windows `kubectl.exe` with `MSYS_NO_PATHCONV=1` exported. Re-run with `cd`
plus a relative filename, as phase-2b §3a does.

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

**Observed: all three, and the premise was demonstrated rather than assumed.**
Full transcript in evidence §6f.

The runbook asserts the committed ciphertext cannot be reused. That was
**tested** by applying the old file first against the new controller:

```
$ kubectl get sealedsecret demo-app-secret -n demo
demo-app-secret   no key could decrypt secret (db-password)   False   8s
$ kubectl get secret demo-app-secret -n demo
Error from server (NotFound): secrets "demo-app-secret" not found
```

(exit code: 1 on the Secret; `ErrUnsealFailed` event raised.) The fetched cert
is genuinely new — `notBefore=Jul 30 14:02:39 2026 GMT`.

After re-sealing and re-prepending the header:

- `git diff --numstat` → `1	1` — **exactly one line changed, the ciphertext.**
  32 lines before and after, line 21 still `apiVersion: bitnami.com/v1alpha1`,
  header byte-identical to the block quoted above (`diff` exit code: 0), zero
  CR bytes.
- Applied → `sealedsecret … True`, `secret/demo-app-secret   Opaque   1`
  (exit code: 0); controller log shows two `ErrUnsealFailed` then
  `'Unsealed' SealedSecret unsealed successfully`.
- **Round trip by digest, value never printed:** source
  `2a8d0a93a6387c37cba8af645e0cf275c712f5542c4c8440c703bd057011769c`,
  in-cluster `2a8d0a93a6387c37cba8af645e0cf275c712f5542c4c8440c703bd057011769c`
  — MATCH, and it is the same digest phase 3 recorded.
- **The guard was checked before the greps were believed:** `${#B64}=44`,
  `${#VAL}=31`, both non-empty. Positive control finds the value only in
  `secrets/plain/demo-app-secret-plain.yaml`; all three searches of the
  committed set and of history return **exit code 1, no match**; both paths
  `git check-ignore`d.
- **And the guard was proved load-bearing** by a deliberate negative control:
  `git grep --untracked -n ""` matches **15244 lines and exits 0**. An unset
  variable would have inverted this proof into an apparent clean bill of health.

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

**Observed: driver resolved to `modern_ebpf` with no fallback, and both markers
fired.** Full transcript in evidence §6g.

Install used the verbatim flag set from `clusters/falco-install.md`, all eleven
`--set` flags including `collectors.containerEngine.pluginRef`. DaemonSet 3/3
Running, **0 restarts** on every pod.

Driver proofs, only one of which is Falco's own word:

| check | result |
| --- | --- |
| BTF on all three nodes | `-r--r--r-- 1 root root 6677359 /sys/kernel/btf/vmlinux`, identical on each |
| Falco log | `Opening 'syscall' source with modern BPF probe.` and `/etc/falco/falco_rules.yaml \| schema validation: ok` |
| running pod's own config | `engine:` / `kind: modern_ebpf` |
| kernel module | `NO_FALCO_KMOD_LOADED` on all three nodes |
| BPF objects in Falco PID 1 | 13 `bpf`, 14 `bpf-map`, 197 `bpf-prog` |
| restarts | 0 / 0 / 0 |

The pins held — falcoctl resolved **both** ghcr artifacts by digest
(`falco-rules@sha256:36d143c0…` and `plugins/plugin/container@sha256:f3d531f3…`)
with 2 × `Signature successfully verified`. No floating tag survived.

Detection, against `demo/nginx-78c88678f4-8k5lb` on `seclab-worker`, read from
the co-located sensor `falco-g8d62`:

- `R3-DR-PRIMARY-MARKER` → `14:07:41.306012745: Notice A shell was spawned in a
  container with an attached terminal`, `terminal=34816`, `user_uid=101`,
  `k8s_ns_name=demo`. Window T0 `14:07:40.985619100Z` → T1 `14:07:41.461033300Z`
  — the alert sits inside it.
- `R3-DR-SHM-MARKER` → `14:07:41.640496274: Warning File execution detected from
  /dev/shm`, `evt_res=SUCCESS`, `proc_exepath=/dev/shm/bb`. Window T0
  `14:07:41.494076400Z` → T1 `14:07:41.673850800Z` — inside it. (The exec exited
  127; that is busybox's own `applet not found` **after** it started, and
  `evt_res=SUCCESS` is the independent confirmation the execve worked.)

**One kernel, three sensors** reproduces: the same primary event appears in all
three pods 2.45 ms apart end to end (`.306012745`, `.305097485`, `.303562132`)
and only the co-located one resolves `container_name` / `k8s_*`; the other two
read `<NA>`. Divide every count by three. The log is fresh, so the whole
enumeration is exactly these two lines and both are this drill's. Staged payload
removed afterwards (`cleaned-rc=0`).

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

**Observed:** (exit code: 0 throughout — Job Completed on
`seclab-control-plane`, one DS pod per worker.)

| target | before | predicted | **actual** |
| --- | --- | --- | --- |
| master | 46 / 10 / 50 / 0 | 51 / 6 / 49 / 0 | **51 / 6 / 49 / 0** |
| node, `seclab-worker` | 17 / 2 / 6 / 0 | 19 / 2 / 4 / 0 | **19 / 2 / 4 / 0** |
| node, `seclab-worker2` | 17 / 2 / 6 / 0 | 19 / 2 / 4 / 0 | **19 / 2 / 4 / 0** |

(PASS / FAIL / WARN / INFO.) **Every predicted count is exact on all three
targets.** Report lengths dropped 426→399 and 97→90 lines, which is kube-bench
dropping the remediation-advice blocks for the checks that now pass — see §9b.
Evidence §7a.

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

**Observed: exactly five master status lines and exactly two per worker, and
nothing else moved.**

Master (exit code: 1 — five changes, plus the two count blocks):
`1.2.5` FAIL→PASS, `1.2.11` WARN→PASS, `1.2.15` FAIL→PASS, `1.3.2` FAIL→PASS,
`1.4.1` FAIL→PASS.
Each worker (exit code: 1 — two changes, plus counts; the two workers' diffs
are character-identical): `4.2.13` WARN→PASS, `4.2.14` WARN→PASS.

**`4.2.9` still reads `[WARN]` on both workers.** The §3 prediction holds, and
§5b's `/configz` capture shows the mechanism directly: `tlsCertFile` and
`tlsPrivateKeyFile` are absent from the kubelet config file, which is what the
check reads.

**The stronger assertion, measured rather than eyeballed.** Restricting to
`[STATUS]` lines only, so count lines cannot pad the number: master 10 changed
lines = 5 checks out of 123; each worker 4 changed lines = 2 checks out of 29.
Then masking the checks that were *supposed* to move and re-diffing:

```
$ diff <(before | grep -Ev '^\[[A-Z]+\] (1\.2\.5|1\.2\.11|1\.2\.15|1\.3\.2|1\.4\.1) ') <(after | same)
(exit code: 0 — no output; every OTHER master check is byte-identical)
$ diff <(before | grep -Ev '^\[[A-Z]+\] (4\.2\.13|4\.2\.14) ') <(after | same)
(exit code: 0 on BOTH workers)
```

**The full-text diff is non-empty and every changed line is accounted for**
(exit code: 1 on all three, which §4a predicted):

| target | changed | `ps`/audit detail | status+count | remediation advice |
| --- | --- | --- | --- | --- |
| master | 59 | 14 | 22 | 23, all *removed* |
| worker | 19 | 0 | 12 | 7, all *removed* |
| worker2 | 19 | 0 | 12 | 7, all *removed* |

14+22+23 = 59; 0+12+7 = 19. The third column is kube-bench's own
`== Remediations ==` prose, emitted only for checks that are **not** passing —
**zero were added on any target**; they only disappeared, because the checks now
pass. The `ps` detail is the §4a noise class (new PIDs, new start times,
`--advertise-address` 172.18.0.3 → 172.18.0.4).

**A method failure is recorded because it manufactured a false pass.** The first
decomposition used `grep -P`; this host answers `grep: -P supports only unibyte
and UTF-8 locales`. The failed grep printed nothing, which the arithmetic then
read as "0 unexplained lines". Redone with a literal tab — which is where the
23 / 7 advice lines actually surfaced. Evidence §7b–§7d.

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

**Observed: 8 of 8 predictions HIT, including the one predicted not to move.**
The probe pod was recreated from a manifest proven byte-identical to §4b's
(`diff` exit code: 0) and deleted afterwards.

| check | predicted | actual | verdict |
| --- | --- | --- | --- |
| 1.2.15 / 1.3.2 / 1.4.1 | FAIL → PASS | PASS | HIT ×3 |
| 1.2.5 | FAIL → PASS | PASS | HIT |
| 1.2.11 | WARN → PASS | PASS | HIT |
| 4.2.13 / 4.2.14 | WARN → PASS | PASS | HIT ×2 |
| 4.2.9 | WARN → **WARN** | WARN | HIT |
| master counts | 51 / 6 / 49 / 0 | 51 / 6 / 49 / 0 | HIT |
| node counts ×2 | 19 / 2 / 4 / 0 | 19 / 2 / 4 / 0 | HIT |
| "nothing else moves" | — | held, exit code 0 | HIT |

Ground-truth probes:

| check | probe | before | after |
| --- | --- | --- | --- |
| 1.2.15/1.3.2/1.4.1 | control-plane `ps` | absent ×3 | `--profiling=false` ×3 |
| 1.2.5 | apiserver flag + logs flip | absent / n/a | present / proved on 3 nodes |
| 1.2.11 | probe pod `imagePullPolicy` | `IfNotPresent` | **`Always`** |
| 4.2.14 | probe pod `Seccomp_filters` | 1 | **2** |
| 4.2.9 | serving-cert issuer ×3 | per-node self-signed | **`CN=kubernetes`** |
| 4.2.13 | probe pod `/sys/fs/cgroup/pids.max` | 18999 | **18999 — DID NOT MOVE** |

**THE 4.2.13 PROBE IN THE TABLE ABOVE IS WRONG, AND THE DRILL FOUND OUT WHY.**
The check legitimately passes (`podPidsLimit: 4096` really is in
`/var/lib/kubelet/config.yaml`), but reading `pids.max` from **inside the
container** cannot see it. Mechanism, found not guessed:

- `18999` is systemd's `DefaultTasksMax` inside the kind node —
  `systemctl show --property=DefaultTasksMax` → `DefaultTasksMax=18999`, and
  `threads-max` is `126663`; systemd's default is `15%`, and
  126663 × 0.15 = 18999.45 → 18999. **That also closes §4b's "origin
  undetermined" note**: it is a property of the node image, which is why it
  survived a full rebuild unchanged.
- `4096` is applied one level **up**, on the **pod** cgroup slice. Counted
  across the whole node tree: 22 × `18999` (container scopes), 8 × `max`,
  **7 × `4096` (the pod slices, one per pod on the node)**, 1 × `126663`.
  Pinned to this exact probe pod by its own UID:
  `…/kubelet-kubepods-besteffort-pod46f84866_c2cd_4aac_91c6_708a5115ee98.slice/pids.max`
  = **4096**, while its two `cri-containerd-*.scope` children read `18999`.

cgroup v2 enforces pids limits hierarchically, so 4096 binds the pod regardless.
**The correct probe for 4.2.13 is the pod slice's `pids.max` on the node, not
`cat /sys/fs/cgroup/pids.max` from inside the container.** The "expect 4096" in
the table above is corrected here rather than in §0, which is not edited.

Had the drill accepted "4.2.13 flipped to PASS" as sufficient, the broken probe
would never have been found. The check passing and the probe failing disagreed,
and the disagreement was the finding. Evidence §8a–§8b.

### 9d. Cleanup and whole-lab final state

```bash
kubectl -n cis-benchmark delete job kube-bench-master
kubectl -n cis-benchmark delete ds kube-bench-node-ds
kubectl -n cis-benchmark get jobs,ds,pods
```

**Expected:** `No resources found in cis-benchmark namespace.` Namespace
retained, per the phase-5 convention. Probe pod gone.

**Observed:** as expected.

```
job.batch "kube-bench-master" deleted from cis-benchmark namespace
daemonset.apps "kube-bench-node-ds" deleted from cis-benchmark namespace
$ kubectl -n cis-benchmark get jobs,ds,pods
No resources found in cis-benchmark namespace.
$ kubectl get ns cis-benchmark
cis-benchmark   Active   8m37s
```

(exit code: 0 throughout.) `demo-kyverno-only` is empty, and a cluster-wide
sweep for leftover attack objects returns `NO_LEFTOVER_ATTACK_OBJECTS`
(exit code: 0). Evidence §7e.

Then the whole-lab final state in the phase-6 §5 style: every namespace, every
policy, every DaemonSet and Deployment, with the point being that a cluster
destroyed and rebuilt from git is back to the same posture. **State honestly
what did not come back.** Anything that needed a manual step (the CSR
approvals, the re-seal against a new controller keypair) is not
config-as-code, and the drill's value is partly in naming those.

**Observed: the lab came back.** (exit code: 0 throughout; evidence §7e.)

- 3 nodes `Ready`, all `v1.35.5`.
- All **five** policies `READY=true` — the four `ValidatingPolicy` in `[Deny]`
  plus `require-keyless-signed-ghcr`.
- `demo`: `nginx` 2/2 and `signed-app` 1/1, three pods Running, **0 restarts**,
  both on their pinned digests (`…@sha256:0c79d56a…`, `…@sha256:7fd13d22…`).
- All four NetworkPolicies present; `sealedsecret … True` with its `Secret`
  materialised.
- Falco DaemonSet 3/3 on `falco:0.44.1@sha256:d0cfe422…`.
- Helm: `falco 9.1.0 / 0.44.1`, `kyverno 3.8.2 / v1.18.2`,
  `sealed-secrets 2.19.1 / 0.38.4`.
- Ten namespaces, including `cis-benchmark` and `falco` from their committed
  manifests with their PSA exemptions intact.

**AND WHAT WAS NOT CONFIG-AS-CODE — the part worth more than the green ticks:**

1. **The four CSR approvals.** Done by hand, with `kubectl logs`, `exec` and
   `top` hard-down cluster-wide until they were finished. Nothing in this repo
   automates it and nothing in the cluster auto-approves `kubelet-serving`.
2. **The re-seal.** The controller mints a new RSA keypair on first start, so
   the committed ciphertext was dead on arrival — §7 proves that rather than
   assuming it — and had to be regenerated by hand from a **gitignored**
   plaintext that exists only on this host. If that file were lost the
   credential would not come back from git. The repo protects the secret from
   disclosure; it does not preserve it.
3. **`clusters/kind-config.yaml` itself needed editing mid-drill.** It did not
   build a cluster on the first, second or third attempt (§5). It does now, and
   the fix is committed — but **"rebuilt from git unattended" is not a claim
   this drill earned.** What it does now support is the narrower and more useful
   claim: rebuilt from git, by a human who reads the output, in 27m53s of wall
   clock — `kind delete` at 13:43:20Z, whole-lab final state at 14:11:13Z.
