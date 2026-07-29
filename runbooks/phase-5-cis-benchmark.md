# Runbook — Phase 5: CIS benchmark (kube-bench assessment, nothing enforced)

A replayable command log for the CIS assessment layer: a dedicated
`cis-benchmark` namespace whose PSA exemption is written down rather than
inherited silently, two digest-pinned run-once kube-bench Jobs — one pinned to
the control-plane node for the `master,controlplane,etcd,policies` targets and
one on a worker for the `node` target — a recorded demonstration that the same
scanner spec is REFUSED by `demo`, as a Pod by PSA and as a Job by Kyverno,
and a triage of every FAIL and WARN the run produced, split into kind-inherent,
already-documented and genuinely new. Sections 0-4 are that original run, dated
2026-07-26. Section 5 is an addendum dated 2026-07-29: the `node` target re-run
as a **DaemonSet**, because a Job schedules one Pod and `seclab-worker2` was
therefore never scanned — same digest, same benchmark, one Pod per worker. It
closes a coverage gap and nothing else; the phase still enforces nothing.
Commands are in execution order; each has a one-line purpose and the observed
output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash
unless noted. Kubernetes node image v1.35.5, kube-bench v0.15.6
(`docker.io/aquasec/kube-bench:v0.15.6@sha256:861900910eec...`), CIS config
`cis-1.12`.

**Three honesty caveats, up front — they are part of the deliverable, not
footnotes:**

1. **This phase adds NO ENFORCEMENT. It is an assessment, not a control.**
   Every other phase in this repo ships something that BLOCKS an attack and
   then proves the block. kube-bench blocks nothing. It reads files and
   processes on a node and prints a list. No policy was added, no namespace
   label on `demo` was changed, no apiserver flag was altered, and not one
   finding was remediated. The only thing this phase demonstrates being
   blocked is the scanner itself — by PSA and Kyverno, both of which already
   existed. A reader who takes "kube-bench ran" as "the cluster was hardened"
   has read it exactly backwards, and the README/threat-model wording must not
   put this phase in an "attack it blocks" or "enforced scope" column.
2. **A CIS benchmark on kind is a TEACHING artifact, not a compliance
   result.** kind is not a production cluster: its three "nodes" are
   containers on one shared WSL2 kernel, its control-plane components are
   kubeadm static pods, and the large majority of the PASSes are kubeadm's
   defaults rather than decisions this lab made — the point threat model §6.8
   already concedes about `NodeRestriction` and `Node,RBAC`. Scores do not
   transfer to any other cluster and this is not an audit.
3. **A kube-bench PASS is not proof of compliance.** Section 3 records a check
   that reports PASS while the live configuration is exactly what the check
   forbids, caused by a string-versus-integer comparison in the benchmark
   config. One PASS was audited and found wrong; the other 62 were not each
   re-checked. The defensible figure is "63 checks kube-bench scored as
   passing", never "63 controls verified compliant".

---

## 0. The assessment — and why it is not a control

This section is the house's `## 0. The controls`. It is retitled because there
are no new controls in this phase, and naming a section for something it does
not contain is the exact failure mode this repo is built to avoid.

- **kube-bench v0.15.6, run as two `batch/v1` Jobs** —
  `docs/evidence/phase-5-cis/job-kube-bench-master.yaml` and
  `job-kube-bench-node.yaml`. Each runs once, prints a report, and exits 0.
  **What it does:** stats node-local files (static pod manifests, kubeconfigs,
  the etcd data directory, the kubelet unit and `config.yaml`) and reads live
  component flags out of `ps` in the host PID namespace, then compares what it
  finds against the CIS Kubernetes Benchmark. **What it does NOT do:** change
  anything, watch anything, or run again. It is point-in-time and on-demand.
- **A dedicated `cis-benchmark` namespace** —
  `docs/evidence/phase-5-cis/00-namespace-cis-benchmark.yaml`, carrying
  `enforce: privileged`, `warn: restricted`, `audit: restricted`. **Why it is
  needed:** see section 1. The exemption is labelled so it is greppable rather
  than inherited from an unlabelled namespace's built-in default.
- **The two rejection probes** — `rejected-in-demo-pod.yaml` and
  `rejected-in-demo-job.yaml`, the same scanner spec aimed at `demo`. These
  are the only adversarial-shaped objects in the phase, and neither is ever
  persisted.

### What a CIS benchmark does and does not tell you

It tells you how a cluster's **configuration** compares to a published list of
recommendations, on the one node the scanner happened to land on, at one
instant. It does not tell you whether the cluster is secure, whether its
workloads are hardened, or whether any of its policies work — those are
separate claims that need separate evidence, and in this repo they live in
phases 2a, 2b, 2c, 3 and 4. It is also neither preventive nor detective:
threat model §6.2 notes every control in this lab is preventive and none is
detective, and a benchmark that is run by hand twice is neither. Nothing
schedules it, nothing alerts on it, and nothing re-runs it when the cluster
changes.

Two specific over-claims to refuse. First, the `policies` target (CIS section
5) is effectively unassessed here — all 34 of its checks WARN, for the reasons
in section 3 — so this run corroborates **nothing** about the lab's RBAC,
admission, NetworkPolicy or secrets posture in either direction. Second, a Job
produces one Pod, so `seclab-worker2` was never scanned at all. That second
gap was closed 2026-07-29 by the DaemonSet run in section 5 — both workers now
have kube-bench `node` reports (evidence section 8); the first over-claim
stands unchanged, because nothing about the `policies` target was re-run.

### The benchmark is pinned — the "default version 1.18" warning is cosmetic

Both Jobs run `--benchmark cis-1.12` and `--v=1`. The `--v=1` is not
decoration: it makes kube-bench name, in its own output, the benchmark and the
exact config files it loaded, so the report is self-proving on this point
instead of asking a reader to trust a paragraph.

```bash
kubectl -n cis-benchmark get job kube-bench-master -o jsonpath='{.spec.template.spec.containers[0].command}'
# ["kube-bench","run","--v=1","--benchmark","cis-1.12","--targets","master,controlplane,etcd,policies","--include-test-output"]
```

Every run prints a warning that it could not auto-detect the Kubernetes
version and is "Assuming default version 1.18". Read the next three lines with
it:

```bash
# Warning: Kubernetes version was not auto-detected ... Assuming default version 1.18
# util.go:395] Unable to get Kubernetes version from kubectl, using default version: 1.18
# common.go:351] Kubernetes version: "" to Benchmark version: "cis-1.12"
# common.go:274] Using config file: cfg/cis-1.12/config.yaml
# => the kube version is the EMPTY STRING at the point the benchmark resolves.
#    The detected 1.18 was never consulted.
```

The warning comes from `getPlatformInfo()`, which Go evaluates as an argument
before `getBenchmarkVersion` runs, unconditionally; its `kubectl` probe fails
because these Jobs set `automountServiceAccountToken: false` and hold no API
credentials. `getBenchmarkVersion` only consults a detected version inside
`if isEmpty(benchmarkVersion)`, and `--benchmark cis-1.12` never enters that
branch. The falsifiable check is upstream's own mapping:

```bash
gh api repos/aquasecurity/kube-bench/contents/cfg/config.yaml?ref=v0.15.6 --jq .content \
  | base64 -d | sed -n '/version_mapping/,/target_mapping/p'
#   "1.18": "cis-1.6"
#   ...
#   "1.32": "cis-1.12"
#   "1.33": "cis-1.12"
#   "1.34": "cis-1.12"
# => 1.18 maps to cis-1.6, and the run demonstrably loaded cfg/cis-1.12/*.
#    Mutually exclusive, so the pin held and the warning is cosmetic.
```

**And the caveat that mapping exposes:** the highest Kubernetes entry is
`"1.34"`, and this cluster is v1.35.5. `cis-1.12` is the newest generic CIS
config kube-bench v0.15.6 ships, so it is the closest available match — but it
is being applied **one minor version ahead** of the newest release its authors
mapped it to. Do not write "cis-1.12 is the CIS benchmark for Kubernetes
1.35". It is not.

### What a WARN means — two different things, printed identically

kube-bench prints `[WARN]` both for "I ran this check and it did not pass" and
for "I never evaluated this check at all", with nothing in the output
distinguishing them. Of the 56 WARNs in this run, **38 were never evaluated**.
The split, and why it matters, is in section 3.

---

## 1. Where it runs — which control refuses the scanner depends on the object

kube-bench needs `hostPID: true` and `hostPath` mounts of `/etc/kubernetes`,
`/var/lib/etcd`, `/var/lib/kubelet`, `/var/lib/cni`, `/etc/systemd`,
`/lib/systemd`, `/etc/passwd` and `/etc/group`. Pointed at `demo` it is
refused both times below — but **by a different control each time, decided by
which object is submitted**, and that difference is the most interesting thing
in the phase. A bare **Pod** is denied outright by PSA `enforce: restricted`,
which names hostPID, hostPath and root (1a). The **Job** — the form this
phase actually ships — gets past PSA with a warning only, because PSA
enforcement is evaluated against Pods and not against Jobs, and is stopped
instead by Kyverno for an unrelated reason: the image registry (1b).

Nothing was admitted either way, so this is not a gap in the cluster. It is a
gap in the sentence "the restricted profile refuses the scanner", which is
true only of the Pod form; written of the Job it names the wrong control.
Both denials are correct behaviour, not bugs, and both are captured rather
than routed around.

Applied with `--server-side --dry-run=server`, never a plain
`--dry-run=server`: against an UNCHANGED object the plain form computes an
empty patch client-side and issues only a GET, so it never reaches admission
and proves nothing (traced with `-v=8` in `runbooks/phase-4-supply-chain.md`
section 3a). Server-side apply always sends the PATCH with `dryRun=All`, so
the request traverses the whole admission chain and the apiserver discards the
result.

**1a. POD PATH — the object PSA actually evaluates.**

```bash
kubectl apply --server-side --dry-run=server -f docs/evidence/phase-5-cis/rejected-in-demo-pod.yaml
# Error from server (Forbidden): pods "kube-bench-master-pod" is forbidden:
# violates PodSecurity "restricted:v1.35": host namespaces (hostPID=true),
# restricted volume types (volumes "etc-kubernetes", "var-lib-etcd", ... use
# restricted volume type "hostPath"), runAsNonRoot != true (... must set
# securityContext.runAsNonRoot=true), runAsUser=0 (container "kube-bench" must
# not set runAsUser=0)                                                (exit 1)
```

Note `restricted:v1.35` — the PINNED enforce version from the namespace label.
That is what distinguishes an ENFORCE denial from the `restricted:latest`
string the warn label emits, and reading it is how you tell which label
answered.

**1b. JOB PATH — the same spec, and the answer changes.** First confirm the
probe really is the real Job with only the namespace altered, so the
comparison is checked rather than asserted:

```bash
cd docs/evidence/phase-5-cis
diff <(grep -v '^\s*#' job-kube-bench-master.yaml | grep -v '^\s*$') \
     <(grep -v '^\s*#' rejected-in-demo-job.yaml   | grep -v '^\s*$')
# 5c5
# <   namespace: cis-benchmark
# ---
# >   namespace: demo                                                 (exit 1)
```

```bash
kubectl apply --server-side --dry-run=server -f docs/evidence/phase-5-cis/rejected-in-demo-job.yaml
# Warning: would violate PodSecurity "restricted:latest": host namespaces
# (hostPID=true), restricted volume types (...), runAsNonRoot != true, runAsUser=0
# Error from server: admission webhook "vpol.validate.kyverno.svc-fail" denied
# the request: Policy restrict-registries failed: Image registry not allowed:
# every container ... must use an image from Docker Hub nginxinc/* or
# curlimages/*, or ghcr.io/joesevv/k8s-security-lab/*.                (exit 1)
```

**Read which control answered, do not assume it.** Two things changed at the
Job level. PodSecurity only WARNED — `restricted:latest`, the warn label, not
the enforce one — and would have admitted: PSA enforcement is evaluated
against **Pods**, and against a `batch/v1` Job it warns and admits. With PSA
alone the Job object would exist and then never produce a Pod, the rejection
surfacing only in Job controller events, which is a silent failure instead of
a loud one. And the actual denial came from **Kyverno**, for **registry**, not
for hostPID or hostPath: `docker.io/aquasec/*` is outside the allow-list.
Writing "Kyverno blocks kube-bench because it is privileged" would exceed
enforced reality — **no `ValidatingPolicy` in `policies/` covers `hostPath` or
`hostPID` at all.** PSA is what closes that gap, exactly as in phase 2b.

**1c. CONSEQUENCE — the namespace choice, and the residual risk it makes
concrete.** The scanner has to run somewhere without restricted enforcement.
Three options, and the reasoning is written down because the choice is
content:

- `demo` — impossible: the Pod is denied by PSA (1a) and the Job by Kyverno
  (1b). Correct behaviour in both forms.
- `demo-kyverno-only` — PSA is warn-only there, so the Pod would be ADMITTED
  (no `ValidatingPolicy` covers `hostPath`/`hostPID`;
  `runbooks/phase-2b-admission.md` states this). But the four Kyverno policies
  DO select that namespace and `restrict-registries` would deny the Job, as 1b
  shows.
- A dedicated, labelled `cis-benchmark` namespace — chosen. All five Kyverno
  policies are scoped by `namespaceSelector` to `[demo, demo-kyverno-only]`
  only, so none of them evaluates anything here, and PSA is set to
  `enforce: privileged`.

```bash
kubectl get ns cis-benchmark --show-labels
# NAME            STATUS   AGE   LABELS
# cis-benchmark   Active   15h   app.kubernetes.io/part-of=k8s-security-lab,
#   kubernetes.io/metadata.name=cis-benchmark,
#   pod-security.kubernetes.io/audit=restricted,
#   pod-security.kubernetes.io/enforce=privileged,
#   pod-security.kubernetes.io/warn=restricted
```

**Nothing in that namespace is gated by admission. That is threat model §6.7's
already-conceded residual risk, and this namespace is a concrete instance of
it.** An unlabelled namespace on this cluster already behaves this way — the
apiserver has no `--admission-control-config-file`, so the PodSecurity plugin
falls back to its built-in privileged default. Labelling changes nothing about
enforcement; it makes the exemption reviewable instead of implicit. The
`audit: restricted` label is honest bookkeeping only: audit annotations go to
the API server audit log, and this cluster has no audit logging (§6.2, and
kube-bench's own 1.2.16-1.2.19 findings confirm it).

**1d. Nothing was persisted.** Both probes above are dry runs, as is the third
one in the transcript (the node Job spec pointed at `demo`, kept as a scratch
copy because it exists only to show a second Kyverno policy firing):

```bash
kubectl -n demo get jobs,pods
# pod/nginx-775678cbbd-mmrxb        1/1   Running
# pod/nginx-775678cbbd-q7ddt        1/1   Running
# pod/signed-app-5d4c4ffff4-vrtps   1/1   Running
# (three workload pods, zero jobs, no kube-bench object)               (exit 0)
```

The 1a and 1b captures were taken 2026-07-26, re-run 2026-07-28 and again
2026-07-29 across two host reboots; the output is byte-identical all three
times.

---

## 2. Running it

The namespace first, then both Jobs. Every apply prints the exact
restricted-profile violations the scanner commits, because the namespace
carries `warn: restricted` — **that warning is part of the deliverable, not
noise to be suppressed.**

```bash
kubectl apply -f docs/evidence/phase-5-cis/00-namespace-cis-benchmark.yaml
# namespace/cis-benchmark unchanged                                    (exit 0)

kubectl apply -f docs/evidence/phase-5-cis/job-kube-bench-master.yaml
# Warning: would violate PodSecurity "restricted:latest": host namespaces
# (hostPID=true), restricted volume types (volumes "etc-kubernetes",
# "var-lib-etcd", ...), runAsNonRoot != true, runAsUser=0
# job.batch/kube-bench-master created                                  (exit 0)

kubectl apply -f docs/evidence/phase-5-cis/job-kube-bench-node.yaml
# Warning: would violate PodSecurity "restricted:latest": host namespaces
# (hostPID=true), unrestricted capabilities (container "kube-bench" must not
# include "DAC_READ_SEARCH" in securityContext.capabilities.add), ...
# job.batch/kube-bench-node created                                    (exit 0)

kubectl -n cis-benchmark wait --for=condition=complete job/kube-bench-master --timeout=300s
# job.batch/kube-bench-master condition met                            (exit 0)
kubectl -n cis-benchmark wait --for=condition=complete job/kube-bench-node --timeout=300s
# job.batch/kube-bench-node condition met                              (exit 0)
```

**Placement is checked, not assumed.** If the master Job did not land on
`seclab-control-plane`, its 1.x and 2.x findings would be a scan of a machine
with no control plane on it — fabricated results, not findings. The Job pins
itself with a `nodeSelector` on `node-role.kubernetes.io/control-plane` plus a
toleration for that node's single `NoSchedule` taint:

```bash
kubectl -n cis-benchmark get pod -l app.kubernetes.io/component=cis-benchmark \
  -o custom-columns='POD:.metadata.name,NODE:.spec.nodeName,PHASE:.status.phase,IMAGE_ID:.status.containerStatuses[0].imageID'
# POD                       NODE                   PHASE       IMAGE_ID
# kube-bench-master-fr4dk   seclab-control-plane   Succeeded   docker.io/aquasec/kube-bench@sha256:861900910eec...
# kube-bench-node-cmwb8     seclab-worker          Succeeded   docker.io/aquasec/kube-bench@sha256:861900910eec...

# The same question asked of the 2026-07-29 DaemonSet run (section 5). Two rows,
# one per worker, is the whole point of that run:
kubectl -n cis-benchmark get pods -l app.kubernetes.io/name=kube-bench-node-ds \
  -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,STATUS:.status.phase
# NAME                       NODE             STATUS
# kube-bench-node-ds-6nhfh   seclab-worker    Running
# kube-bench-node-ds-vm7cw   seclab-worker2   Running
```

**A Job produces ONE Pod, so `seclab-worker2` was never scanned.** Stated here
rather than left for a reader to work out. Covering every worker needs a
DaemonSet, which this phase does not ship. **Closed 2026-07-29:** that
DaemonSet now exists — `docs/evidence/phase-5-cis/daemonset-kube-bench-node.yaml`
— and it ran, so both workers have kube-bench `node` reports. Method in
section 5, full captures in evidence section 8. The sentence above is left
standing because it is true of the 2026-07-26 Job run it describes.

The two Jobs differ in one privilege, and the asymmetry is deliberate rather
than an oversight:

```bash
kubectl -n cis-benchmark get pod \
  -o jsonpath='{range .items[*]}{.metadata.name}{"  drop="}{.spec.containers[0].securityContext.capabilities.drop}{"  add="}{.spec.containers[0].securityContext.capabilities.add}{"\n"}{end}'
# kube-bench-master-fr4dk  drop=["ALL"]  add=
# kube-bench-node-cmwb8    drop=["ALL"]  add=["DAC_READ_SEARCH"]
```

The kind node image ships `/etc/systemd/system/kubelet.service.d` as a
directory with mode `0644` — **no execute bit** — so with `drop: [ALL]` even
uid 0 cannot traverse into it and the `node` target dies on a `permission
denied` stat. `CAP_DAC_READ_SEARCH` is the minimum that fixes it: it bypasses
read permission on files and read-plus-search on directories, and unlike
`CAP_DAC_OVERRIDE` it does not bypass write. The master Job needs none of this
— none of its four targets reads a path behind such a directory — so it is
withheld there rather than granted for symmetry.

Then read the reports:

```bash
kubectl -n cis-benchmark logs job/kube-bench-master
kubectl -n cis-benchmark logs job/kube-bench-node
# both exit 0
```

Both containers exit 0 **with FAILs in the report**, because `--exit-code` is
left at its default and `backoffLimit: 0` is set. That is deliberate: findings
belong in a committed transcript, not in a `BackoffLimitExceeded` loop. A zero
exit here means "the scanner ran", not "the cluster passed".

---

## 3. Reading the report — the triage methodology, and one false PASS

The raw counts, which are kube-bench's own summary lines added together:

| Job | PASS | FAIL | WARN | INFO |
| --- | --- | --- | --- | --- |
| master (`master,controlplane,etcd,policies`) | 46 | 10 | 50 | 0 |
| node (`node`) | 17 | 2 | 6 | 0 |
| combined | 63 | 12 | 56 | 0 |

That table is the 2026-07-26 Job run and is left exactly as it was. The
`node` target was re-run on 2026-07-29 as a DaemonSet (section 5), which
produces a report **per worker** rather than one report from whichever worker
the scheduler picked:

| Run | Node | PASS | FAIL | WARN | INFO |
| --- | --- | --- | --- | --- | --- |
| Job, 2026-07-26 | `seclab-worker` | 17 | 2 | 6 | 0 |
| DaemonSet, 2026-07-29 | `seclab-worker` | 17 | 2 | 6 | 0 |
| DaemonSet, 2026-07-29 | `seclab-worker2` | 17 | 2 | 6 | 0 |

Each node matches the 2026-07-26 node Job exactly, **as of 2026-07-29 on this
cluster** — and the match is stronger than the counts: strip the glog
timestamp lines and each DaemonSet report is byte-identical to the Job's,
checked with `diff` in evidence section 8f. The combined 63 / 12 / 56 is
deliberately **not** restated to include `seclab-worker2`: adding a second copy
of the same worker configuration would inflate PASS by 17 for no new
information. What the DaemonSet bought is coverage, not new findings.

**Do not read those numbers at face value.** Two corrections apply before the
triage in 3c, and between them they are what the phase is actually for.

**3a. 38 of the 56 WARNs are not findings in either direction.** kube-bench
emits WARN for two completely different reasons and prints them identically.
Classified mechanically against `cfg/cis-1.12/*.yaml` at upstream tag
`v0.15.6`, by asking of each check id whether it has an audit command at all
and whether that command shells out to `kubectl`:

| WARN reason | Count | Which |
| --- | --- | --- |
| `type: "manual"` with NO audit command — kube-bench never evaluates these, it prints WARN plus remediation text unconditionally | 27 | 3.1.1-3.1.3, 3.2.2, and 23 of section 5 |
| audit shells out to `kubectl`, which cannot reach the API because the Job sets `automountServiceAccountToken: false` — produces no output, so the check WARNs | 11 | 5.1.1-5.1.6, 5.2.2-5.2.6 |
| audit ran locally and did not pass — REAL results, reported as WARN rather than FAIL only because the check carries `scored: false` | 18 | see 3c |

So **12 FAIL + 18 WARN = 30 checks were evaluated and did not pass**, and 38
were not assessed at all.

**The trap this avoids would have inverted the truth.** 5.2.1 "Ensure that the
cluster has at least one active policy control mechanism in place" WARNs — and
this cluster runs BOTH PSA `enforce: restricted` on `demo` AND five Kyverno
policies in Deny. 5.2.3 (hostPID) and 5.2.11 (hostPath volumes) also WARN,
while section 1 above shows PSA denying exactly those two things by name.
Reading section 5's WARNs as failures would state the opposite of what this
cluster enforces. They mean "not assessed".

**3b. At least one PASS is wrong.** Found by auditing the report against the
live node configuration instead of reading the report alone:

```bash
for n in seclab-control-plane seclab-worker seclab-worker2; do
  docker exec $n grep -E "^streamingConnectionIdleTimeout" /var/lib/kubelet/config.yaml
done
# streamingConnectionIdleTimeout: 0s
# streamingConnectionIdleTimeout: 0s
# streamingConnectionIdleTimeout: 0s
# => but the report says: [PASS] 4.2.5 Ensure that the
#    --streaming-connection-idle-timeout argument is not set to 0 (Manual)
```

`cfg/cis-1.12/node.yaml` compares `{.streamingConnectionIdleTimeout}` with
`compare: {op: noteq, value: 0}` under a `bin_op: or`. The configured value is
the **string** `"0s"`, a Go duration; `"0s" != "0"` is true, so the first test
item passes and the or-clause short-circuits to PASS. And because
`--include-test-output` prints observed values only for NON-passing checks,
the value never appears in the transcript, so a reader cannot catch this from
the report alone.

Two separate things follow, and only one of them is about tooling.

- **The methodological point.** A kube-bench PASS is not proof of compliance.
  This one is an artifact of a string-versus-integer comparison, which is why
  the defensible figure is "63 checks kube-bench scored as passing".
- **The finding.** `0s` is the live value on all three nodes, and `0s`
  disables the timeout entirely: idle `exec`, `attach` and `port-forward`
  streams are never reaped, so a session left open holds a kubelet stream
  indefinitely. That is a real open gap on this cluster, and it is NOT
  remediated. It sits outside the 30 evaluated non-passing checks triaged in
  3c only because kube-bench scored it PASS.

**Where `0s` came from is UNVERIFIED.** The working note behind this phase
asserts it is kind's doing and that kubeadm defaults to `4h0m0s`, but no
command was ever run to establish either half, and this is the one triage
input in the phase with no probe behind it. It is recorded as unverified
rather than repeated as fact. It would also not change the finding if it were
true: this phase keeps 4.1.1 / 4.1.9 and 1.1.12 as real findings precisely
because "it is the installer's default" is not a defence, and the same
standard applies here.

**3c. The triage.** Every one of the 30 evaluated non-passing checks is
classified in the evidence file, in three buckets, undocumented first because
that is the only part that is new information:

| Bucket | Count | Contents |
| --- | --- | --- |
| **Real, NOT previously documented** | 20 | 1.2.5 (no `--kubelet-certificate-authority`) and 4.2.9 (kubelet serves a self-signed cert) are the loudest and are two halves of one gap; 1.2.1 anonymous auth, confirmed by observation not inference; 1.2.30, 4.2.14 (no `seccompDefault`), 4.2.13 (no `podPidsLimit`), 1.2.11 (`AlwaysPullImages`), 1.2.15 / 1.3.2 / 1.4.1 (`--profiling`), 1.2.9, 4.1.1 / 4.1.9 (mode 644 want 600) and 1.1.9, the same class but found by probe rather than by the scanner, 1.1.12, 1.2.3, 1.2.29, 4.2.12, and two weak ones kept honest rather than flattered away, 1.2.20 and 1.3.1 |
| **Real, ALREADY documented** | 7 | 1.2.16-1.2.19 and 3.2.1 → threat model §6.2, no audit logging; 1.2.27 and 1.2.28 → §6.1, no encryption at rest for etcd. The scanner independently rediscovering two written concessions is corroboration that they are real |
| **Kind-inherent, not findings** | 3 | 1.1.10 (CNI ownership) and 4.1.3 / 4.1.4 (proxy kubeconfig). In all three the WARN is for ABSENCE OF DATA, not a bad value. This bucket held four until a probe moved 1.1.9 out of it |

Each classification was turned from a guess into an observation by a probe,
run read-only against the live nodes. "That's just kind" is exactly the excuse
that hides real gaps, so the two buckets that lean on it were checked hardest:

```bash
docker exec seclab-control-plane sh -c 'ls -la /var/lib/cni; ls -la /var/lib/cni/networks; ps -ef | grep kubele[t] | grep -o -- "--cni-conf-dir[= ][^ ]*"'
# drwx------  2 root root 4096 ... results
# ls: cannot access '/var/lib/cni/networks': No such file or directory
# (flag absent)
# => 1.1.9/1.1.10: both of kube-bench's audit branches emit nothing, so both
#    WARN for absence of data. That is a fact about the SCANNER, and taking
#    it as the answer is what mis-triaged 1.1.9 — see the next probe.

for n in seclab-control-plane seclab-worker seclab-worker2; do
  docker exec $n stat -c "%a %U:%G %n" /etc/cni/net.d /etc/cni/net.d/10-kindnet.conflist
done
# 700 root:root /etc/cni/net.d
# 644 root:root /etc/cni/net.d/10-kindnet.conflist      (identical on all 3)
# => THE TWO CHECKS SPLIT. 1.1.9 is a REAL finding, not kind-inherent: its
#    audit never read the CNI config kind actually uses, and a direct stat
#    shows mode 644 where CIS wants 600, on every node. Low, because the
#    containing directory is 700 root:root and the file holds no
#    credentials. This is a SECOND DEFECTIVE AUDIT beside 3b's false PASS —
#    there the tool scored a bad value it read, here it warned without ever
#    reading the value. 1.1.10 stays kind-inherent: the file is root:root,
#    which is exactly what that check wants.

docker exec seclab-worker sh -c 'ls -l /etc/kubernetes/proxy.conf; ps -ef | grep kube-prox[y]'
# ls: cannot access '/etc/kubernetes/proxy.conf': No such file or directory
# root  766  544  0 13:09 ?  00:00:00 /usr/local/bin/kube-proxy --config=/var/lib/kube-proxy/config.conf --hostname-override=seclab-worker
# => 4.1.3/4.1.4: the check text begins "If proxy kubeconfig file exists".
#    kubeadm/kind run kube-proxy as a DaemonSet from a ConfigMap. WARN for absence.
```

Two more findings the probes moved OUT of "kind's fault", which is the
direction that matters:

```bash
docker exec seclab-control-plane stat -c "%a %U:%G %n" /var/lib/etcd
# 700 root:root /var/lib/etcd
# => 1.1.12 wants etcd:etcd. kubeadm runs etcd as a root static pod and creates
#    no `etcd` OS user, so this reads root:root on ANY kubeadm cluster, not just
#    kind. Small consequence, because 1.1.11 PASSES at mode 700.

docker exec seclab-worker2 sh -c 'stat -c "%a %U:%G %n" /var/lib/kubelet/config.yaml /etc/systemd/system/kubelet.service.d/10-kubeadm.conf'
# 644 root:root /var/lib/kubelet/config.yaml
# 644 root:root /etc/systemd/system/kubelet.service.d/10-kubeadm.conf
# => 4.1.1/4.1.9 are kubeadm defaults, real, and present on the worker
#    kube-bench never scanned. Confirmed by hand, which is not a kube-bench result.
#    Since 2026-07-29 there IS a kube-bench result for that worker: the DaemonSet
#    run in section 5 reports the same two FAILs on seclab-worker2 (evidence
#    section 8e). The hand check above stays a hand check — it is not promoted
#    retroactively; it is now corroborated by scanner output taken on that node.
```

And the one finding tested rather than inferred from a missing flag:

```bash
SRV=$(kubectl config view --minify -o jsonpath='{.clusters[0].cluster.server}')
for p in /version /healthz /api/v1/secrets; do
  printf '%s -> HTTP ' "$p"; curl -sk -o /dev/null -w '%{http_code}\n' "$SRV$p"
done
# /version          -> HTTP 200
# /healthz          -> HTTP 200
# /api/v1/secrets   -> HTTP 403
# => 1.2.1: anonymous access is enabled and WORKS. An unauthenticated caller
#    gets gitVersion, gitCommit and buildDate — a clean fingerprint for CVE
#    matching. BOUNDED: RBAC still refuses real resources, so this is
#    information disclosure, not access.
```

**Nothing above was remediated.** Threat model §6.3 concedes "no CIS
remediation"; running the scanner does not discharge that concession, it only
itemises it. The honest amendment §6.3 earns is that kube-bench now reports
against CIS and the findings are recorded rather than unknown — not that the
gap is closed.

Full verbatim captures — both complete reports, the demo-namespace rejection,
the five ground-truth probes, the false PASS and the classification of every
FAIL and WARN: `docs/evidence/phase-5-cis/attack-output.txt`. That file is
named for the house convention and for the three manifests in the directory
that already reference it; its preamble says plainly that it is an assessment,
not an attack.

---

## 4. Teardown

The two Jobs and their Pods are deleted; their reports survive only in the
committed transcript, which is the point of committing it. The namespace is
**kept**, because the committed manifests define it and the phase should stay
re-appliable with `kubectl apply -f docs/evidence/phase-5-cis/`.

```bash
kubectl -n cis-benchmark delete job kube-bench-master kube-bench-node
# job.batch "kube-bench-master" deleted from cis-benchmark namespace
# job.batch "kube-bench-node" deleted from cis-benchmark namespace     (exit 0)

kubectl -n cis-benchmark get jobs,pods
# No resources found in cis-benchmark namespace.                       (exit 0)
kubectl get jobs -A
# No resources found                        (no Job anywhere on the cluster)
```

Nothing to tear down from section 1: every probe was a dry run, and every one
of them was rejected at admission anyway, so no scanner Pod or Job ever
existed in `demo`. Confirm the rest of the lab is exactly as it was — an
assessment that changed something would be a failed assessment:

```bash
kubectl -n demo get deploy
# nginx        2/2   2   2
# signed-app   1/1   1   1

kubectl get validatingpolicy,imagevalidatingpolicy
# disallow-latest-and-bare-tag     true
# disallow-privileged-containers   true
# require-drop-all-capabilities    true
# restrict-registries              true
# require-keyless-signed-ghcr      true          (all five still READY=true)

kubectl get nodes
# seclab-control-plane   Ready   control-plane   v1.35.5
# seclab-worker          Ready   <none>          v1.35.5
# seclab-worker2         Ready   <none>          v1.35.5
```

To remove the layer entirely (**not done for the lab** — the namespace is what
makes the phase re-runnable, and deleting it deletes the written-down PSA
exemption along with it):

```bash
kubectl delete -f docs/evidence/phase-5-cis/00-namespace-cis-benchmark.yaml
```

The namespace manifest is named explicitly rather than using
`kubectl delete -f docs/evidence/phase-5-cis/`, which would also read the other
five manifests in that directory — the two Job manifests and the DaemonSet
(the Jobs deleted here, the DaemonSet deleted in section 5's cleanup) and the
two rejection probes (which never existed in `demo`, because that is the whole
point of section 1) — and report NotFound for all five. Ordering matters while
section 5 is mid-run: with the DaemonSet still applied, that directory-wide
delete would really delete it rather than print NotFound, which is why section
5 tears its own object down explicitly.

---

## 5. Scanning every worker — the DaemonSet run (2026-07-29)

Placed after the teardown because that is execution order: this ran on
2026-07-29, after section 4 had already deleted both Jobs, as an addendum to
the phase rather than part of the original run. It closes exactly one thing —
**coverage** — and adds no
control, no policy and no remediation. A DaemonSet full of scanners still
enforces nothing.

**Why a DaemonSet.** A Job schedules ONE Pod, so on 2026-07-26 the `node`
target assessed whichever worker the scheduler picked (`seclab-worker`) and
`seclab-worker2` was never scanned by kube-bench at all. A DaemonSet schedules
one Pod per eligible node, so coverage stops depending on that choice.

**The manifest is the Job's spec** —
`docs/evidence/phase-5-cis/daemonset-kube-bench-node.yaml`: same digest-pinned
image, same `--v=1 --benchmark cis-1.12 --targets node --include-test-output`,
same `hostPID: true`, same `automountServiceAccountToken: false`, the same six
read-only `hostPath` mounts with explicit types, the same
`drop: [ALL]` + `add: [DAC_READ_SEARCH]`. Four differences, and they are shown
with `diff` rather than asserted (evidence section 8b):

1. `kind: DaemonSet` and the name `kube-bench-node-ds`.
2. A `selector`, plus the third label `app.kubernetes.io/name:
   kube-bench-node-ds` it matches on; `backoffLimit: 0` has no DaemonSet
   equivalent and is gone.
3. `restartPolicy: Always` — a DaemonSet template accepts no other value
   (`ValidateDaemonSetSpec`, kubernetes/kubernetes at tag `v1.35.5`).
4. The scan wrapped in a shell that holds the Pod open afterwards, which
   follows from (3): kube-bench exits when it is done, the kubelet restarts an
   exited container, and an unwrapped Pod would rescan-and-exit into
   `CrashLoopBackOff` with each report stranded in a discarded container log.
   The hold is `while true; do sleep 3600; done` rather than `sleep infinity`
   because `infinity` is a GNU coreutils extension BusyBox's `sleep` rejects,
   and which of the two this image ships was not tested.

**Still no `nodeSelector` and no toleration**, deliberately. The
`node-role.kubernetes.io/control-plane:NoSchedule` taint keeps the DaemonSet
off `seclab-control-plane`, which is the intent: `--targets node` is the
worker-node benchmark, and the control-plane machine is assessed by the master
Job against its own targets.

```bash
kubectl apply -f docs/evidence/phase-5-cis/daemonset-kube-bench-node.yaml
# Warning: would violate PodSecurity "restricted:latest": host namespaces
# (hostPID=true), unrestricted capabilities (container "kube-bench" must not
# include "DAC_READ_SEARCH" in securityContext.capabilities.add), restricted
# volume types (...), runAsNonRoot != true, runAsUser=0
# daemonset.apps/kube-bench-node-ds created                            (exit 0)

# The warning is character-for-character the one the node Job drew on
# 2026-07-26. Printed rather than asserted — both lines live in the evidence
# file, so they are diffed where they sit (line 163 is the Job's, line 1376 the
# DaemonSet's):
diff <(sed -n '163p' docs/evidence/phase-5-cis/attack-output.txt) \
     <(sed -n '1376p' docs/evidence/phase-5-cis/attack-output.txt)
# (no output)                                                          (exit 0)
# => the controller kind changed; the violations did not.

kubectl -n cis-benchmark rollout status daemonset/kube-bench-node-ds --timeout=180s
# Waiting for daemon set "kube-bench-node-ds" rollout to finish: 1 of 2 updated
#   pods are available...
# daemon set "kube-bench-node-ds" successfully rolled out              (exit 0)
```

**Placement is checked, not assumed — two rows, or it did not work:**

```bash
kubectl -n cis-benchmark get pods -l app.kubernetes.io/name=kube-bench-node-ds \
  -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,STATUS:.status.phase
# NAME                       NODE             STATUS
# kube-bench-node-ds-6nhfh   seclab-worker    Running
# kube-bench-node-ds-vm7cw   seclab-worker2   Running
```

**Read the reports per Pod, not per controller.** `kubectl logs
daemonset/kube-bench-node-ds` returns one Pod's log without saying which node
it came from — the exact ambiguity this section exists to remove — so the loop
resolves `.spec.nodeName` for each Pod first:

```bash
for p in $(kubectl -n cis-benchmark get pods -l app.kubernetes.io/name=kube-bench-node-ds -o name); do
  echo "=== $p on $(kubectl -n cis-benchmark get $p -o jsonpath='{.spec.nodeName}')"
  kubectl -n cis-benchmark logs $p
done
# === pod/kube-bench-node-ds-6nhfh on seclab-worker
# ...97 lines of report, elided here; verbatim in evidence section 8d...
# == Summary node ==
# 17 checks PASS
# 2 checks FAIL
# 6 checks WARN
# 0 checks INFO
# === pod/kube-bench-node-ds-vm7cw on seclab-worker2
# ...97 lines of report, elided here; verbatim in evidence section 8e...
# == Summary node ==
# 17 checks PASS
# 2 checks FAIL
# 6 checks WARN
# 0 checks INFO
```

Per-node counts and the comparison against 2026-07-26 are in the second table
in section 3. **`seclab-worker2`'s report contains no finding
`seclab-worker`'s did not already contain** — same two mode-644 FAILs, same
six WARNs, same 4.2.5 false PASS — which is the expected result for two
containers off one kind node image. What changed is the class of evidence: the
findings probe 5d-d confirmed by hand on that worker are now scanner output.

**The hold, and what it costs.** The container never exits, so section 2's
`kubectl wait --for=condition=complete` has no analogue here; readiness is the
signal instead. Observed at 2m40s of DaemonSet age: `READY 2` of `DESIRED 2`,
`restartCount 0` on both Pods, which is what a working hold looks like and is
not what `CrashLoopBackOff` looks like.

**Cleanup — run 2026-07-29, after the reports above were captured:**

```bash
kubectl -n cis-benchmark delete daemonset kube-bench-node-ds
# daemonset.apps "kube-bench-node-ds" deleted from cis-benchmark namespace
#                                                                      (exit 0)

kubectl -n cis-benchmark get daemonset,pods
# No resources found in cis-benchmark namespace.                       (exit 0)

kubectl get daemonset -A
# falco         falco        3   3   3   3   3
# kube-system   kindnet      3   3   3   3   3
# kube-system   kube-proxy   3   3   3   3   3
# => three DaemonSets survive and none is this phase's: falco is phase 6's
#    sensor, kindnet and kube-proxy are kind's own. No kube-bench DaemonSet
#    exists anywhere on the cluster.

kubectl get ns cis-benchmark --show-labels
# cis-benchmark   Active   3d15h   app.kubernetes.io/part-of=k8s-security-lab,
#   kubernetes.io/metadata.name=cis-benchmark,
#   pod-security.kubernetes.io/audit=restricted,
#   pod-security.kubernetes.io/enforce=privileged,
#   pod-security.kubernetes.io/warn=restricted                         (exit 0)
```

The DaemonSet was left `Running` between the capture and this teardown on
purpose, so the live cluster could be checked against the evidence rather than
taken on trust. The namespace is **kept**, for section 4's reason exactly: the
committed manifests define it and the phase stays re-appliable. Verbatim
captures of all four commands are in evidence section 8g. With the DaemonSet
gone, section 4's closing paragraph is true again — every object manifest in
`docs/evidence/phase-5-cis/` now reports NotFound, so the only thing a
directory-wide `kubectl delete -f` would still find is the namespace itself,
which is why that command names the namespace manifest explicitly.
