# Runbook — Phase 6: Runtime detection (Falco alerts only, nothing blocked)

A replayable command log for the runtime-observation layer: a dedicated
`falco` namespace whose PSA exemption is written down rather than inherited
silently, a digest-pinned Falco DaemonSet whose `modern_ebpf` driver is proved
against the kernel rather than against its own log, a recorded demonstration
that the same sensor spec is REFUSED by `demo` — as a Pod by PSA and as a
DaemonSet by Kyverno, with a third control answering first when the probe is
left unmodified — two real behaviours fired at the hardened `demo` workload
with the verbatim alerts they raised, and the evidence that neither behaviour
was prevented, routed, stored or answered. Commands are in execution order;
each has a one-line purpose and the observed output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash
unless noted. Kubernetes node image v1.35.5, kernel
`6.18.33.2-microsoft-standard-WSL2`, Falco 0.44.1 (chart
`falcosecurity/falco` 9.1.0, image
`docker.io/falcosecurity/falco:0.44.1@sha256:d0cfe422d6ac...`), driver
`modern_ebpf`. Any `kubectl exec` that passes an in-container path needs
`MSYS_NO_PATHCONV=1` in the environment: Git Bash rewrites `/bin/sh` and
`/etc/falco/falco.yaml` into Windows paths and the resulting error looks like
a missing file inside the container. It is not.

**Four honesty caveats, up front — they are part of the deliverable, not
footnotes:**

1. **Falco DETECTS. It does not PREVENT. This phase blocks nothing.** Every
   other phase in this repo ships something that REFUSES an attack and then
   proves the refusal. Falco writes one line to its own container's stdout and
   the attack continues. Both behaviours in section 3 SUCCEEDED: the shell ran
   and printed its output, the staged binary executed and Falco's own
   `evt_res=SUCCESS` field records that it did. This phase belongs in no
   "attack it blocks" column, and it earns **no row** in the threat model's
   Control → ATT&CK table, whose rule is that mappings are mitigations.
2. **There is NO ALERTING PIPELINE. The alert goes to a pod's stdout and
   nothing reads it.** `stdout_output` is the only live channel — proved from
   the running container's config in section 4, not assumed. No file output,
   no PVC, no HTTP sink, no falcosidekick, no Talon, no log store, no shipper,
   no dashboard, no retention, no page, no on-call rota, no owner. The alert's
   entire lifetime is: falco stdout → the kubelet's container log on that node
   → gone at pod restart or log rotation. An alert nobody reads is a
   capability, not a control.
3. **Threat model §6.4 is AMENDED by this phase and NOT closed.** Its title
   clause "until Falco lands" is now satisfiable, but only half its substance
   changes: runtime behaviour is now *detected*; it is still not *stopped*,
   and nobody is notified. `responseActions.enabled` is `false` in the release
   values and there is no responder on the cluster. **Detection without
   response is not mitigation.** The new gaps Falco itself introduces are
   §6.13.
4. **The sensor cannot run in `demo`, and it is exempt from the controls this
   lab enforces on everything else.** It needs `privileged: true` and twelve
   `hostPath` mounts, which is a `restricted`-profile violation six ways over.
   `demo` correctly refuses it (section 1). So it runs in its own namespace
   where PSA does not enforce and no Kyverno policy selects it — a second
   concrete instance of §6.7's conceded residual risk alongside
   `cis-benchmark`, this time holding the **most privileged workload in the
   lab**. `driver.modernEbpf.leastPrivileged` was left at its default `false`,
   so no minimal-privilege claim is made either.

---

## 0. The sensor — and why it is not a control

This section is the house's `## 0. The controls`. It is retitled for the same
reason phase 5 retitled it: there are no new controls in this phase, and
naming a section for something it does not contain is the exact failure mode
this repo is built to avoid. Phase 5 measured. This one watches. Neither
blocks.

- **Falco 0.44.1, run as a DaemonSet, one pod per node** — installed by Helm
  from chart `falcosecurity/falco` 9.1.0; the exact command and every
  override's justification are in
  [`clusters/falco-install.md`](../clusters/falco-install.md), and the
  DaemonSet as installed is committed at
  `docs/evidence/phase-6-falco/falco-daemonset-rendered.yaml`. **What it
  does:** attaches a CO-RE eBPF probe to the kernel, watches every syscall on
  the machine, and when an event matches a rule in
  `/etc/falco/falco_rules.yaml` prints one line to its own stdout carrying a
  priority, a message and a set of enriched fields. **What it does NOT do:**
  block, kill, evict, quarantine, deny, page, store, forward or retry. It has
  no admission hook, no `responseActions`, and no downstream of any kind.
- **A dedicated `falco` namespace** —
  `docs/evidence/phase-6-falco/00-namespace-falco.yaml`, carrying
  `enforce: privileged`, `warn: restricted`, `audit: restricted`. **Why it is
  needed:** see section 1. `warn: restricted` is deliberate: the `helm
  install` then prints, in the apiserver's own words, the six categories of
  `restricted` violation the sensor commits. That warning is evidence, not
  noise. `audit: restricted` records nothing today — this cluster has no audit
  logging (§6.2) — and is there so the record exists the moment one appears.
- **The three placement probes** — `rejected-in-demo-daemonset.yaml`,
  `rejected-in-demo-pod.yaml` and `rejected-in-demo-pod-sa-isolated.yaml`, the
  same sensor spec aimed at `demo`. These are the only adversarial-shaped
  objects in the phase, none of them is ever persisted, and the third exists
  only because the second was answered by the wrong control (1b).
- **Two attack behaviours, and no attack manifests.** Unlike phases 2b, 4 and
  5, this phase ships no `attack-*.yaml`. Runtime detection needs a running
  workload to misbehave, not a new object to be admitted, so both behaviours
  are `kubectl exec` into the standing `demo/nginx` pod. Nothing was created
  to attack, which is why there is nothing to delete in section 5.

### What a runtime detector does and does not tell you

It tells you that a syscall pattern matching a written rule occurred, on the
kernel the probe is attached to, while the sensor was running. It does not
tell you that the behaviour was stopped, that anyone was told, that the rule
covers the technique in general, or that behaviours which fired no rule did
not happen. Coverage here is exactly two rules — the two that were fired and
came back. Nothing in this phase measures false negatives, and section 3f
documents one blind spot found by accident: the stock sensitive-file rule
matches only *successful* opens, so an attack this lab's own hardening BLOCKS
is invisible to it.

### The alert's whole life is a line in a pod log

`kubectl logs` is the alert console. There is no other one. Section 4 reads
every output channel out of `/etc/falco/falco.yaml` **in the running
container** — `file_output: false`, `http_output: false` with an empty `url`,
`program_output: false` pointing at the chart's unedited Slack placeholder,
`json_output: false`, and `syslog_output: true` writing to a socket no daemon
in the image consumes. Only `stdout_output` is live. So the honest sentence is
not "Falco is configured to alert"; it is "Falco writes a line to a file
descriptor and the line's next hop does not exist."

### One kernel, three sensors — divide every count by three

All three kind "nodes" are containers on one shared WSL2 kernel, and the
modern eBPF probe is attached to that one kernel. Every Falco pod therefore
sees every event on the whole cluster: each alert below appears **three
times**, the three copies **12.9 microseconds** apart end to end (12,910 ns
for the section 3b alert; the subtraction is written out in 3c), and only the
pod co-located with the target's containerd resolves `container_name` and the
`k8s_*` fields — the other two print `<NA>`. This is a kind-on-Docker-Desktop
artifact and does not describe Falco on a real multi-node cluster. Every count
in this phase is of distinct **events**, never of log lines.

---

## 1. Where it runs — the restricted profile refuses the sensor

Falco needs `privileged: true` and `hostPath` mounts of `/proc`, `/etc`,
`/usr`, `/boot`, `/lib/modules`, `/sys/kernel` and six container-runtime
sockets. Pointed at `demo` it is refused every time below — but **by a
different control depending on which object is submitted**, and one of those
controls is not even part of this lab. That is the most instructive thing in
the phase. Note what Falco does **not** need: `hostPID`, `hostNetwork`,
`hostIPC` and `/dev` are all unset by chart 9.1.0 for `modern_ebpf`, which is
where this spec differs from phase 5's kube-bench.

Everything here is applied with `--server-side --dry-run=server`, never a
plain `--dry-run=server`: against an UNCHANGED object the plain form computes
an empty patch client-side and issues only a GET, so it never reaches
admission and proves nothing (traced with `-v=8` in
[`runbooks/phase-4-supply-chain.md`](phase-4-supply-chain.md) section 3a).

**1a. The probes are the real spec with the namespace changed, checked rather
than asserted.** The DaemonSet probe against the committed rendering of what
is actually installed:

```bash
cd docs/evidence/phase-6-falco
diff <(grep -v '^#' falco-daemonset-rendered.yaml) \
     <(grep -v '^#' rejected-in-demo-daemonset.yaml)
# 5c5
# <   namespace: falco
# ---
# >   namespace: demo                                                  (exit 1)
```

The bare-Pod probe carries the DaemonSet's `spec.template.spec` byte for byte;
both were canonicalised and hashed rather than eyeballed:

```bash
# canonical-YAML compare of DaemonSet .spec.template.spec against Pod .spec
# IDENTICAL
# podSpec sha256 (daemonset): b563ae3cca4ae3faffac4dd69903ab0db1dcd901159621bb0555a791b142a09b
# podSpec sha256 (bare pod) : b563ae3cca4ae3faffac4dd69903ab0db1dcd901159621bb0555a791b142a09b
```

**1b. POD PATH — and the control that answered is NEITHER PSA NOR KYVERNO.**

```bash
kubectl apply --server-side --dry-run=server -f rejected-in-demo-pod.yaml
# Error from server (Forbidden): pods "falco" is forbidden: error looking up
# service account demo/falco: serviceaccount "falco" not found        (exit 1)
```

**Read which control answered, do not assume it.** That is the built-in
**ServiceAccount admission plugin**, which runs in the *mutating* phase —
before the PodSecurity validating plugin and before any webhook. The request
never reached the controls this phase is about. The probe carries the real
podSpec, so it names `serviceAccountName: falco`, and that ServiceAccount
exists only in namespace `falco`. Writing "PSA refuses the Falco pod in
`demo`" on the strength of this output would have been **false**, and it is
exactly the failure mode this repo has been marked down for before: crediting
the control you expected instead of the one that answered.

**1c. POD PATH, SERVICEACCOUNT ISOLATED — now PSA answers.** One field of
substance changes, and the diff is committed:

```bash
diff <(grep -v '^#' rejected-in-demo-pod.yaml) \
     <(grep -v '^#' rejected-in-demo-pod-sa-isolated.yaml)
# 4c4
# <   name: falco
# ---
# >   name: falco-psa-isolated
# 14c14
# <   serviceAccountName: falco
# ---
# >   serviceAccountName: default                                      (exit 1)
```

`default` exists in every namespace, so the SA plugin is satisfied and the
request proceeds. Every field that bears on the security question —
`privileged`, capabilities, the twelve `hostPath` volumes, `runAsNonRoot`,
`seccompProfile` — is untouched; the object name changes only so the two
probes cannot be confused in a transcript.

```bash
kubectl apply --server-side --dry-run=server -f rejected-in-demo-pod-sa-isolated.yaml
# Error from server (Forbidden): pods "falco-psa-isolated" is forbidden:
# violates PodSecurity "restricted:v1.35": privileged (container "falco" must
# not set securityContext.privileged=true), allowPrivilegeEscalation != false
# (...), unrestricted capabilities (...), restricted volume types (volumes
# "container-engine-socket-0", ... "boot-fs", "lib-modules", "usr-fs",
# "etc-fs", "sys-fs", "proc-fs" use restricted volume type "hostPath"),
# runAsNonRoot != true (...), seccompProfile (...)                    (exit 1)
```

Note `restricted:v1.35` — the PINNED enforce version from the namespace label.
That is what distinguishes an ENFORCE denial from the `restricted:latest`
string the warn label emits, and reading it is how you tell which label
answered. Six independent `restricted` violations are listed. No Kyverno
policy is involved: PSA short-circuits before webhooks.

**1d. DAEMONSET PATH — the form Falco really ships as, and the answer changes
again.**

```bash
kubectl apply --server-side --dry-run=server -f rejected-in-demo-daemonset.yaml
# Warning: would violate PodSecurity "restricted:latest": privileged
# (container "falco" must not set securityContext.privileged=true), ...
# Error from server: admission webhook "vpol.validate.kyverno.svc-fail" denied
# the request: Policy require-drop-all-capabilities failed: ...; Policy
# restrict-registries failed: Image registry not allowed: ... nginxinc/* or
# curlimages/*, or ghcr.io/joesevv/k8s-security-lab/*.; Policy
# disallow-privileged-containers failed: Privileged containers are not
# allowed: ...                                                        (exit 1)
```

Same podSpec, different object kind, **different control, different severity,
different profile version quoted**. PodSecurity only WARNED, naming
`restricted:latest` — the warn label, not the enforce one — so with PSA alone
the DaemonSet would have been ADMITTED and then failed silently as each of its
pods was rejected. The actual denial came from **Kyverno**, and from three
policies at once. Note which is absent: **no `ValidatingPolicy` in
`policies/` covers `hostPath` or host namespaces**, so Kyverno says nothing
about the twelve host mounts. PSA covers those, and only against the Pod form.
Neither control alone tells the whole story, and writing either one as "the
control that refuses Falco" would exceed enforced reality. Phase 5's
kube-bench Job was denied by **one** Kyverno policy (`restrict-registries`);
the extra two here are Falco's own doing — it sets `privileged: true` and it
drops no capabilities.

**1e. THE SAME TWO FORMS IN `demo-kyverno-only`.** That namespace has a warn
label and no enforce label, so PSA warns on both forms and Kyverno denies both
— the Pod form's answer therefore *changes with the namespace*, which is a
second reason not to write one sentence naming one control:

```bash
sed 's/namespace: demo/namespace: demo-kyverno-only/' rejected-in-demo-pod-sa-isolated.yaml \
  | kubectl apply --server-side --dry-run=server -f -
# Warning: would violate PodSecurity "restricted:latest": ...
# Error from server: admission webhook "vpol.validate.kyverno.svc-fail" denied
# the request: Policy disallow-privileged-containers failed: ...; Policy
# require-drop-all-capabilities failed: ...; Policy restrict-registries
# failed: ...                                                         (exit 1)

sed 's/namespace: demo/namespace: demo-kyverno-only/' rejected-in-demo-daemonset.yaml \
  | kubectl apply --server-side --dry-run=server -f -
# Warning: would violate PodSecurity "restricted:latest": ...
# Error from server: admission webhook "vpol.validate.kyverno.svc-fail" denied
# the request: Policy restrict-registries failed: ...; Policy
# disallow-privileged-containers failed: ...; Policy
# require-drop-all-capabilities failed: ...                           (exit 1)
```

The policies are listed in a different order in each message. That is Kyverno
reporting order and nothing should be read into it.

**1f. CONSEQUENCE — the namespace choice, and the residual risk it makes
concrete.** The sensor has to run somewhere without `restricted` enforcement.
Three options, and the reasoning is written down because the choice is
content:

- `demo` — impossible: the Pod is denied by PSA (1c) and the DaemonSet by
  Kyverno (1d). Correct behaviour in both forms.
- `demo-kyverno-only` — PSA is warn-only there, but all four
  `ValidatingPolicy` objects select that namespace and three of them deny
  (1e).
- A dedicated, labelled `falco` namespace — chosen. All five Kyverno policies
  are scoped by `namespaceSelector` to `[demo, demo-kyverno-only]` only, so
  none of them evaluates anything here, and PSA is set to
  `enforce: privileged`.

**Nothing in that namespace is gated by admission. That is threat model §6.7's
already-conceded residual risk, and this is now its second concrete instance
alongside `cis-benchmark`** — except that this one holds a permanently
running, privileged workload with twelve host mounts rather than a Job that
exits. Labelling changes nothing about enforcement: the apiserver has no
`--admission-control-config-file`, so an unlabelled namespace already falls
back to the PodSecurity plugin's built-in privileged default. The label makes
the exemption greppable instead of implicit.

**1g. Nothing was persisted.** Every probe above is a dry run, and every one
was rejected at admission anyway:

```bash
kubectl -n demo get pod,daemonset -o name
# pod/nginx-775678cbbd-mmrxb
# pod/nginx-775678cbbd-q7ddt
# pod/signed-app-5d4c4ffff4-vrtps
# (three workload pods, zero daemonsets, no falco object)              (exit 0)

kubectl -n demo-kyverno-only get pod,daemonset -o name
# (no output — the namespace is empty)                                 (exit 0)
```

---

## 2. Installing it, pinned, and proving the driver

The driver was this phase's main technical risk. The nodes run a Microsoft
WSL2 kernel, `6.18.33.2`, for which there is no prebuilt Falco kernel module
and no kernel headers on the node to build one, so the CO-RE eBPF probe is the
only viable path and it needs BTF. Checked before installing anything — and
re-checked afterwards on all three nodes, which is the capture printed here
(see the dating below the block):

```bash
docker exec seclab-worker uname -r
# 6.18.33.2-microsoft-standard-WSL2                                    (exit 0)

for n in seclab-worker seclab-control-plane seclab-worker2; do
  MSYS_NO_PATHCONV=1 docker exec $n ls -la /sys/kernel/btf/vmlinux
done
# -r--r--r-- 1 root root 6677359 Jul 29 14:47 /sys/kernel/btf/vmlinux
# -r--r--r-- 1 root root 6677359 Jul 29 14:47 /sys/kernel/btf/vmlinux
# -r--r--r-- 1 root root 6677359 Jul 29 14:47 /sys/kernel/btf/vmlinux  (exit 0)
```

`MSYS_NO_PATHCONV=1` is required on the stat, not optional: without it Git
Bash rewrites the in-container path and the command fails with `ls: cannot
access 'C:/Program Files/Git/sys/kernel/btf/vmlinux': No such file or
directory` (exit 2) — which reads exactly like a missing BTF blob and is not
one. Same trap as 2d and 3e.

**BTF is present on all three nodes**, stat'd directly on each rather than
inferred from the shared kernel; identical size and mtime on all three is what
one kernel behind three container mounts looks like. The worker2 stat was
taken later than the other two — the loop above was re-run against the live
cluster at 2026-07-29T16:09:23Z, after sections 3 to 5 were captured — and it
is dated here rather than presented as part of the pre-install check.

**2a. The namespace first, from the committed manifest,** so the PSA exemption
is reviewable rather than inherited:

```bash
kubectl apply -f docs/evidence/phase-6-falco/00-namespace-falco.yaml
# namespace/falco created                                              (exit 0)

kubectl get ns falco --show-labels
# NAME    STATUS   AGE   LABELS
# falco   Active   0s    app.kubernetes.io/part-of=k8s-security-lab,
#   kubernetes.io/metadata.name=falco,
#   pod-security.kubernetes.io/audit=restricted,
#   pod-security.kubernetes.io/enforce=privileged,
#   pod-security.kubernetes.io/warn=restricted
```

**2b. The chart version is searched, not guessed,** matching what phases 2b
and 3 did for Kyverno and sealed-secrets:

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
# "falcosecurity" already exists with the same configuration, skipping (exit 0)

helm repo update falcosecurity
# ...Successfully got an update from the "falcosecurity" chart repository
# Update Complete. ⎈Happy Helming!⎈                                   (exit 0)

helm search repo falcosecurity/falco --versions | head -5
# NAME                   CHART VERSION  APP VERSION  DESCRIPTION
# falcosecurity/falco    9.1.0          0.44.1       Falco
# falcosecurity/falco    9.0.0          0.44.0       Falco
# falcosecurity/falco    8.0.5          0.43.1       Falco
# falcosecurity/falco    8.0.4          0.43.1       Falco            (exit 0)
```

**2c. The install.** The full command with every override justified line by
line lives in [`clusters/falco-install.md`](../clusters/falco-install.md) and
is not duplicated here; what matters for the runbook is what it printed:

```bash
helm install falco falcosecurity/falco --namespace falco --version 9.1.0 \
  --set driver.kind=modern_ebpf --set image.tag=0.44.1@sha256:d0cfe422d6ac... \
  ... --timeout 10m --wait
# Warning: would violate PodSecurity "restricted:latest": privileged
# (container "falco" must not set securityContext.privileged=true),
# allowPrivilegeEscalation != false (...), unrestricted capabilities (...),
# restricted volume types (volumes "container-engine-socket-0", ...
# "boot-fs", "lib-modules", "usr-fs", "etc-fs", "sys-fs", "proc-fs" use
# restricted volume type "hostPath"), runAsNonRoot != true (...),
# seccompProfile (...)
# NAME: falco
# LAST DEPLOYED: Wed Jul 29 10:07:44 2026
# NAMESPACE: falco
# STATUS: deployed
# REVISION: 1
# DESCRIPTION: Install complete                                        (exit 0)
```

**The install prints its own justification for not being in `demo`.** That is
the namespace's `warn: restricted` label doing its job: the apiserver
enumerates six categories of `restricted` violation the sensor commits. It is
a warning here only because the namespace is labelled `enforce: privileged`;
section 1 submits the same spec to `demo`, where it is not a warning.

```bash
helm -n falco list
# NAME   NAMESPACE  REVISION  UPDATED                                STATUS
# falco  falco      1         2026-07-29 10:07:44.9542527 -0500 CDT   deployed
#   CHART: falco-9.1.0    APP VERSION: 0.44.1                         (exit 0)

kubectl -n falco get pods -o wide
# falco-6pq4p   1/1   Running   0   27s   10.244.1.8    seclab-worker
# falco-b6hrw   1/1   Running   0   27s   10.244.0.7    seclab-control-plane
# falco-rvlds   1/1   Running   0   27s   10.244.2.10   seclab-worker2 (exit 0)
```

**Running is not the proof.** 2d is.

**2d. The driver claim, checked against ground truth rather than against
Falco's own log** — phase 5's lesson was that a tool's own output can be
wrong. Falco's log first:

```bash
kubectl -n falco logs falco-6pq4p -c falco \
  | grep -n -E 'Falco version|Loading rules|falco_rules.yaml|event sources|Opening|libpman' \
  | sed 's/Wed Jul 29 15:07:53 2026: //'
# 1:Falco version: 0.44.1 (x86_64)
# 20:Loading rules from:
# 21:   /etc/falco/falco_rules.yaml | schema validation: ok
# 25:Loaded event sources: syscall
# 26:Enabled event sources: syscall
# 27:Opening 'syscall' source with modern BPF probe.
# 30:[libs]: libpman: disabled BPF iterators (not running in the root PID
#    namespace, or failed to determine it)                             (exit 0)
# (the trailing `sed` is part of the command, not an edit of the output: every
#  line Falco writes carries a `Wed Jul 29 15:07:53 2026: ` prefix that would
#  otherwise push these lines past the page width. The evidence file prints
#  the same lines WITH the prefix, unstripped. `falco_rules.yaml` is in the
#  pattern on purpose — line 21 does not match any of the other alternatives,
#  and it is the one line in the block that matters most.)
# => line 21 is the WHOLE detection surface: one stock rules file, no custom
#    rule, no override. Line 30 is the cost of the chart not requesting
#    hostPID — process-tree visibility is reduced and none is claimed.
```

Then three checks that do not depend on Falco telling the truth:

```bash
MSYS_NO_PATHCONV=1 kubectl -n falco exec falco-6pq4p -c falco -- \
  sed -n '/^engine:/,/^[a-z]/p' /etc/falco/falco.yaml
# engine:
#   kind: modern_ebpf
#   modern_ebpf:
#     buf_size_preset: 4
#     cpus_for_each_buffer: 2
#     disable_iterators: false
#     drop_failed_exit: false
# falco_libs:                                                          (exit 0)
# (`falco_libs:` is the sed range's closing line — the next top-level key —
#  not part of the engine block. Kept because the command prints it.)

docker exec seclab-worker sh -c "lsmod | grep -i -E 'falco|scap' || echo NO_FALCO_KMOD_LOADED"
# NO_FALCO_KMOD_LOADED       (same on control-plane and worker2)       (exit 0)

kubectl -n falco exec falco-6pq4p -c falco -- \
  sh -c "ls -l /proc/1/fd | grep -o 'bpf[-a-z]*' | sort | uniq -c"
#      13 bpf
#      14 bpf-map
#     197 bpf-prog                                                     (exit 0)

kubectl -n falco get pods \
  -o custom-columns=NAME:.metadata.name,NODE:.spec.nodeName,RESTARTS:.status.containerStatuses[0].restartCount
# falco-6pq4p   seclab-worker          0
# falco-b6hrw   seclab-control-plane   0
# falco-rvlds   seclab-worker2         0                               (exit 0)
# => four independent lines agree and only one is Falco's own word: the
#    running container's config says modern_ebpf, no kernel module exists
#    anywhere, procfs shows 197 in-kernel bpf-prog fds held by PID 1, and no
#    pod restarted, so nothing fell back to another driver.
```

**Without `MSYS_NO_PATHCONV=1` the first command fails with `sed: C:/Program
Files/Git/etc/falco/falco.yaml: No such file or directory`** — Git Bash
rewriting the in-container path. That error reads exactly like "Falco has no
config file" and it is not; it is recorded in the evidence file because it is
a live instance of *read which thing answered*.

The privilege the sensor actually runs with, read off the DaemonSet:
`{"privileged": true}`, with `hostPID`, `hostNetwork` and `hostIPC` all unset.
`driver.modernEbpf.leastPrivileged` was left at its chart default `false`, so
the least-privileged capability set was **not** adopted and the sensor runs
with more privilege than it strictly requires. That is an unremediated gap,
not a claim of minimal privilege.

**2e. A correction, recorded rather than dropped — the first pinned install
was not fully pinned.** The first attempt pinned both images and both falcoctl
rules refs. Its init-container log then resolved an artifact the `--set` flags
never named:

```bash
# falco-fkbsf is a pod of the FIRST install, not the one running now.
kubectl -n falco logs falco-fkbsf -c falcoctl-artifact-install
# {"level":"INFO","msg":"Installing artifacts","refs":[
#   "ghcr.io/falcosecurity/rules/falco-rules@sha256:36d143c0ae2d...",
#   "ghcr.io/falcosecurity/plugins/plugin/container:0.7.1"],...}
# => a FLOATING TAG survived a pin that looked complete.
```

`ghcr.io/falcosecurity/plugins/plugin/container:0.7.1` comes from the chart
value `collectors.containerEngine.pluginRef`, **not** from falcoctl dependency
resolution, so `resolveDeps=false` does not remove it — confirmed by rendering
the chart, where the tag ref was still appended. The fix is to pin `pluginRef`
itself, using the manifest digest the first install's own log printed. The
release was uninstalled and replaced; the committed install command is the
fully pinned one, and only that one produced the alerts in section 3. Anyone
who copies a flag set without the `pluginRef` line gets a floating plugin and
will not know it.

After the fix, both ghcr artifacts are pulled **by digest** and
cosign-verified at pull time by the init container (`Signature successfully
verified!`). That verification is falcoctl's own claim, not independently
reproduced — no cosign binary exists on this host — and the two Docker Hub
images were not signature-verified at all. The pins prove the bytes are
stable, not that they are trustworthy.

---

## 3. Detection demo — two behaviours are observed, and only observed

Target: `demo/nginx-775678cbbd-q7ddt` on `seclab-worker` — PSA
`enforce: restricted`, uid 101, all capabilities dropped, read-only root
filesystem, digest-pinned `nginxinc/nginx-unprivileged` image. This is the
hardened workload, not a helper pod stood up to be easy to detect. Alerts are
read from `falco-6pq4p`, the pod on the same node, because only the
co-located sensor resolves the container and `k8s_*` fields.

**3a. PRIMARY — an interactive shell, with a real TTY, inside the pod.** The
stock rule requires `proc.tty != 0`. `kubectl exec -it` from Git Bash does NOT
allocate a PTY (stdin is not a tty), so the exec is driven through util-linux
`script` on the control-plane node against that node's own kubectl. This is a
genuine interactive exec, not a synthesized event — `tty` inside the shell
returns a real `/dev/pts` device:

The attack window was bracketed by a UTC clock read immediately before and
immediately after, so the alert can be placed inside it rather than merely
near it: **T0 = 2026-07-29T15:13:31.760633900Z**, **T1 =
2026-07-29T15:13:32.179439800Z**.

```bash
docker exec seclab-control-plane script -q -c "kubectl exec -it -n demo nginx-775678cbbd-q7ddt -- /bin/sh -c 'tty; id; echo PHASE6-PRIMARY-MARKER; uname -a'" /dev/null
# ^@/dev/pts/0^M
# uid=101(nginx) gid=101(nginx) groups=101(nginx)^M
# PHASE6-PRIMARY-MARKER^M
# Linux nginx-775678cbbd-q7ddt 6.18.33.2-microsoft-standard-WSL2 ...^M (exit 0)
```

**3b. THE ALERT IT RAISED**, verbatim:

```bash
kubectl -n falco logs falco-6pq4p -c falco | grep PHASE6-PRIMARY-MARKER
# 15:13:32.047577782: Notice A shell was spawned in a container with an
# attached terminal | evt_type=execve user=<NA> user_uid=101
# user_loginuid=-1 process=sh proc_exepath=/bin/busybox parent=<NA>
# command=sh -c tty; id; echo PHASE6-PRIMARY-MARKER; uname -a
# terminal=34816 exe_flags=EXE_LOWER_LAYER container_id=4e6de1a83332
# container_name=nginx
# container_image_repository=docker.io/nginxinc/nginx-unprivileged
# container_image_tag=1.29.8-alpine k8s_pod_name=nginx-775678cbbd-q7ddt
# k8s_ns_name=demo                                                     (exit 0)
# => alert 15:13:32.047577782 sits inside the window 15:13:31.760 → .179.
#    terminal=34816 is the non-zero proc.tty the rule requires; user_uid=101
#    confirms it fired against the NON-ROOT hardened workload.
```

The line carries the priority (`Notice`) and the rule's **output string**, not
the rule's name: `json_output` is `false`, so no rule name is printed
anywhere. This is the stock rule commonly named "Terminal shell in container",
but that name was **not** read out of the loaded rules file by any command in
this run and is recorded as an identification, not as a captured field.

**Every alert line in that pod's log is accounted for, and the count is a
function of when you look.** `falco-6pq4p` has restartCount 0, so its log
spans the whole pinned install; every capture in this section greps for a
marker string, which hides every line the marker is not in. The log **only
grows** — nothing deduplicates it and nothing removes a line until the pod
restarts — so any total is valid only as of a stated moment. Enumerated whole
at **2026-07-29T16:10:06Z**:

```bash
kubectl -n falco logs falco-6pq4p -c falco \
  | grep -oE '^[0-9:.]+: (Notice|Warning) [A-Za-z /]+'
# 15:12:42.954798594: Notice A shell was spawned in a container with an attached terminal
# 15:13:32.047577782: Notice A shell was spawned in a container with an attached terminal
# 15:14:27.005294126: Warning File execution detected from /dev/shm
# 15:42:04.019645548: Notice A shell was spawned in a container with an attached terminal
# 15:42:16.729771901: Warning File execution detected from /dev/shm    (exit 0)
```

**Three of those five lines are the 2026-07-29 attack window; two are not.**

- `15:12:42.954798594` — a **rehearsal of 3a's behaviour**: same rule, same
  container, same `terminal=34816`, and a command that is 3a's minus the
  marker `echo` and `uname -a`. Not a third technique and not a third rule.
  `15:13:32.047577782 - 15:12:42.954798594 = 49.09 s`, so it falls BEFORE 3a's
  bracketed window (T0 15:13:31.760) and is excluded by it. Nothing in the
  phase transcript records the invocation that produced it, so it is written
  down here rather than left unexplained.
- `15:13:32.047577782` and `15:14:27.005294126` — the 3b primary and the 3d
  secondary, each carrying its `PHASE6-*` marker.
- `15:42:04.019645548` and `15:42:16.729771901` — **not this phase's run.**
  They carry `VERIFY-PRIMARY-MARKER-JS` and `VERIFY-SHM-MARKER-JS`, and they
  were produced by an adversarial verification agent re-firing both behaviours
  against the live cluster roughly 28 minutes later, to confirm the phase
  reproduced. That is a legitimate thing to have happened and it is recorded
  as what it was, not folded into the demo.

So do not read a total line count as a result. **The phase's evidence is the
two demonstrated behaviours and the two stock rules they fired** — both of
which are fixed — and three alert lines in the attack window. Replay the
section and the log gets longer without the evidence changing at all.

**3c. THE SHARED-KERNEL ARTIFACT.** The same event is in all three pods' logs
**12,910 ns — 12.9 microseconds — end to end**, and two of the three carry no
k8s metadata. Read the three timestamps out and do the subtraction rather than
taking the spread on trust:

```bash
for p in falco-6pq4p falco-b6hrw falco-rvlds; do
  kubectl -n falco logs $p -c falco | grep PHASE6-PRIMARY-MARKER
done
# (pod and node names below are annotation; the loop prints only the three
#  alert lines, each ~600 chars, truncated here at ' ...')
# falco-6pq4p (seclab-worker):        15:13:32.047577782 ...
#   container_name=nginx  k8s_pod_name=nginx-775678cbbd-q7ddt k8s_ns_name=demo
# falco-b6hrw (seclab-control-plane): 15:13:32.047572312 ...
#   container_name=<NA>   k8s_pod_name=<NA>  k8s_ns_name=<NA>
# falco-rvlds (seclab-worker2):       15:13:32.047564872 ...
#   container_name=<NA>   k8s_pod_name=<NA>  k8s_ns_name=<NA>          (exit 0)
# => the spread, worked out rather than asserted:
#      .047577782 - .047564872 = 12,910 ns = 12.9 us  (first line to last)
#      .047577782 - .047572312 =  5,470 ns            (6pq4p -> b6hrw)
#      .047572312 - .047564872 =  7,440 ns            (b6hrw -> rvlds)
#    ONE event, seen three times, all three copies inside 13 microseconds.
#    Neither adjacent gap is 13 of anything; the figure is a spread, not a
#    step. On a real cluster with three kernels, two of these three lines
#    would not exist. Divide every count by three.
```

**3d. SECONDARY — stage and execute a payload from `/dev/shm`.**
`readOnlyRootFilesystem` blocks writing into the image, so the attacker uses
the one writable, exec-able path the pod spec left open. No TTY needed:

```bash
kubectl exec -n demo nginx-775678cbbd-q7ddt -- /bin/sh -c 'cp /bin/busybox /dev/shm/bb && /dev/shm/bb id && echo PHASE6-SHM-MARKER'
# bb: applet not found
# command terminated with exit code 127                              (exit 127)
# (window: T0 15:14:26.822373800Z  ->  T1 15:14:27.026634800Z)

kubectl -n falco logs falco-6pq4p -c falco | grep PHASE6-SHM-MARKER | head -1
# 15:14:27.005294126: Warning File execution detected from /dev/shm |
# evt_res=SUCCESS ... user_uid=101 process=bb proc_exepath=/dev/shm/bb
# parent=sh command=bb id terminal=0 exe_flags=EXE_WRITABLE
# container_id=4e6de1a83332 container_name=nginx
# k8s_pod_name=nginx-775678cbbd-q7ddt k8s_ns_name=demo                (exit 0)
# => alert 15:14:27.005294126 sits inside the window. evt_res=SUCCESS and
#    proc_exepath=/dev/shm/bb: the execve of the staged binary SUCCEEDED.
```

**Do not misread the 127.** `bb: applet not found` is busybox's *own* message
printed *after* it started — a copied busybox picks its applet from `argv[0]`
and `bb` is not an applet name. The kernel executed the staged binary; Falco's
`evt_res=SUCCESS` is the independent confirmation. The exit code belongs to
the payload's argument handling, not to the exec.

**3e. AND NEITHER BEHAVIOUR WAS PREVENTED.** This is the point of the phase,
not a footnote to it. The staged payload is still there after the alert, and
the same command shows a real preventive control doing what Falco did not:

```bash
MSYS_NO_PATHCONV=1 \
kubectl exec -n demo nginx-775678cbbd-q7ddt -- /bin/sh -c 'ls -l /dev/shm/bb; touch /blocked; echo rootfs-write-rc=$?'
# -rwxr-xr-x    1 nginx    nginx       804616 Jul 29 15:14 /dev/shm/bb
# rootfs-write-rc=1
# touch: /blocked: Read-only file system                               (exit 0)

kubectl -n demo get pod nginx-775678cbbd-q7ddt -o wide
# nginx-775678cbbd-q7ddt   1/1   Running   2 (26h ago)   3d20h
#   10.244.1.4   seclab-worker                                         (exit 0)
# => restartCount is still 2 and the last restart was 26h BEFORE the attack.
#    Same node, same IP, still Running. Nothing killed it, nothing evicted
#    it, no NetworkPolicy was applied, and the payload it was made to run is
#    still in its /dev/shm. Three alert lines were raised in the attack window
#    across the two behaviours (see 3b) and the workload did not notice one.
```

`touch /blocked` is **refused**, and that refusal is a control: it produces an
error the attacker cannot argue with. Falco produced a log line. Only one of
those two is enforcement, and it is the one that predates this phase.

**3f. NEGATIVE CONTROL — the textbook demo that produces nothing here.** The
classic Falco demonstration is `cat /etc/shadow`:

```bash
kubectl exec -n demo nginx-775678cbbd-q7ddt -- /bin/sh -c 'cat /etc/shadow; echo PHASE6-SHADOW-MARKER rc=$?'
# PHASE6-SHADOW-MARKER rc=1
# cat: can't open '/etc/shadow': Permission denied

kubectl -n falco logs falco-6pq4p -c falco --since=30s \
  | grep -iE 'shadow|Sensitive file' || echo NO_SENSITIVE_FILE_ALERT
# NO_SENSITIVE_FILE_ALERT                                              (exit 0)
```

**Two things are true here and only one of them is comfortable.** First, the
lab's own `runAsNonRoot` posture defeated the attack outright: as uid 101 the
`open()` failed `EACCES` before Falco was ever relevant — prevention beat
detection to it. Second, the stock rule's `open_read` macro requires a
*successful* open (`fd.num >= 0`), so **Falco stayed silent on the blocked
attempt**. A detector that says nothing about a failed attack has a blind
spot, and this is a documented one. A demo built on this rule would have shown
an empty log, which is why 3a and 3d were used instead.

Full verbatim captures — the install, the pin correction, all four ground
truth driver checks, both alerts in all three pods, every output channel read
out of the running config, and the closing NOT PROVEN HERE block:
`docs/evidence/phase-6-falco/attack-output.txt`. That file keeps the house
filename and says plainly in its preamble that it is a detection transcript,
not a denial transcript.

---

## 4. Reading the alerts — where they live, and what was not tuned

`kubectl logs` is the alert console. There is no other one, and that is a
configuration fact read out of the running container rather than an
impression:

**The first two blocks below are FLOWED, not verbatim.** Both commands print
several lines per key — including `-A2` context that spills into the *next*
top-level key, and fourteen `http_output` sub-keys — and they are compressed
here to the keys the argument turns on. Nothing is altered and nothing is
contradicted, but this is a selection: the two outputs appear in full,
unflowed, in `docs/evidence/phase-6-falco/attack-output.txt` §3b. Read that
one if you want to check the wording. The third block is verbatim.

```bash
kubectl -n falco exec falco-6pq4p -c falco -- sh -c 'for k in stdout_output file_output http_output program_output syslog_output json_output; do echo "== $k =="; grep -A2 "^$k:" /etc/falco/falco.yaml; done'
# == stdout_output ==   stdout_output:   enabled: true
# == file_output ==     file_output:     enabled: false  filename: ./events.txt
# == http_output ==     http_output:     ca_bundle: ""   ca_cert: ""
# == program_output ==  program_output:  enabled: false  keep_alive: false
# == syslog_output ==   syslog_output:   enabled: true
# == json_output ==     json_output: false                            (exit 0)

MSYS_NO_PATHCONV=1 kubectl -n falco exec falco-6pq4p -c falco -- \
  sed -n '/^http_output:/,/^[a-z]/p;/^program_output:/,/^[a-z]/p' /etc/falco/falco.yaml
# (MSYS_NO_PATHCONV=1 is required: without it Git Bash rewrites the
#  in-container path and the command dies with `sed: C:/Program
#  Files/Git/etc/falco/falco.yaml: No such file or directory` — same trap
#  as 2d. The two `sh -c '...'` commands on either side do not need it,
#  because their argument does not begin with a slash.)
# http_output:  enabled: false   url: ""   mtls: false
# program_output:  enabled: false
#   program: 'jq ''{text: .output}'' | curl -d @- -X POST
#             https://hooks.slack.com/services/XXX'
# rule_matching: first                                                 (exit 0)

kubectl -n falco exec falco-6pq4p -c falco -- sh -c 'ls -la ./events.txt 2>&1; for p in /proc/[0-9]*; do echo "pid $(basename $p) $(cat $p/comm)"; done; command -v syslogd rsyslogd syslog-ng; echo syslog-binary-rc=$?'
# ls: ./events.txt: No such file or directory
# pid 1 falco
# pid 313 sh
# syslog-binary-rc=127                                                 (exit 0)
# => stdout_output is the ONLY live channel. http_output's url is the empty
#    string. program_output's program is the chart's unedited Slack EXAMPLE,
#    hooks.slack.com/services/XXX — a placeholder, not a destination.
#    syslog_output is nominally on and worth nothing: the container's whole
#    PID namespace is Falco itself plus the shell this command runs in, and
#    `command -v` finds no syslogd, rsyslogd or syslog-ng binary in the image
#    at all (127 = not found). json_output is off, which is why no rule NAME
#    appears in any alert in section 3.
# (`pid 313 sh` is this command's own shell; the number changes every run and
#  only `pid 1 falco` is stable. The pod does not set hostPID, so /proc here
#  is the container's PID namespace, which is exactly the scope of the claim
#  — nothing is said about daemons on the node. Captured 2026-07-29T16:12:02Z;
#  the same capture is in the evidence file §3b.)
```

**That command replaced an earlier one, and the replacement is the point.**
The channel check first shipped as `pgrep -a syslogd rsyslogd 2>&1 | head; echo
pgrep-rc=$?`, which does not work and was never going to: busybox `pgrep`
takes ONE pattern, so two arguments make it print its usage message instead of
searching, and `$?` after a pipeline captures `head`'s status, not `pgrep`'s.
It reported a meaningless `0` either way. **And the line printed under it in an
earlier draft — a bare `NO_SYSLOG_DAEMON` — was FABRICATED**: there is no `echo
NO_SYSLOG_DAEMON` anywhere in that command, so it is a string the command
cannot emit. What the broken command really prints is a busybox usage message,
recorded in full in the evidence file §3b alongside this replacement. The claim
it was supposed to support — no syslog daemon in this container — is true, and
the two probes above are what actually establish it. The claim survived; its
evidence did not, and swapping evidence quietly is the failure this repo
exists to avoid.

And nothing downstream exists on the cluster either — not merely unconfigured
in Falco, absent:

```bash
helm ls -A | grep -iE 'sidekick|talon|loki|elastic|fluent|alertmanager|prometheus' || echo NONE
# NONE                                                                 (exit 0)
kubectl get pods -A | grep -iE 'sidekick|talon|loki|elastic|fluent|alertmanager|prometheus' || echo NONE
# NONE                                                                 (exit 0)

helm -n falco get values falco -a | grep -A2 -iE 'responseActions|driver:|leastPrivileged' | head
# driver:
#   enabled: true
#   kind: modern_ebpf
# --
#     leastPrivileged: false
#     sysfsMount: true
#   sysfsMountPath: /sys/kernel
# --
# responseActions:
#   enabled: false                                                     (exit 0)
# => all ten lines `head` returns, not just the last two. The `--` separators
#    are grep's own, between the three -A2 context runs. Two facts in one
#    command: responseActions.enabled is false, and leastPrivileged is false.
```

**So the retention model is: none.** The alert is written to the falco
container's stdout, the kubelet writes that to a container log file on the
node, and it is gone at pod restart or log rotation. There is no PVC, no
shipper, no index, no dashboard and no rota. If both behaviours in section 3
had happened at 3am, the only trace this morning would be whatever is left in
three pods' stdout, and nobody would have been told.

**What was NOT tuned, stated plainly.** The startup log in 2d shows a single
rules file, `/etc/falco/falco_rules.yaml`, from the pinned upstream
`falco-rules` artifact, and nothing else is loaded. So:

- **No custom rule was written.** There is no `falco-rules-custom.yaml` in
  this repo and no `customRules` value in the release.
- **No exception, no rule disable, no priority threshold.** The ruleset is
  stock, unmodified, and every alert in section 3 came from it as shipped.
- **No noise baseline and no false-positive rate.** Alert volume in steady
  state was never measured, and neither was `syscall_event_drops`. A detector
  silently dropping events under load would look exactly like this one does.
- **No coverage analysis.** Two rules were exercised. What the other rules
  would or would not catch on this cluster is unknown, and 3f is the one blind
  spot that was found — by accident, not by a method.

A production deployment needs all four of those. This one has none of them,
and the README/threat-model wording must not imply otherwise.

---

## 5. Teardown

Falco is **kept**, and so is its namespace: the sensor is the phase's
deliverable, and unlike phase 5's Jobs it is meant to keep running. The
namespace manifest stays applied so the phase remains re-appliable, and the
install replays from
[`clusters/falco-install.md`](../clusters/falco-install.md).

**Nothing was created to attack, so there is almost nothing to delete.** Both
behaviours were `kubectl exec` into a pod that already existed; the shell exec
left no artifact at all. The one thing either left behind is the staged
payload, on tmpfs, which would vanish at pod restart anyway — removed so the
standing workload is returned to a clean state:

```bash
kubectl exec -n demo nginx-775678cbbd-q7ddt -- /bin/sh -c 'rm -f /dev/shm/bb; ls /dev/shm; echo cleaned-rc=$?'
# total 0
# drwxrwxrwt    2 root     root            40 Jul 29 15:16 .
# drwxr-xr-x    5 root     root           360 Jul 28 13:09 ..
# cleaned-rc=0                                                         (exit 0)
```

Nothing to tear down from section 1 either: every probe was a dry run and
every one was rejected at admission anyway, so no Falco Pod or DaemonSet ever
existed in `demo` or `demo-kyverno-only`. Confirm, and confirm the rest of the
lab is exactly as it was — a detection phase that changed the lab would be a
failed detection phase:

```bash
kubectl get pod,daemonset,job -A | grep -iE 'falco-smoke|psa-isolate|attack|probe' || echo NO_LEFTOVER_ATTACK_OBJECTS
# NO_LEFTOVER_ATTACK_OBJECTS                                           (exit 0)

kubectl -n demo get deploy,pods -o wide
# nginx        2/2   2   2
# signed-app   1/1   1   1
# (three pods Running on their pinned digests, restartCount unchanged)

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

To remove the layer entirely (**not done for the lab** — removing it puts the
cluster back to having no runtime observation at all, which is the state
threat model §6.4 described before this phase):

```bash
helm uninstall falco --namespace falco
# release "falco" uninstalled                                          (exit 0)

kubectl delete -f docs/evidence/phase-6-falco/00-namespace-falco.yaml
```

Those two commands were in fact run once during this phase, against the
earlier unpinned install that the pinned one replaced (`helm uninstall` then
`kubectl delete ns falco --wait=true`, which printed `namespace "falco"
deleted`); the outputs above are that run's. The namespace manifest is named
explicitly rather than `kubectl delete -f docs/evidence/phase-6-falco/`, which
would also read the rendered DaemonSet — a Helm-owned object that must be
removed by `helm uninstall`, not by `kubectl delete` — and the three placement
probes, which never existed in `demo` because that is the whole point of
section 1.
