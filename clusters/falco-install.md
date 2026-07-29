# Falco install record — Phase 6 runtime detection

Installed 2026-07-29 on the kind `seclab` cluster (context `kind-seclab`,
Kubernetes v1.35.5).

Falco is a runtime DETECTOR, not a control. It writes an alert to stdout when a
rule matches; it blocks, kills and denies nothing. It is the first privileged
workload in this lab that is privileged in order to WATCH rather than to
ENFORCE, so its install is recorded here in full and its privilege is written
down rather than assumed. See `runbooks/phase-6-falco.md` and
`docs/evidence/phase-6-falco/` for the detection demo and the honest limits.

This record follows the **sealed-secrets model**: overrides go inline in the
`helm install` command and are justified in prose immediately below, rather than
in a values file. There is no `values.yaml` anywhere in this repo. Falco needs
more than the one override sealed-secrets did, but every flag is a pin or a
deliberate disable, each is explained, and keeping them in the command means the
install replays byte-for-byte from what is written here.

## Exact commands

```bash
helm repo add falcosecurity https://falcosecurity.github.io/charts
helm repo update falcosecurity
helm search repo falcosecurity/falco --versions | head -3   # resolve chart for app 0.44.1
# -> falcosecurity/falco  9.1.0  0.44.1  Falco
# -> falcosecurity/falco  9.0.0  0.44.0  Falco

# Namespace first, from the committed manifest, so its PSA exemption is
# reviewable rather than inherited (see the header comment in the file):
kubectl apply -f docs/evidence/phase-6-falco/00-namespace-falco.yaml

# NOTE: run from Git Bash with MSYS_NO_PATHCONV=1 is NOT needed for the install
# itself (no in-container paths are passed here), but IS needed for the exec-based
# attack demo in the runbook, where MSYS rewrites /bin/sh into a Windows path.
helm install falco falcosecurity/falco \
  --namespace falco \
  --version 9.1.0 \
  --set driver.kind=modern_ebpf \
  --set image.tag=0.44.1@sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b \
  --set falcoctl.image.tag=0.13.0@sha256:0eeb79adc580ae6a5abfdefd7f8f0fed9151fcb545f015c84e8f1d7b2d8a6b02 \
  --set falcoctl.artifact.follow.enabled=false \
  --set falcoctl.config.artifact.install.refs[0]=ghcr.io/falcosecurity/rules/falco-rules@sha256:36d143c0ae2d5569da0274ea6bef188bac02b95abe51e44cfff16f38d3d6b9e0 \
  --set falcoctl.config.artifact.follow.refs[0]=ghcr.io/falcosecurity/rules/falco-rules@sha256:36d143c0ae2d5569da0274ea6bef188bac02b95abe51e44cfff16f38d3d6b9e0 \
  --set collectors.containerEngine.pluginRef=ghcr.io/falcosecurity/plugins/plugin/container@sha256:f3d531f370e8e7907f5fbfc27f8cf99863563ae02174e420f8bbf8b2b4828891 \
  --set collectors.kubernetes.enabled=false \
  --set falcosidekick.enabled=false \
  --set falcosidekick.webui.enabled=false \
  --set tty=true \
  --timeout 10m --wait
```

Why each override, grouped:

- `driver.kind=modern_ebpf` — states the driver decision in the command instead
  of leaving it to the chart default `auto`. On this cluster it is the *only*
  viable driver: all three kind nodes run kernel
  `6.18.33.2-microsoft-standard-WSL2`, which exposes BTF
  (`/sys/kernel/btf/vmlinux`) so the CO-RE eBPF probe loads, while the kmod path
  has no prebuilt module and no kernel headers on the node to build one. `auto`
  would have resolved to the same thing but silently; this makes it greppable.
- `image.tag=…@sha256:…` and `falcoctl.image.tag=…@sha256:…` — pin both images
  by their **manifest-list** digest, the form the kubelet resolves for a
  multi-arch node (verified: `docker buildx imagetools inspect` reports
  `manifest.list` / `oci.image.index` media types for both). The chart has no
  `image.digest` field; pinning is done by putting `tag@sha256:` in the tag,
  exactly as `workloads/nginx/deployment.yaml` does. Note that
  `restrict-registries` and the other Kyverno policies are scoped to
  `[demo, demo-kyverno-only]` and do **not** reach the `falco` namespace, so
  nothing on the cluster *compelled* this pin — it is the repo's standard, not
  Kyverno's reach.
- `falcoctl.artifact.follow.enabled=false` — the chart default runs a sidecar
  that re-pulls the ruleset every 168h. A self-updating detection ruleset in a
  repo whose thesis is immutability is a contradiction, so the follower is
  disabled and the ruleset is frozen at the digest below. The committed evidence
  therefore describes the ruleset that will actually be running, not a snapshot
  of something that drifts.
- `falcoctl.config.artifact.install.refs[0]=…@sha256:…` (and the matching
  `follow.refs[0]`) — pin the **ruleset** OCI artifact by digest instead of the
  floating tag `falco-rules:5`. falcoctl 0.13.0 accepts the `<repo>@sha256:`
  form and cosign-verifies it (proven in the init-container log in
  `attack-output.txt`).
- `collectors.containerEngine.pluginRef=…@sha256:…` — pin the **container
  metadata plugin**, `ghcr.io/falcosecurity/plugins/plugin/container`. This one
  is easy to miss: it is a chart value, not a `falcoctl` ref, and the first
  install attempt left it on the floating tag `:0.7.1` even with the rules
  pinned. Setting `pluginRef` to the digest closes the last unpinned OCI
  artifact. The plugin only enriches events with pod/namespace/image metadata;
  it is not part of detection.
- `collectors.kubernetes.enabled=false` — the `k8s-metacollector` add-on is not
  installed; the container plugin already supplies the k8s fields seen in the
  alerts, and turning it off keeps the footprint to a single DaemonSet.
- `falcosidekick.enabled=false`, `falcosidekick.webui.enabled=false` — the alert
  fan-out component is deliberately NOT installed. It is what would turn a line
  in a pod log into a page that reaches a human, and it needs a real
  destination (Slack, PagerDuty, a log store) that this lab does not have.
  Standing up a fake one would produce a screenshot, not a control. Its absence
  is exactly why this phase is detection, not response — see threat model §6.13.
- `tty=true` — makes Falco line-buffer its stdout so `kubectl logs` shows alerts
  promptly; it does not affect detection.

Not set, and worth noting because a reader may assume otherwise: **no `hostPID`,
no `hostNetwork`, no `/dev` mount.** The chart does not request them for
`modern_ebpf`. The cost is one line in the startup log — `libpman: disabled BPF
iterators (not running in the root PID namespace)` — so this is not a
fully-featured deployment and no full host process-tree visibility is claimed.
The falco container still runs `privileged: true` (chart default for
`modern_ebpf`, since `driver.modernEbpf.leastPrivileged` defaults to false); the
least-privileged capability set was NOT adopted, so the sensor runs with more
privilege than it strictly needs. That is an unremediated gap, recorded in
threat model §6.13, not a claim of minimal privilege.

## Pinned versions (observed)

| What | Value |
| --- | --- |
| Helm chart | `falcosecurity/falco` **9.1.0** (pinned via `--version`) |
| App version | **0.44.1** (`helm list -n falco` APP VERSION; `Falco version: 0.44.1` in the pod log) |
| Falco image | `docker.io/falcosecurity/falco:0.44.1` |
| Falco image digest | `sha256:d0cfe422d6ac0e0f20857798f46c7d7273210e1b064b22821e4e6e7f843cde6b` (manifest list) |
| falcoctl image | `docker.io/falcosecurity/falcoctl:0.13.0` |
| falcoctl image digest | `sha256:0eeb79adc580ae6a5abfdefd7f8f0fed9151fcb545f015c84e8f1d7b2d8a6b02` (manifest list) |
| Ruleset artifact | `ghcr.io/falcosecurity/rules/falco-rules` pinned by digest `sha256:36d143c0ae2d5569da0274ea6bef188bac02b95abe51e44cfff16f38d3d6b9e0` (tag was `5`) |
| Container plugin | `ghcr.io/falcosecurity/plugins/plugin/container` pinned by digest `sha256:f3d531f370e8e7907f5fbfc27f8cf99863563ae02174e420f8bbf8b2b4828891` (tag was `0.7.1`) |
| Driver | **`modern_ebpf`** — resolved on-cluster, see below |

`helm list -n falco`:

```
NAME 	NAMESPACE	REVISION	UPDATED                              	STATUS  	CHART      	APP VERSION
falco	falco    	1       	2026-07-29 10:07:44.9542527 -0500 CDT	deployed	falco-9.1.0	0.44.1
```

The DaemonSet rolled out 3/3 within ~30s (one pod per node, 0 restarts). All
four OCI artifacts — the two images plus the rules and plugin — are digest-pinned
and, for the two ghcr artifacts, cosign-verified by the `falcoctl-artifact-install`
init container at pull time (`Signature successfully verified!`).

## Driver resolved on-cluster

The install requests `modern_ebpf`; this is confirmed against ground truth, not
taken from the flag (the tool's own word is not evidence — see the phase-5
lesson). From the running pod on `seclab-worker`:

```
$ kubectl -n falco exec <pod> -c falco -- sed -n '/^engine:/,/^[a-z]/p' /etc/falco/falco.yaml
engine:
  kind: modern_ebpf
  modern_ebpf:
    buf_size_preset: 4
    cpus_for_each_buffer: 2
    ...
```

Startup log: `Opening 'syscall' source with modern BPF probe.` No kernel module
is loaded on any node (`lsmod | grep -E 'falco|scap'` is empty cluster-wide), so
events cannot be kmod-sourced; and Falco PID 1 holds live BPF objects in
`/proc/1/fd` (13 `bpf`, 14 `bpf-map`, 197 `bpf-prog`). No fallback to another
driver occurred (0 restarts). Full capture in
`docs/evidence/phase-6-falco/attack-output.txt`.

## Admission note

The `falco` namespace is labelled `pod-security.kubernetes.io/enforce:
privileged` precisely because the DaemonSet is a `restricted`-profile violation
(privileged, hostPath mounts, no capability drop). The install command above
prints the full PSA `warn` list to prove it. The same spec is REFUSED by `demo`
— as a Pod by PodSecurity Admission and as a DaemonSet by Kyverno — and that
two-controls-two-object-forms demonstration, including which control answers
which form, is captured in `docs/evidence/phase-6-falco/`. The four Kyverno
`ValidatingPolicy` rules and the `ImageValidatingPolicy` are scoped by
namespaceSelector to `[demo, demo-kyverno-only]`, so none of them evaluates
anything in the `falco` namespace; that unenforced namespace is a second
concrete instance of the residual risk conceded in threat model §6.7, alongside
`cis-benchmark`.
