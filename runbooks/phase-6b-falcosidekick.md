# Runbook — Phase 6b: Alert routing (falcosidekick, so the alert outlives the sensor)

A replayable command log for the one thing phase 6 left undone: giving the
Falco alert a next hop. The `falco` Helm release is upgraded in place from
REVISION 1 to REVISION 2 with `falcosidekick.enabled=true` and
`falcosidekick.webui.enabled=true`, three new images pinned by manifest-list
digest, Falco's own `json_output` and `http_output` proved changed inside the
running container rather than read off the chart, one marked attack followed
end to end from the syscall to the Web UI's Redis, and then every sensor pod
on the cluster destroyed to show the alert still there. Commands are in
execution order; each has a one-line purpose and the observed output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash
unless noted. Kubernetes node image v1.35.5, kernel
`6.18.33.2-microsoft-standard-WSL2`, Falco 0.44.1 (chart
`falcosecurity/falco` 9.1.0, unchanged by this phase), falcosidekick 2.32.0
from subchart `falcosidekick` 0.12.1, falcosidekick-ui 2.2.0,
`redis/redis-stack` 7.2.0-v11. Any `kubectl exec` that passes an in-container
path needs `MSYS_NO_PATHCONV=1` in the environment: Git Bash rewrites
`/bin/sh` and `/etc/falco/falco.yaml` into Windows paths and the resulting
error looks like a missing file inside the container. It is not. Same trap as
phase 6 sections 2d, 3e and 4.

**Five honesty caveats, up front — they are part of the deliverable, not
footnotes:**

1. **This phase still blocks NOTHING. It routes.** Phase 6's first caveat
   stands unamended: Falco detects and does not prevent. The attack in
   section 4 succeeded, printed its output and exited 0, exactly as both
   phase 6 behaviours did. 6b earns **no row** in the threat model's
   Control → ATT&CK table for the same reason phase 6 earned none. What 6b
   does falsify is broader than one sentence: it retires every present-tense
   output-channel reading in phase 6's runbook — the header's "routed,
   stored", caveat 2's pipeline list, the `http_output: false` /
   `json_output: false` readings and *"the line's next hop does not exist"*,
   "no rule name is printed anywhere", and "the retention model is: none".
   Those readings are preserved there as the pre-upgrade state and marked at
   each site — see the dated pointer under phase 6's title. What that runbook
   says that 6b leaves standing: nothing is blocked, nobody is paged, and
   there is no Talon, no rota and no owner.
2. **Still NOBODY IS PAGED.** falcosidekick ships integrations for Slack,
   Teams, PagerDuty, Opsgenie, SMTP and dozens more. **Exactly one output is
   enabled and it is the in-cluster Web UI** — proved in section 6 from
   falcosidekick's own startup line, not from the values. No credential was
   entered anywhere in this phase and nothing in this release can reach
   outside the cluster. There is no rota, no owner and no notification. An
   alert in a dashboard nobody opens is still an alert nobody reads.
3. **The store is NOT durable, and this was TESTED rather than read off the
   spec.** The Redis gets a real 1Gi PersistentVolumeClaim, Bound, mounted at
   `/data` — and it **lost every stored event when its pod was deleted**
   (section 5b), because redis-stack's default RDB thresholds (`save 3600 1
   300 100 60 10000`) were never met at this lab's alert volume and no
   snapshot had ever been written. Worse, the ingest path then **stayed
   broken** until the Web UI Deployment was manually restarted. What 6b buys
   is survival of the SENSOR, not survival of the STORE.
4. **6b ADDS attack surface: five new pods, three new images, an
   unauthenticated Redis and a default credential.** They run in the same
   unenforced `falco` namespace as the sensor — PSA `enforce: privileged`,
   outside every Kyverno `namespaceSelector`. Section 7 reads the apiserver's
   own verdict: they would fail `restricted` on **four** categories, not
   phase 6's six, and all four are boilerplate fields the chart already
   exposes. **"Could be gated and is not" is the honest sentence**, and
   closing it was deliberately left out of a routing upgrade.
5. **Threat model §6.13 item 6 is AMENDED, not closed.** Alerts now survive a
   pod restart, which is what that item was about. They do not survive a Redis
   restart, a `kind delete`, or anyone with network access to port 6379. And
   §6.4 is untouched: runtime behaviour is still detected and still not
   stopped.

---

## 0. What changes, and what does not

This section is the house's `## 0. The controls`, retitled for the third time
and for the same reason phases 5 and 6 retitled it: **there are no new
controls in this phase.** Phase 5 measured, phase 6 watched, 6b files what
phase 6 saw. None of the three blocks anything.

- **falcosidekick 2.32.0, a Deployment of 2 replicas** — accepts Falco's JSON
  on `:2801` and fans it out to whatever destinations are configured. **What
  it does here:** exactly one destination, the Web UI. **What it does NOT
  do:** notify, escalate, retry to a second sink, or act.
- **falcosidekick-ui 2.2.0, a Deployment of 2 replicas** — a web front end
  reachable only by `kubectl port-forward` (section 8). It creates a
  RediSearch index at startup and writes each event into Redis as a hash.
- **`redis/redis-stack` 7.2.0-v11, a StatefulSet of 1** with a 1Gi PVC. This
  is where an alert actually lives after the sensor that raised it is gone.
- **Falco itself: UNCHANGED.** Same app 0.44.1, same image digest, same
  pinned ruleset artifact, same pinned container plugin, same `modern_ebpf`
  driver, same `privileged: true`, same twelve hostPath mounts. The only
  difference is four settings in `/etc/falco/falco.yaml` that the chart flips
  on its own (section 3).

### The three new images are pinned, and nothing made them

All five Kyverno policies are scoped by `namespaceSelector` to
`[demo, demo-kyverno-only]`, so **nothing on this cluster would have refused
an unpinned or unsigned image in `falco`**. Every pin below is self-imposed
and self-verified — the repo's standard, not Kyverno's reach. The pins prove
the bytes are stable; they do **not** prove the images are trustworthy. None
of the three was signature-verified (no cosign on this host, and unlike the
two ghcr artifacts phase 6 pinned, these are Docker Hub images with no
falcoctl init container to verify them).

### One kernel, three sensors — the rule still applies, and now it is visible

Every count in this phase is of distinct **events**, never of POSTs or of
stored documents. All three Falco pods see every syscall on the shared WSL2
kernel, so one attack produces **three** POSTs and **three** stored
documents. Section 4 shows the sidekick's own counters moving by exactly 3 for
one shell. Divide by three. Only the copy from the sensor co-located with the
target's containerd carries the `k8s_*` fields; the other two store them
empty.

---

## 1. Discovery — read the chart before changing anything

`helm show values falcosecurity/falco` is **not enough**: it prints a
three-key stub for `falcosidekick` (`enabled`, `fullfqdn`, `listenPort`)
because the real value tree lives in a dependency. Pull the chart:

```bash
helm pull falcosecurity/falco --version 9.1.0 --untar --untardir <scratch>
cat <scratch>/falco/Chart.lock
# dependencies:
# - name: falcosidekick
#   repository: https://falcosecurity.github.io/charts
#   version: 0.12.1
# [... k8s-metacollector 0.1.10 and falco-talon 0.3.0 elided ...]  (exit 0)
# => the subchart's values.yaml is 1419 lines; the webui block starts at 1220.
```

Four image tag paths matter, and **two of them are the same image** — the
Web UI's `wait-redis` init container and the Redis itself both run
`redis/redis-stack`:

| Value path | Default image |
| --- | --- |
| `falcosidekick.image.tag` | `docker.io/falcosecurity/falcosidekick:2.32.0` |
| `falcosidekick.webui.image.tag` | `docker.io/falcosecurity/falcosidekick-ui:2.2.0` |
| `falcosidekick.webui.initContainer.image.tag` | `docker.io/redis/redis-stack:7.2.0-v11` |
| `falcosidekick.webui.redis.image.tag` | `docker.io/redis/redis-stack:7.2.0-v11` |

**1a. THE CHART AUTO-WIRES FALCO'S CONFIG — you do NOT set `json_output`
yourself.** This is the question the phase turned on, and the answer is in the
parent chart's helpers:

```bash
sed -n '120,160p' <scratch>/falco/templates/_helpers.tpl
# [... 22 lines elided — the rbac helper and the falcosidekick.url helper ...]
# {{- define "falco.falcosidekickConfig" -}}
# {{- if .Values.falcosidekick.enabled  -}}
#     {{- $_ := set .Values.falco "json_output" true -}}
#     {{- $_ := set .Values.falco "json_include_output_property" true -}}
#     {{- $_ := set .Values.falco.http_output "enabled" true -}}
#     {{- $_ := set .Values.falco.http_output "url" (include "falcosidekick.url" .) -}}
# {{- end -}}                                                          (exit 0)
# => falcosidekick.enabled=true ALONE flips four Falco settings. No extra
#    --set flag was needed and none was used. That is the chart's INTENT;
#    section 3 proves it landed in the running container.
```

**1b. Render before applying, and read what it would create.** Two
Deployments, one StatefulSet, three Services — and, critically, the Redis is a
**StatefulSet with a real `volumeClaimTemplates`**, not an emptyDir:

```bash
helm template falco falcosecurity/falco --namespace falco --version 9.1.0 \
  <the 15 --set flags from section 2> > <raw>/rendered.yaml
sed -n '1364,1439p' <raw>/rendered.yaml
# [... 66 lines elided — metadata, selector, probes ...]
#   volumeClaimTemplates:
#     - apiVersion: v1
#       kind: PersistentVolumeClaim
#       metadata:
#         name: falco-falcosidekick-ui-redis-data
#       spec:
#         accessModes: [ "ReadWriteOnce" ]
#         resources:
#           requests:
#             storage: 1Gi                                             (exit 0)
# => read that and you would conclude the events persist. Section 5b tests it
#    and they do not. This is why the repo proves things from behaviour.
```

**1c. A FOURTH IMAGE EXISTS IN THE CHART AND IS NOT PINNED.** It is gated by
one annotation and `helm upgrade` never creates it:

```bash
sed -n '1440,1460p' <raw>/rendered.yaml
# [... 12 of the 21 lines elided — apiVersion, the labels block, the curl
#  command/args and restartPolicy; the block appears in full in the evidence
#  file §2d ...]
# kind: Pod
# metadata:
#   name: "falco-falcosidekick-test-connection"
#   annotations:
#     "helm.sh/hook": test-success
# spec:
#   containers:
#     - name: curl
#       image: appropriate/curl                                        (exit 0)
# => NO REGISTRY, NO TAG, NO DIGEST. `helm test falco` WOULD create it and
#    pull docker.io/appropriate/curl:latest. THAT COMMAND WAS NOT RUN and must
#    not be while the repo's thesis is immutability. Dormant, not absent —
#    recorded because phase 6 section 2e was marked down for exactly this
#    failure mode.
```

**1d. Resolve a manifest-list digest for each of the three images.** Same
standard and same tool as phase 6:

```bash
docker buildx imagetools inspect falcosecurity/falcosidekick:2.32.0
# Name:      docker.io/falcosecurity/falcosidekick:2.32.0
# MediaType: application/vnd.docker.distribution.manifest.list.v2+json
# Digest:    sha256:1976da72151850aae4436f33a5ed94bdef469f42a9b61c182b4feeb5441fb081
# [... per-platform manifest entries elided ...]                       (exit 0)

docker buildx imagetools inspect falcosecurity/falcosidekick-ui:2.2.0
# Digest:    sha256:0faadedfdff7e6af8be0d7d90efb0638cedc337e4e5c3e57f527da2f6722c851  (exit 0)

docker buildx imagetools inspect redis/redis-stack:7.2.0-v11
# Digest:    sha256:96a8426b991a06c1e07198c5af5a62d0b24e87a7dfd6a1efaff19c2d80af836b  (exit 0)
# => the `Digest:` line is the manifest-LIST digest and is what gets pinned.
#    The per-platform `Name:` lines carry a DIFFERENT digest (the amd64
#    image's own) and pinning that one breaks on any other architecture. The
#    redis list prints linux/arm64 FIRST, which is the reminder that the first
#    entry is not "the" image.
```

**1e. Capture the before-state, because the upgrade destroys it.** The
DaemonSet restarts and takes its logs with it — which is itself a live
demonstration of the problem 6b fixes:

```bash
date -u +"%Y-%m-%dT%H:%M:%S.%NZ"
for p in falco-g8d62 falco-hzkbw falco-lbrt9; do
  echo "== $p =="
  kubectl -n falco logs $p -c falco | grep -oE '^[0-9:.]+: (Notice|Warning|Error|Critical) [A-Za-z /]+'
done
# 2026-08-03T18:35:44.205947000Z
# == falco-g8d62 ==
# 17:15:58.596277394: Notice Unexpected connection to K
# 17:15:59.106566367: Notice Unexpected connection to K
# 17:16:53.685165726: Notice Unexpected connection to K
# == falco-hzkbw ==
# [... the same three, plus 18:34:56.191257800: Notice Shell spawned by untrusted binary ...]
# == falco-lbrt9 ==
# 17:16:53.683726256: Notice Unexpected connection to K                (exit 0)
# => the `[A-Za-z /]+` class stops at the digit in "K8s", which is why every
#    line ends at "K". FOUR DISTINCT EVENTS. lbrt9's container started 29 s
#    later than the other two, which accounts for its two missing lines; the
#    one-pod-only shell alert is NOT accounted for and no reason is offered.
```

Also read the output channels out of a running container, so section 3 has
something to compare against — `json_output: false`, `http_output.enabled:
false`, `http_output.url: ""`. Full capture in
`docs/evidence/phase-6b-falcosidekick/attack-output.txt` §1b.

---

## 2. The upgrade — every existing flag restated, and why

**`--reuse-values` is NOT used, and that is deliberate.** This repo keeps no
`values.yaml` anywhere; the written command IS the record. A command naming
only the deltas would stop replaying the install, so REVISION 1's eleven
`--set` flags are restated verbatim. Two change value, four are added.

The full command with every override justified line by line lives in
[`clusters/falco-install.md`](../clusters/falco-install.md) and is not
duplicated here; what matters for the runbook is what it printed:

```bash
helm upgrade falco falcosecurity/falco --namespace falco --version 9.1.0 \
  --set driver.kind=modern_ebpf --set image.tag=0.44.1@sha256:d0cfe422d6ac... \
  ... --set falcosidekick.enabled=true --set falcosidekick.webui.enabled=true \
  --set falcosidekick.image.tag=2.32.0@sha256:1976da721518... \
  --set falcosidekick.webui.image.tag=2.2.0@sha256:0faadedfdff7... \
  --set falcosidekick.webui.initContainer.image.tag=7.2.0-v11@sha256:96a8426b991a... \
  --set falcosidekick.webui.redis.image.tag=7.2.0-v11@sha256:96a8426b991a... \
  --set tty=true --timeout 10m --wait
# Warning: would violate PodSecurity "restricted:latest": privileged
# (container "falco" ...), ... restricted volume types (...12 hostPath...)
# Warning: would violate PodSecurity "restricted:latest":
# allowPrivilegeEscalation != false (containers "wait-redis",
# "falcosidekick-ui" ...), unrestricted capabilities (...), runAsNonRoot !=
# true (...), seccompProfile (...)
# Warning: would violate PodSecurity "restricted:latest": ... (container
# "falcosidekick" ...)
# Warning: would violate PodSecurity "restricted:latest": ... (container
# "redis" ...)
# Release "falco" has been upgraded. Happy Helming!
# NAME: falco
# LAST DEPLOYED: Mon Aug  3 13:36:16 2026
# STATUS: deployed
# REVISION: 2
# DESCRIPTION: Upgrade complete                                        (exit 0)
# => FOUR PSA warnings, not one. The namespace's `warn: restricted` label
#    makes the apiserver enumerate what each new workload does that
#    `restricted` forbids. That is section 7's evidence and it arrived free.
#    First attempt, no retry, no rollback. The four warnings are quoted in
#    full, unwrapped, in the evidence file §3.
```

```bash
helm -n falco list
# NAME   NAMESPACE  REVISION  UPDATED                              STATUS
# falco  falco      2         2026-08-03 13:36:16.905806 -0500 CDT  deployed
#   CHART: falco-9.1.0    APP VERSION: 0.44.1                        (exit 0)

kubectl -n falco get pods,svc,deploy,statefulset,pvc
# pod/falco-falcosidekick-ccbb99b56-cmh2b      1/1  Running  0  82s
# pod/falco-falcosidekick-ccbb99b56-qtjxm      1/1  Running  0  82s
# pod/falco-falcosidekick-ui-d4779ff66-bn2jj   1/1  Running  0  82s
# pod/falco-falcosidekick-ui-d4779ff66-zs94v   1/1  Running  0  82s
# pod/falco-falcosidekick-ui-redis-0           1/1  Running  0  82s
# pod/falco-p95h2 / falco-p9ljh / falco-t827z  1/1  Running  0  (DaemonSet)
# service/falco-falcosidekick            ClusterIP  2801/TCP,2810/TCP
# service/falco-falcosidekick-ui         ClusterIP  2802/TCP
# service/falco-falcosidekick-ui-redis   ClusterIP  6379/TCP
# deployment/falco-falcosidekick     2/2  ...falcosidekick:2.32.0@sha256:1976da...
# deployment/falco-falcosidekick-ui  2/2  ...falcosidekick-ui:2.2.0@sha256:0faade...
# statefulset/falco-falcosidekick-ui-redis 1/1 ...redis-stack:7.2.0-v11@sha256:96a842...
# pvc/falco-falcosidekick-ui-redis-data-...-0  Bound  1Gi  RWO  standard  (exit 0)
# => all three pinned digests are on the LIVE objects, not just in the
#    command. Note the sidekick Service exposes TWO ports: 2801 (alert
#    intake) and 2810 (its own Prometheus metrics).
```

**Running is not the proof.** Sections 3 to 5 are. The full unwrapped output
of every command above is in the evidence file §3.

**2a. And the pre-upgrade alerts are gone**, which is the problem statement
demonstrated on the way past:

```bash
kubectl -n falco logs falco-g8d62 -c falco
# error: error from server (NotFound): pods "falco-g8d62" not found in
# namespace "falco"                                                    (exit 1)

for p in falco-p95h2 falco-p9ljh falco-t827z; do
  kubectl -n falco logs $p -c falco | grep -cE 'Unexpected connection to K8s API Server'
done
# 0
# 0
# 0                                              (exit 1 — grep's, no match)
# => THE UPGRADE THAT INSTALLS THE FIX DESTROYS THE EVIDENCE THE FIX WOULD
#    HAVE SAVED. Those four events are unrecoverable from anywhere on this
#    cluster. Same loss the 2026-07-30 rebuild caused (threat model §6.13
#    item 6), and the last time it happens for a routed alert.
```

---

## 3. Falco's own config actually changed — read from the running container

Section 1a showed the chart's **intent**. This is the running sensor, read the
phase-6 way, and it is the only thing that settles it:

```bash
MSYS_NO_PATHCONV=1 kubectl -n falco exec falco-p95h2 -c falco -- \
  sed -n '/^http_output:/,/^[a-z]/p' /etc/falco/falco.yaml
# http_output:
#   [... 7 lines elided — ca_bundle, ca_cert, ca_path, client_cert,
#        client_key, compress_uploads, echo; unchanged from before ...]
#   enabled: true
#   [... 4 lines elided — insecure, keep_alive, max_consecutive_timeouts, mtls ...]
#   url: http://falco-falcosidekick:2801
#   user_agent: falcosecurity/falco
# json_include_message_property: false                                 (exit 0)
# (`json_include_message_property` is the sed range's closing line — the next
#  top-level key — not part of the http_output block. Kept because the
#  command prints it.)

kubectl -n falco exec falco-p95h2 -c falco -- \
  grep -E '^json_output:|^json_include_output_property:' /etc/falco/falco.yaml
# json_include_output_property: true
# json_output: true                                                    (exit 0)
# => compare against section 1e's before-reading, line for line:
#      enabled: false            ->  enabled: true
#      url: ""                   ->  url: http://falco-falcosidekick:2801
#      json_output: false        ->  json_output: true
#    NOT ONE --set FLAG NAMED ANY OF THOSE THREE. The helper from 1a did it.
```

`stdout_output` is still `enabled: true`, so the old channel still works and
phase 6's runbook does not become wrong. And `json_output: true` has a second
consequence: **phase 6 had to record rule NAMES as "a named unverified
input"** because no alert line carried one. From here on the rule name is a
captured field — section 4 reads `"rule":"Terminal shell in container"`
straight out of the stored event.

---

## 4. The routed alert, end to end, with a marker

**4a. Baseline the sidekick PER POD, not through the Service.** falcosidekick
runs 2 replicas and each keeps its own counters, so a curl to the Service
returns whichever pod answered and is useless as a baseline. Both are queried
directly through the apiserver's pod-proxy subresource:

```bash
for p in <the two sidekick pods>; do
  kubectl -n falco get --raw "/api/v1/namespaces/falco/pods/$p:2801/proxy/metrics" \
    | grep -E "^falcosecurity_falcosidekick_(falco_events_total|inputs_total|outputs_total)"
done
# == falco-falcosidekick-ccbb99b56-cmh2b ==
# ..._falco_events_total{hostname="seclab-worker2",...,rule="Run shell untrusted",...} 1
# ..._inputs_total{source="requests",status="accepted"} 1
# ..._outputs_total{destination="webui",status="ok"} 1
# == falco-falcosidekick-ccbb99b56-qtjxm ==
#                              (exit 1 — grep's; this pod prints no lines)
# => BASELINE = 1 event cluster-wide. It is not from an attack: it is `Run
#    shell untrusted`, fired by this evidence run's OWN kubectl exec into a
#    falco container three minutes earlier. Recorded, not filtered.

kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli DBSIZE
# 1                                                                    (exit 0)
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli FT._LIST
# eventIndex                                                           (exit 0)
# => remember that RediSearch index. Section 5c is about what happens to it.
```

**4b. The attack — phase 6 section 3a's method exactly.** The stock rule
requires `proc.tty != 0`, and `kubectl exec -it` from Git Bash does NOT
allocate a PTY, so the exec is driven through util-linux `script` on the
control-plane node. Target is the hardened `demo/nginx` pod (PSA
`enforce: restricted`, uid 101, all capabilities dropped, read-only root
filesystem), not a helper pod stood up to be easy to detect:

```bash
echo "T0=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
docker exec seclab-control-plane script -q -c "kubectl exec -it -n demo nginx-78c88678f4-8k5lb -- /bin/sh -c 'tty; id; echo P6B-ROUTED-MARKER'" /dev/null
echo "T1=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)"
# T0=2026-08-03T18:39:03.234989100Z
# ^@/dev/pts/0
# uid=101(nginx) gid=101(nginx) groups=101(nginx)
# P6B-ROUTED-MARKER                                                    (exit 0)
# T1=2026-08-03T18:39:03.694388700Z
# => a real PTY and uid 101. THE ATTACK SUCCEEDED — it printed its output and
#    exited 0. Nothing blocked it, exactly as in phase 6. Window is 459.4 ms.
```

**4c. The same event at the sidekick, 8 seconds later:**

```bash
# same per-pod metrics command as 4a
# == cmh2b ==  inputs_total 3   outputs_total{...,status="ok"} 3
#              falco_events_total{hostname="seclab-control-plane",...,
#                rule="Terminal shell in container",...} 1
#              falco_events_total{hostname="seclab-worker2",...,
#                rule="Terminal shell in container",...} 1
# == qtjxm ==  inputs_total 1   outputs_total{...,status="ok"} 1
#              falco_events_total{hostname="seclab-worker",
#                k8s_ns_name="demo",k8s_pod_name="nginx-78c88678f4-8k5lb",
#                ...,rule="Terminal shell in container",...} 1         (exit 0)
# => the arithmetic, written out rather than asserted:
#      inputs_total  cmh2b  1 -> 3   (+2)
#      inputs_total  qtjxm  0 -> 1   (+1)   the metric did not exist before
#      TOTAL                1 -> 4   (+3)
#    THREE POSTs FOR ONE ATTACK — phase 6 §3c's shared-kernel artifact,
#    arriving at the sidekick. DIVIDE BY THREE. The Service's round-robin
#    split them 2/1, which is why per-pod baselines were necessary.
#    Only the qtjxm copy carries k8s_ns_name / k8s_pod_name: that is the
#    sensor co-located with the target's containerd. The other two are empty.

kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli DBSIZE
# 4                                                                    (exit 0)
# => 1 -> 4. The store agrees with the counters.
```

**4d. The stored event itself.** falcosidekick-ui stores each event as a Redis
**hash** — `JSON.GET` returns `Existing key has wrong Redis type` — with the
whole event in a `json` field:

```bash
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- \
  redis-cli HGET event:a6c5ccd6-3d83-4dce-9487-1bf0270eea55 json
# {"uuid":"a6c5ccd6-...","output":"18:39:03.551716000: Notice A shell was
#  spawned in a container with an attached terminal | ... command=sh -c tty;
#  id; echo P6B-ROUTED-MARKER terminal=34816 ... container_name=nginx
#  container_image_repository=docker.io/nginxinc/nginx-unprivileged
#  k8s_pod_name=nginx-78c88678f4-8k5lb k8s_ns_name=demo",
#  "priority":"Notice","rule":"Terminal shell in container",
#  "time":"2026-08-03T18:39:03.551716Z","source":"syscall",
#  "output_fields":{... "proc.cmdline":"sh -c tty; id; echo
#  P6B-ROUTED-MARKER", "proc.tty":34816, "user.uid":101 ...},
#  "hostname":"seclab-worker",
#  "tags":["","T1059","container","maturity_stable","mitre_execution","shell"]}
#                                                                      (exit 0)
# (FLOWED to fit the page. The document is one line and appears in full,
#  unflowed, in the evidence file §5d. Read that one to check the wording.)
# => THE MARKER IS IN THE STORED EVENT TWICE — in the human `output` string
#    and in the structured field "proc.cmdline". "time" 18:39:03.551716Z sits
#    inside the 4b window. "proc.tty":34816 is the non-zero TTY the rule
#    requires; "user.uid":101 confirms it fired against the NON-ROOT hardened
#    workload. THREE THINGS HERE DID NOT EXIST IN PHASE 6 AT ALL: the rule
#    NAME as a field, the ruleset's own ATT&CK tag T1059, and a stable uuid.
```

```bash
grep -c "P6B-ROUTED-MARKER" <raw>/s4-redis-all-events-json.txt
# 3                                                                    (exit 0)
# => 3 of the 4 stored documents carry the marker: the triplication again.
#    The fourth is the pre-attack event from the 4a baseline.
```

---

## 5. The two things that were tested rather than assumed

**5a. SURVIVAL ACROSS THE SENSOR'S DEATH — the point of the phase.** Kill the
pod that produced the alert, then kill the other two so no reader has to
wonder whether a survivor still held a copy. The DaemonSet recreates them;
this is safe and reversible:

```bash
kubectl -n falco logs falco-p95h2 -c falco | grep -c "P6B-ROUTED-MARKER"
# 1                                                                    (exit 0)

kubectl -n falco delete pod falco-p95h2
# pod "falco-p95h2" deleted from falco namespace                       (exit 0)
kubectl -n falco logs falco-p95h2 -c falco
# error: error from server (NotFound): pods "falco-p95h2" not found in
# namespace "falco"                                                    (exit 1)

kubectl -n falco delete pod -l app.kubernetes.io/name=falco
# pod "falco-p9ljh" deleted from falco namespace
# pod "falco-rlw27" deleted from falco namespace
# pod "falco-t827z" deleted from falco namespace                       (exit 0)
kubectl -n falco rollout status daemonset/falco --timeout=180s
# [... 3 "Waiting for daemon set" lines elided ...]
# daemon set "falco" successfully rolled out                           (exit 0)

for p in <the three NEW falco pods>; do
  echo -n "$p P6B-ROUTED-MARKER-lines="
  kubectl -n falco logs $p -c falco | grep -c "P6B-ROUTED-MARKER"
done
# falco-6hp56 P6B-ROUTED-MARKER-lines=0
# falco-cq9ck P6B-ROUTED-MARKER-lines=0
# falco-tz6ts P6B-ROUTED-MARKER-lines=0          (exit 1 — grep's, no match)
# => THE STDOUT CHANNEL IS COMPLETELY WIPED. Under phase 6 this is the moment
#    the alert ceased to exist. `kubectl logs --previous` cannot help: these
#    are new PODS, not restarted containers.

kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli DBSIZE
# 4                                                                    (exit 0)
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- \
  redis-cli HGET event:a6c5ccd6-3d83-4dce-9487-1bf0270eea55 json
# {"uuid":"a6c5ccd6-...","output":"... P6B-ROUTED-MARKER ...
#  k8s_ns_name=demo", ... }                                            (exit 0)
# => SAME UUID, SAME MARKER, SAME k8s METADATA, AFTER EVERY SENSOR THAT SAW
#    IT WAS DESTROYED. THAT IS THE ONE THING 6b ADDS THAT PHASE 6 DID NOT
#    HAVE. It is also the ONLY thing.
```

**5b. AND THE STORE IS NOT DURABLE.** Section 1b's rendered spec promised a
1Gi PVC and section 2 showed it Bound. Read the actual persistence config out
of the running Redis, then test it:

```bash
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli CONFIG GET save
# save
# 3600 1 300 100 60 10000
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli CONFIG GET appendonly
# appendonly
# no                                                                   (exit 0)
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- ls -la /data
# total 8
# drwxrwxrwx 2 root root 4096 Aug  3 18:36 .
# drwxr-xr-x 1 root root 4096 Aug  3 18:36 ..                          (exit 0)
# => RDB SNAPSHOTS ONLY, NO AOF, AND /data IS EMPTY. The thresholds are "1
#    change in 3600 s", "100 in 300 s", "10000 in 60 s". This lab produced 4
#    changes in ~6 minutes, meeting none. THERE IS NO dump.rdb. Every stored
#    event exists only in RAM, on a volume whose whole purpose is to stop
#    that being true.

kubectl -n falco delete pod falco-falcosidekick-ui-redis-0
# pod "falco-falcosidekick-ui-redis-0" deleted from falco namespace    (exit 0)
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli DBSIZE
# 0                                                                    (exit 0)
kubectl -n falco get pvc
# falco-falcosidekick-ui-redis-data-...-0  Bound  1Gi  RWO  standard   (exit 0)
# => DBSIZE 4 -> 0. THE PVC IS STILL BOUND, STILL THE SAME VOLUME, AND EVERY
#    EVENT IS GONE — including the one 5a just proved survives a sensor
#    restart. 6b buys survival of the SENSOR, not survival of the STORE.
#    Both sentences are needed and neither implies the other.
```

**5c. AND IT IS WORSE THAN LOSING THE DATA — THE INGEST PATH STAYED BROKEN.**
Fire a fresh marked attack after the Redis restart and watch it fail to land:

```bash
docker exec seclab-control-plane script -q -c "kubectl exec -it -n demo nginx-78c88678f4-8k5lb -- /bin/sh -c 'echo P6B-REDIS-RESTART-MARKER'" /dev/null
# P6B-REDIS-RESTART-MARKER                                             (exit 0)
for p in <the three falco pods>; do kubectl -n falco logs $p -c falco | grep -c "P6B-REDIS-RESTART-MARKER"; done
# 1 / 1 / 1
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli DBSIZE
# 0                                                                    (exit 0)
# => ALL THREE SENSORS DETECTED IT AND THE STORE STAYED EMPTY.

kubectl -n falco logs -l app.kubernetes.io/component=core --tail=10 --prefix
# [.../falcosidekick] 2026/08/03 18:42:56 [ERROR] : WebUI - exceeding post rate limit (500)
# [.../falcosidekick] 2026/08/03 18:42:56 [ERROR] : WebUI - internal server error  (exit 0)

kubectl -n falco logs -l app.kubernetes.io/component=ui -c falcosidekick-ui --tail=20 --prefix
# [...-bn2jj/falcosidekick-ui] 2026/08/03 18:36:58 [WARN] : Index does not exist
# [...-bn2jj/falcosidekick-ui] 2026/08/03 18:36:58 [WARN] : Create Index
# [...-bn2jj/falcosidekick-ui] 2026/08/03 18:42:24 [ERROR]: [0] dial tcp
#   10.96.245.44:6379: connect: connection refused
# [...-bn2jj/falcosidekick-ui] 2026/08/03 18:42:56 [ERROR]: [0] Unknown index name
# [...-zs94v/falcosidekick-ui] 2026/08/03 18:42:56 [ERROR]: [0] Unknown index name  (exit 0)
# => ROOT CAUSE IN THE COMPONENT'S OWN WORDS: `Unknown index name`. The
#    `eventIndex` from 4a is created ONCE, AT STARTUP. The Redis restart took
#    the index with the data and the UI never recreates it, so every write
#    fails. falcosidekick surfaces that as HTTP 500 and MISLABELS it
#    "exceeding post rate limit" — a misleading message pointing at the wrong
#    cause, worth knowing before someone tunes a rate limit that is not the
#    problem. NOTHING SELF-HEALED.
```

Recovery, and the release is left healthy:

```bash
kubectl -n falco rollout restart deployment/falco-falcosidekick-ui
# Warning: would violate PodSecurity "restricted:latest": ...
# deployment.apps/falco-falcosidekick-ui restarted                     (exit 0)
kubectl -n falco rollout status deployment/falco-falcosidekick-ui --timeout=180s
# [... 6 "Waiting for deployment" lines elided ...]
# deployment "falco-falcosidekick-ui" successfully rolled out          (exit 0)

docker exec seclab-control-plane script -q -c "kubectl exec -it -n demo nginx-78c88678f4-8k5lb -- /bin/sh -c 'echo P6B-RECOVERY-MARKER'" /dev/null
# P6B-RECOVERY-MARKER                                                  (exit 0)
kubectl -n falco exec falco-falcosidekick-ui-redis-0 -- redis-cli DBSIZE
# 4                                                                    (exit 0)
# => INGEST RESTORED. Three of the four stored documents carry the recovery
#    marker. Note that the seclab-worker2 sensor filed its copy of the SAME
#    execve under rule `Run shell untrusted` rather than `Terminal shell in
#    container`; no command in this run establishes why, so no reason is
#    offered. Recorded because a reader counting by rule name would get a
#    different answer than one counting by marker.
# THE OPERATIONAL SENTENCE THIS EARNS: this pipeline has a single point of
# failure that loses all history AND silently stops accepting new events, and
# the only thing that noticed was a human running `grep` on purpose. Nothing
# alerted on the alerting being down.
```

---

## 6. Nothing pages anybody, and it all dies with the cluster

```bash
kubectl -n falco logs -l app.kubernetes.io/component=core --tail=200 --prefix \
  | grep 'Enabled Outputs'
# [pod/falco-falcosidekick-ccbb99b56-cmh2b/falcosidekick] 2026/08/03 18:36:22 [INFO]  : Enabled Outputs: [WebUI]
# [pod/falco-falcosidekick-ccbb99b56-qtjxm/falcosidekick] 2026/08/03 18:36:22 [INFO]  : Enabled Outputs: [WebUI]
#                                                                      (exit 0)
# => ONE OUTPUT. No credential of any kind was entered and nothing in this
#    release can reach outside the cluster.

kubectl get pv -o custom-columns=NAME:.metadata.name,PATH:.spec.hostPath.path,NODE:'.spec.nodeAffinity.required.nodeSelectorTerms[0].matchExpressions[0].values[0]'
# pvc-3925c476-...  /var/local-path-provisioner/pvc-3925c476-..._falco_...  seclab-worker2
#                                                                      (exit 0)
# => the volume is a DIRECTORY INSIDE the `seclab-worker2` kind node
#    container. `kind delete cluster` removes that container and the
#    directory with it. NOT PROVEN by deleting the cluster — that is out of
#    scope — so this rests on the path and node name above plus kind's
#    documented behaviour, and is stated as such. It is also node-pinned:
#    RWO and bound to seclab-worker2, so the Redis can only schedule there.
```

---

## 7. The attack surface this phase adds

Five new pods and three new images in a namespace where **nothing is gated**:
PSA `enforce: privileged`, and all five Kyverno policies scoped by
`namespaceSelector` to `[demo, demo-kyverno-only]`. Phase 6 §1f already
conceded that for the sensor; 6b puts four more pods behind the same
exemption, and two of them are network services rather than a read-only agent.

**Would they pass `restricted` if anything gated them? No — but read HOW they
fail.** The namespace's `warn: restricted` label made the apiserver answer
this for free during the section 2 upgrade:

| Workload | `restricted` categories violated |
| --- | --- |
| `falcosidekick` | allowPrivilegeEscalation, capabilities, runAsNonRoot, seccompProfile — **4** |
| `falcosidekick-ui` + `wait-redis` | the same **4** |
| `redis` | the same **4** |
| `falco` + `falcoctl` (unchanged) | those 4 **plus** privileged **plus** restricted volume types (12 hostPath) — **6** |

(That table is a COUNT of the categories named in the four verbatim warnings
quoted in the evidence file §3; it is a summary of that output, not a separate
capture.)

**None of the three new workloads is `privileged`, none uses a `hostPath`,
none requests a host namespace.** What they are missing is four fields that
are pure boilerplate: `allowPrivilegeEscalation: false`,
`capabilities.drop: ["ALL"]`, `runAsNonRoot: true`,
`seccompProfile.type: RuntimeDefault`. The falcosidekick and UI Deployments
already set `runAsUser: 1234` / `fsGroup: 1234` at pod level, so they are
**already running as non-root** — they just never assert it in the field PSA
reads. The redis StatefulSet sets no securityContext at all. So the honest
sentence is **"could be gated and is not"**, not "cannot be gated". The chart
exposes `securityContext` values for every one of these containers. Closing
it is a values change, not a redesign, and it was deliberately left out of a
routing upgrade so it would stay clear which change caused what.

Two more, each a real hole:

- **The Redis has no password and no NetworkPolicy.** Every event retrieval
  in this runbook used plain `redis-cli` with no credential, and section 5b
  destroyed the entire alert history with one pod deletion. Anything on the
  cluster that can reach `10.96.245.44:6379` can read or delete the record of
  its own detection.
- **The Web UI ships the subchart's default credential in a Secret** —
  `FALCOSIDEKICK_UI_USER: "YWRtaW46YWRtaW4="` in the rendered
  `secrets-ui.yaml`. It was **not** overridden, because overriding it means
  putting a password somewhere and this phase entered no credential anywhere.
  The static page is served to any unauthenticated caller that reaches port
  2802; the data API returns `401` with `Www-Authenticate: basic realm=Restricted`.
  That 401 is the credential doing its job against a caller who does not have
  it — not a claim that the credential is a good one.
- **A dormant unpinned image**: `helm test falco` would create a Pod running
  `appropriate/curl` (section 1c). Do not run it.

---

## 8. Reaching the Web UI — port-forward, and nothing else

All three Services are `ClusterIP`. There is **no Ingress, no NodePort and no
LoadBalancer**, which is deliberate: the UI has no TLS and a default
credential, and exposing it on a node port would put both on the network.

```bash
# Web UI. Leave this running in its own terminal; Ctrl-C stops it.
kubectl -n falco port-forward svc/falco-falcosidekick-ui 2802:2802
# Forwarding from 127.0.0.1:2802 -> 2802
# Forwarding from [::1]:2802 -> 2802
# Handling connection for 2802                                         (exit 0)
```

Then browse to `http://127.0.0.1:2802` and authenticate with the value in the
`falco-falcosidekick-ui` Secret. Verified from the command line instead:

```bash
curl -s -i http://127.0.0.1:2802/api/v1/healthz
# HTTP/1.1 200 OK
# Content-Type: application/json; charset=UTF-8
# Content-Length: 16
#
# {"status":"ok"}                                                      (exit 0)

curl -s -w 'http_code=%{http_code}\n' -o <scratch>/uiroot.html http://127.0.0.1:2802/
# http_code=200                                                        (exit 0)

curl -s -i http://127.0.0.1:2802/api/v1/events/count -H 'Accept: application/json' | head -12
# HTTP/1.1 401 Unauthorized
# Www-Authenticate: basic realm=Restricted
#
# {"message":"Unauthorized"}                                           (exit 0)
# => the static page is unauthenticated, the data API is not. NO CREDENTIAL
#    WAS SUPPLIED AT ANY POINT IN THIS PHASE — every event retrieval above
#    went to Redis directly with redis-cli, which needs none.
```

The sidekick itself, if you want its `/ping` or its raw counters:

```bash
kubectl -n falco port-forward svc/falco-falcosidekick 2801:2801
curl -s http://127.0.0.1:2801/ping
# pong                                                                 (exit 0)
```

**A note on `/metrics` through a Service: don't.** Two replicas, each with its
own counters, and the Service round-robins — the number you get back is one
pod's, not the release's. Query each pod through the apiserver's pod-proxy
subresource instead (no port-forward needed), which is what section 4a does:

```bash
kubectl -n falco get --raw \
  "/api/v1/namespaces/falco/pods/<sidekick-pod>:2801/proxy/metrics" \
  | grep '^falcosecurity_falcosidekick_inputs_total'
# falcosecurity_falcosidekick_inputs_total{source="requests",status="accepted"} 3
#                                                                      (exit 0)
```

**A correction, recorded rather than dropped.** An earlier draft of this
section asserted that `MSYS_NO_PATHCONV=1` is *required* on `kubectl get
--raw` because Git Bash would rewrite the leading `/api/...`. **That was
wrong, and it was written without being tested.** It was then tested:

```bash
unset MSYS_NO_PATHCONV
kubectl -n falco get --raw "/api/v1/namespaces/falco/pods/<sidekick-pod>:2801/proxy/ping"
# pong                                                                 (exit 0)
# => the path is NOT rewritten and the command works with the variable unset.
#    The MSYS trap is real for `kubectl exec` and `docker exec` arguments that
#    begin with a slash (phase 6 sections 2d, 3e and 4 record real instances)
#    and every such command in this runbook does carry it — but it does NOT
#    apply here. Claiming a guard is required where it is not is the same
#    class of error as omitting one where it is.
```

---

## 9. Teardown and rollback

falcosidekick is **kept**, like Falco before it: the routing path is the
phase's deliverable and it is meant to keep running. Nothing was created to
attack — all three marked behaviours were `kubectl exec` into the standing
`demo/nginx` pod and left no artifact — so there is nothing in `demo` to
clean up. Both sensor-pod deletions and the Redis deletion in section 5 were
recreated by their controllers and are already accounted for.

To put the release back exactly as phase 6 left it:

```bash
helm rollback falco 1 --namespace falco --wait --timeout 10m
# (NOT RUN in this phase. The upgrade succeeded on its first attempt and no
#  rollback was needed, so this command is written from `helm rollback`'s
#  documented behaviour and has NOT been executed against this cluster.
#  Verify it rather than trusting this line.)
```

Rolling back removes the two Deployments, the StatefulSet and the three
Services, and reverts Falco's ConfigMap so `json_output` and `http_output` go
back to `false` — putting the cluster back to the state phase 6 describes,
where an alert's whole life is a line in a pod log. **The PVC is NOT removed
by a rollback or by `helm uninstall`**: `volumeClaimTemplates` PVCs outlive
their StatefulSet by design. Remove it explicitly if that is what you want:

```bash
kubectl -n falco delete pvc falco-falcosidekick-ui-redis-data-falco-falcosidekick-ui-redis-0
# (also NOT RUN — the PVC is deliberately left in place.)
```

Confirm the rest of the lab is untouched — a routing phase that changed
anything else would be a failed routing phase:

```bash
kubectl -n falco get pods
# falco-6hp56 / falco-cq9ck / falco-tz6ts                  1/1  Running  0
# falco-falcosidekick-ccbb99b56-cmh2b / -qtjxm             1/1  Running  0
# falco-falcosidekick-ui-5765796fbf-9tmdn / -zbjx5         1/1  Running  0
# falco-falcosidekick-ui-redis-0                           1/1  Running  0
# (8 pods, 0 restarts)                                                 (exit 0)
```

Full verbatim captures — the discovery, the four PSA warnings unwrapped, the
digests, the before-and-after config, the complete stored event, the sensor
wipe, the Redis persistence test and the index failure it caused:
`docs/evidence/phase-6b-falcosidekick/attack-output.txt`. That file keeps the
house filename and says plainly in its preamble that it is a routing
transcript, not a denial transcript.
