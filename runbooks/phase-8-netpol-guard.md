# Runbook — Phase 8: a controller for an invariant admission cannot see

A replayable command log for the reconciliation layer this lab did not have: a
small Go controller (`app/netpol-guard`) that holds one invariant in one
namespace — **every pod in `demo` must be selected by a NetworkPolicy for both
`Ingress` and `Egress`** — and the same violation run TWICE, once with
`--remediate=false` to watch it be reported and ignored for 96.950 seconds,
once with `--remediate=true` to watch it be repaired in 19 milliseconds. The
gap between those two runs is the deliverable. The violation is produced by
DELETING an unrelated object, which is why no admission policy on this cluster
can see it. Commands are in execution order; each has a one-line purpose and
the observed output.

Host: Windows 11 + Docker Desktop (WSL2), kind cluster `seclab` (context
`kind-seclab`), Kubernetes v1.35.5, 3 nodes. Commands were run from Git Bash.

**Seven honesty caveats, up front — they are part of the deliverable, not
footnotes:**

1. **The controller RAN OUT OF CLUSTER.** Every observation below comes from a
   binary executed on the Windows host against `C:/Users/josep/.kube/config`,
   using the operator's credentials, not a ServiceAccount token. The
   in-cluster `Deployment`, `ServiceAccount`, `Role` and `RoleBinding` are
   committed under `docs/evidence/phase-8-netpol-guard/` and are **UNAPPLIED**.
   Section 7 lists the four gates that would have to open first — and this is
   a finding, not an apology: **the lab's own phase-5b hardening is what
   forecloses the shortcut.** `AlwaysPullImages` means the kubelet must pull
   from a registry, so `kind load` side-loading no longer works, so a locally
   built image cannot be run on this cluster at all.
2. **It DETECTS AND REPAIRS. It does not PREVENT.** It is not in the request
   path. Section 5 measures the consequence: 226 milliseconds after
   `default-deny` was deleted, a host that had been timed out for 5 full
   seconds got `HTTP 200` from the `signed-app` pod. The pod really was
   unprotected. A controller shrinks that window; only admission control could
   make it zero, and — caveat 3 — admission control cannot see this event.
3. **The invariant is one admission STRUCTURALLY cannot hold.** The violation
   is caused by deleting a NetworkPolicy, so there is no AdmissionReview for
   the pod that loses protection. Section 5c prints all five Kyverno policies'
   `matchConstraints`: `networkpolicies` appears zero times and `DELETE`
   appears zero times. Even fixing both would not be enough — admission sees
   one object per request, and this invariant is a property of the whole SET
   of pods and policies in the namespace.
4. **It checks that isolation EXISTS, not that the rules are RIGHT.** A policy
   with `podSelector: {}`, both `policyTypes`, and `ingress: [{}]` /
   `egress: [{}]` — allow everything from everywhere — satisfies this
   invariant completely and every scan would print `verdict=HOLDS`. Nothing
   here says `demo` is correctly segmented. Phase 2c makes that argument; this
   phase only stops its foundation from vanishing unnoticed.
5. **The probe had to come from OUTSIDE `demo`, and a phase-2c attacker pod
   would NOT have worked.** `allow-dns` has an empty `podSelector` with
   `Egress`, so every pod in `demo` stays Egress-isolated with only DNS
   allowed even after `default-deny` is gone. An in-namespace curl pod is
   blocked before and after and discriminates nothing. Section 3 uses a kind
   NODE that is not the target pod's own node — its traffic is subject to the
   pod's Ingress policy but to no `demo` egress policy. That is a deliberate
   deviation from the phase-2c method, forced by the phase-2c policy set.
6. **One replica, no leader election, no watch.** The controller polls on a
   timer and never opens a watch. Two replicas would both try to create the
   baseline; the loser gets `AlreadyExists`, which is handled — that is safe,
   not correct, and it has not been tested.
7. **The unit tests cover the isolation model only.** Selector semantics
   (including the empty selector), `policyTypes` defaulting, per-direction
   verdicts, policy attribution, and the shape of the baseline object. They do
   NOT cover the client-go call path, the scan loop, signal handling, the
   terminal-pod filter, or remediation against any apiserver, real or fake.
   Everything cluster-facing was verified by running it — sections 4 and 5.

**A note on where the code lives.** `app/netpol-guard/` is a peer of
`app/signed-app/`: `app/` is where this repo keeps things it BUILDS, as
opposed to `policies/`, `network/` and `workloads/`, which are things it
APPLIES. The in-cluster manifests deliberately do NOT go in `workloads/` —
that is the path ArgoCD's `demo-workloads` Application syncs, and putting an
unpublishable image there would leave the Application permanently degraded.
They live under `docs/evidence/phase-8-netpol-guard/` with the rest of the
phase's artefacts, clearly marked unapplied.

Full transcript:
[`docs/evidence/phase-8-netpol-guard/attack-output.txt`](../docs/evidence/phase-8-netpol-guard/attack-output.txt).

## 0. Pre-flight

**`go` is NOT on `PATH` in non-interactive shells on this host.** It is at
`C:\Program Files\Go\bin\go.exe`. Invoke it by absolute path, exactly the way
this repo already invokes `gh`. Every `go` command in this runbook does that;
a bare `go build` will fail with "command not found" and the failure looks
like a missing toolchain rather than a missing PATH entry.

**`MSYS_NO_PATHCONV=1` is required** for any command passing an absolute
POSIX-looking path through to a Windows binary — `kubectl exec`,
`docker exec`, `kubectl get --raw`. Git Bash rewrites `/var/run/...` into
`C:/Program Files/Git/var/run/...` and the resulting error reads like a
missing file inside the container. It is not. Note the inverse trap too:
**with `MSYS_NO_PATHCONV=1` set, `kubectl -f /c/Users/...` will fail**,
because the Windows kubectl cannot open a `/c/...` path. Use `C:/Users/...`
or a path relative to the repo root.

```bash
export MSYS_NO_PATHCONV=1
"C:\Program Files\Go\bin\go.exe" version
# go version go1.26.5 windows/amd64                                    (exit 0)

kubectl config current-context
# kind-seclab                                                          (exit 0)

kubectl version
# Client Version: v1.36.1
# Kustomize Version: v5.8.1
# Server Version: v1.35.5                                              (exit 0)
# => client-go v0.35.5 is chosen to match the SERVER's minor and patch.
```

**Ground truth first — do not build the demo on a remembered fact.** The whole
phase depends on two details of the live policy set: that `allow-dns` has an
EMPTY `podSelector` with `Egress`, and that nothing except `default-deny`
selects `app=signed-app` for `Ingress`. Read them, do not assume them:

```bash
kubectl get networkpolicy -n demo \
  -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}podSelector={.spec.podSelector}{"\t"}policyTypes={.spec.policyTypes}{"\n"}{end}'
# allow-client-egress-to-nginx  podSelector={"matchLabels":{"access":"nginx"}}
#                               policyTypes=["Egress"]
# allow-dns                     podSelector={}   policyTypes=["Egress"]
# allow-nginx-ingress-from-client
#                               podSelector={"matchLabels":{"app":"nginx"}}
#                               policyTypes=["Ingress"]
# default-deny                  podSelector={}   policyTypes=["Ingress","Egress"]
#                                                 (wrapped for width; exit 0)

kubectl get pods -n demo --show-labels
# nginx-78c88678f4-gxqtl       1/1  Running  0  app=nginx,pod-template-hash=...
# nginx-78c88678f4-jfhzk       1/1  Running  0  app=nginx,pod-template-hash=...
# signed-app-d9c5dfcbb-8mzkm   1/1  Running  3  app=signed-app,pod-template-...
#                                                 (wrapped for width; exit 0)
# => Deleting default-deny leaves EVERY pod Egress-isolated (allow-dns, empty
#    selector) and leaves nginx Ingress-isolated (its own policy). It strips
#    Ingress isolation from signed-app ALONE. One pod, one direction.
```

## 1. Build, vet and unit-test the controller

The module is `github.com/joesevv/k8s-security-lab/app/netpol-guard`. The
isolation logic is in `isolation.go` and is deliberately pure — no cluster
calls — which is what makes it testable. The single most important line in the
program is `metav1.LabelSelectorAsSelector(&np.Spec.PodSelector)`: it is what
turns `podSelector: {}` into `labels.Everything()`. Hand-rolled map comparison
would treat the empty selector as "matches nothing" and the controller would
report a healthy namespace as catastrophically broken.

```bash
cd app/netpol-guard

"C:\Program Files\Go\bin\go.exe" build ./...
# (no output — the success condition for this command)               (exit 0)

"C:\Program Files\Go\bin\go.exe" vet ./...
# (no output — vet reports only problems)                            (exit 0)

"C:\Program Files\Go\bin\go.exe" test ./...
# ok  github.com/joesevv/k8s-security-lab/app/netpol-guard  4.031s    (exit 0)
```

`go build ./...` writes `netpol-guard.exe` into the module directory. It is a
build artefact and `.gitignore` does not cover it — delete it, or build with
`-o` to somewhere outside the repo:

```bash
rm -f netpol-guard.exe
```

The verbose run is what belongs in evidence, because the subtest names ARE the
specification. Note the last one: it is this phase's live scenario encoded as
a fixture, so the demo in section 4 is a re-run of a test that already passes.

```bash
"C:\Program Files\Go\bin\go.exe" test -v ./...
# === RUN   TestEvaluate/empty_podSelector_with_both_policyTypes_isolates_...
# === RUN   TestEvaluate/matching_selector_isolates_only_the_pods_it_selects
# === RUN   TestEvaluate/non-matching_selector_isolates_nothing
# === RUN   TestEvaluate/no_policies_at_all:_no_pod_is_isolated_in_either_...
# === RUN   TestEvaluate/one_direction_missing:_an_Egress-only_policy_leaves_...
# === RUN   TestEvaluate/both_directions,_supplied_by_two_different_policies...
# === RUN   TestEvaluate/the_healthy_demo_namespace:_all_four_policies_prese...
# === RUN   TestEvaluate/default-deny_deleted:_signed-app_alone_loses_Ingres...
# [... 38 more lines: TestEvaluateAttributesPoliciesByName, TestMissing,
#  TestEffectivePolicyTypes, TestBaselineDefaultDenyMatchesTheCommittedBase...]
# PASS
# ok  github.com/joesevv/k8s-security-lab/app/netpol-guard  3.533s    (exit 0)
# => 4 top-level tests, 17 subtests, all PASS. Full untruncated output is in
#    the transcript, section 2c.
```

## 2. Build the image — and confirm it cannot be deployed

The `Dockerfile` is a two-stage build onto `distroless/static-debian12:nonroot`
with both bases pinned by `tag@sha256`, matching `app/signed-app/Dockerfile`.
Build it locally to verify it, then delete the tag. **Do not push it and do
not `docker login`** — publishing is a human gate.

```bash
docker build -t netpol-guard:localtest app/netpol-guard
# [... buildkit progress ...]
# naming to docker.io/library/netpol-guard:localtest done             (exit 0)

docker run --rm netpol-guard:localtest --help
# Usage of /usr/local/bin/netpol-guard:
#   -interval duration    time between scans (default 30s)
#   -kubeconfig string    path to a kubeconfig; in-cluster when empty
#   -namespace string     namespace to check (default "demo")
#   -once                 one scan then exit; exit 1 on a violation
#   -remediate            restore the baseline when violated
#                                                 (abridged for width; exit 0)

docker inspect -f 'User={{.Config.User}} Cmd={{.Config.Cmd}}' netpol-guard:localtest
# User=65532:65532 Cmd=[--namespace=demo --remediate=false --interval=30s]
#                                                                     (exit 0)
# => non-root uid, and DETECT-ONLY by default: turning on enforcement has to be
#    a deliberate act in a manifest, not something inherited from the image.

docker image rm netpol-guard:localtest
# Untagged: netpol-guard:localtest                                    (exit 0)
```

**This image can never reach the cluster from here.** Phase 5b enabled
`--enable-admission-plugins=NodeRestriction,AlwaysPullImages`, so the kubelet
must pull from a registry and `kind load` is not a workaround. Section 7 lists
the four gates. Everything from here on runs the binary on the host.

## 3. Calibrate the reachability probe

**The controller's verdict is an opinion about the API. Prove the regression
with TCP.** That requires a probe source whose traffic is subject to
`signed-app`'s INGRESS policy but not to any `demo` EGRESS policy — because
`allow-dns` keeps every pod inside `demo` egress-restricted to DNS whether
`default-deny` exists or not. A kind node that is NOT the pod's own node
satisfies both conditions. Find the target and the right node first:

```bash
kubectl get pods -n demo -o wide
# nginx-78c88678f4-gxqtl      10.244.1.14  seclab-worker2
# nginx-78c88678f4-jfhzk      10.244.2.14  seclab-worker
# signed-app-d9c5dfcbb-8mzkm  10.244.1.7   seclab-worker2
#                                                 (abridged for width; exit 0)
```

`signed-app` is on `seclab-worker2`, so probe from `seclab-worker`. The
discriminating pair — same command, two sources, opposite results:

```bash
docker exec seclab-worker curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://10.244.1.7:8080/
# HTTP:000 time=5.002004
# => blocked. curl -m 5 turns the DROP into a 5s timeout.            (exit 28)

docker exec seclab-worker2 curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://10.244.1.7:8080/
# HTTP:200 time=0.001311
# => from the pod's OWN node it answers in 1.3 ms.                    (exit 0)
```

That second command is not decoration — it is the liveness control. kindnet
does not police traffic from a pod's own node (kubelet probes have to work),
so `seclab-worker2` proves the app is up and serving. Without it, a timeout
from `seclab-worker` could just as easily be a dead process.

A third probe, aimed at nginx from the same remote node, is the differential
control for section 4:

```bash
docker exec seclab-worker curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://10.244.1.14:8080/
# HTTP:000 time=5.002455
# => nginx is blocked too, right now. After the delete it must STILL be
#    blocked, because allow-nginx-ingress-from-client survives.      (exit 28)
```

## 4. STAGE 1 — detect only

Start the controller detect-only at a short interval so several scans fit in
the observation window, let it print clean scans first (a run that starts
already-broken proves less), then delete the policy underneath it.

**On the form of the command.** Sections 4–6 are written as `go run .` because
that is the documented way to run this out of cluster. The captured outputs
came from the equivalent compiled binary
(`go build -o <somewhere-outside-the-repo>/netpol-guard.exe .`, invoked by
path), so the harness could start it, delete a policy underneath it, and stop
it. Same source, same program; only the invocation differs.

```bash
"C:\Program Files\Go\bin\go.exe" run . \
  --kubeconfig=C:/Users/josep/.kube/config \
  --namespace=demo --remediate=false --interval=15s
# 17:00:25.219 netpol-guard start namespace=demo remediate=false interval=15s
# 17:00:25.238 scan=1 ... networkpolicies=4 violations=0 verdict=HOLDS
# 17:00:40.225 scan=2 ... networkpolicies=4 violations=0 verdict=HOLDS
# 17:00:55.225 scan=3 ... networkpolicies=4 violations=0 verdict=HOLDS
#                                     (timestamps abridged to HH:MM:SS.mmm)
```

In another shell, the deletion — the whole point of the phase, and note that
it is an ordinary, successful, unremarkable command:

```bash
kubectl delete networkpolicy default-deny -n demo
# networkpolicy.networking.k8s.io "default-deny" deleted from demo namespace
# => issued at 17:01:03.275. Nothing objected.                        (exit 0)
```

Immediately re-run the probe. **This is the security regression, demonstrated
rather than asserted:**

```bash
docker exec seclab-worker curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://10.244.1.7:8080/
# HTTP:200 time=0.001430
# => at 17:01:03.501 — 226 ms after the delete — the connection that had
#    timed out for 5 full seconds now returns 200 in 1.43 ms.          (exit 0)

docker exec seclab-worker curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://10.244.1.14:8080/
# HTTP:000 time=5.002590
# => nginx, same source, same instant: STILL blocked.                (exit 28)
# => One pod regressed. The other did not. Exactly as section 0 predicted.
```

The controller, still running, notices and then does nothing about it, over
and over:

```bash
# 17:01:10.225 VIOLATION scan=4 pod=signed-app-d9c5dfcbb-8mzkm missing=Ingress
#              isolated-for-ingress-by=[] isolated-for-egress-by=[allow-dns]
# 17:01:10.225 scan=4 ... networkpolicies=3 violations=1 verdict=VIOLATED
# 17:01:25.225 VIOLATION scan=5 ... (identical)
# 17:01:40.225 VIOLATION scan=6 ... (identical)
# 17:01:55.225 VIOLATION scan=7 ... (identical)
# 17:02:10.225 VIOLATION scan=8 ... (identical)
# 17:02:25.225 VIOLATION scan=9 ... (identical)
# 17:02:40.225 VIOLATION scan=10 ... (identical)
# => DETECTION LATENCY 6.950 s (deleted 17:01:03.275, reported 17:01:10.225)
#    at a 15 s interval — a mid-interval arrival, not a best case.
# => Then SEVEN consecutive VIOLATED scans over 96.950 s and no correction,
#    because --remediate=false. Detection is not correction.
# => `isolated-for-egress-by=[allow-dns]` is the controller showing its work:
#    it knows the pod kept Egress and lost only Ingress.
```

### 4a. Nothing else on this cluster noticed

Not admission — and this is structural, not a configuration gap:

```bash
kubectl get validatingpolicy -o jsonpath='{range .items[*]}{.metadata.name}{"\t"}{.spec.matchConstraints.resourceRules}{"\n"}{end}'
kubectl get imagevalidatingpolicy require-keyless-signed-ghcr -o jsonpath='{.spec.matchConstraints.resourceRules}'
# All five policies match: pods, pods/ephemeralcontainers, deployments,
# statefulsets, daemonsets, replicasets, jobs, cronjobs — on CREATE, UPDATE.
# `networkpolicies` appears ZERO times. `DELETE` appears ZERO times.
#                                    (full output in transcript 3d; exit 0)
# => And even matching networkpolicies on DELETE would not be enough: admission
#    sees ONE object per request and cannot answer "does every OTHER pod in
#    this namespace still have coverage?" That is a property of the SET.

kubectl get events -n demo --sort-by=.lastTimestamp
# No resources found in demo namespace.
# => no PSA warning, no Kyverno denial, no event of any kind.          (exit 0)
```

Not GitOps either — ArgoCD, asked while the pod was reachable:

```bash
kubectl -n argocd get application demo-workloads
# NAME             SYNC STATUS   HEALTH STATUS
# demo-workloads   Synced        Healthy                               (exit 0)
# => Synced and Healthy, faithfully. `network/` is outside the Application's
#    scope — phase 7 already measured this, ignoring an out-of-scope drift for
#    4 min 57 s. ArgoCD is not wrong; "GitOps is watching the cluster" is.
```

## 5. STAGE 2 — remediate

Same violation, still uncorrected, one flag changed.

```bash
"C:\Program Files\Go\bin\go.exe" run . \
  --kubeconfig=C:/Users/josep/.kube/config \
  --namespace=demo --remediate=true --interval=15s
# 17:03:57.926 netpol-guard start namespace=demo remediate=true interval=15s
# 17:03:57.939 VIOLATION scan=1 pod=signed-app-d9c5dfcbb-8mzkm missing=Ingress
# 17:03:57.939 scan=1 ... networkpolicies=3 violations=1 verdict=VIOLATED
# 17:03:57.941 REMEDIATE baseline networkpolicy/default-deny is ABSENT in demo
#              — creating it
# 17:03:57.945 REMEDIATE created networkpolicy/default-deny in demo
#              uid=9123c527-... resourceVersion=461137
# 17:04:12.933 scan=2 ... networkpolicies=4 violations=0 verdict=HOLDS
# 17:04:27.932 scan=3 ... verdict=HOLDS
# 17:04:42.934 scan=4 ... verdict=HOLDS
# 17:04:57.933 scan=5 ... verdict=HOLDS
# 17:05:12.933 scan=6 ... verdict=HOLDS
# 17:05:27.932 scan=7 ... verdict=HOLDS
# => start 17:03:57.926 -> created 17:03:57.945 = 19 MILLISECONDS.
# => NO CHURN: exactly one `REMEDIATE created` line in the whole log, and six
#    consecutive HOLDS over 74.999 s with no further write attempt. The first
#    thing remediation does on a violation is a GET; a present baseline means
#    it does nothing.
```

And the network agrees, 1.091 s after the create:

```bash
docker exec seclab-worker curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://10.244.1.7:8080/
# HTTP:000 time=5.002314
# => refused again.                                                  (exit 28)

# repeated 15 s later to rule out a lucky first sample:
# HTTP:000 time=5.001861                                             (exit 28)
```

### 5a. Verify the restored object IS the committed baseline

Do not eyeball this. Print the live `.spec` and the file's `.spec` through the
SAME kubectl jsonpath printer — it emits map keys in sorted order, so a byte
comparison is meaningful — and compare with `cmp`. The file side goes through
`--dry-run=client`, which writes nothing.

```bash
kubectl get networkpolicy default-deny -n demo -o jsonpath='{.spec}' > /tmp/live.json
kubectl apply -f network/00-default-deny.yaml --dry-run=client -o jsonpath='{.spec}' > /tmp/file.json
# both: {"podSelector":{},"policyTypes":["Ingress","Egress"]}         (exit 0)

cmp /tmp/live.json /tmp/file.json
# (no output)                                                         (exit 0)
# => byte-identical specs.

kubectl get networkpolicy default-deny -n demo \
  -o jsonpath='labels={.metadata.labels} annotations={.metadata.annotations} managers={range .metadata.managedFields[*]}{.manager}{" "}{end}{"\n"}'
# labels= annotations= managers=netpol-guard                          (exit 0)
# => no labels, no annotations, one field manager. The controller stamps
#    nothing of its own on the object DELIBERATELY: what it restores must be
#    the repo's baseline, not a controller-flavoured variant. Authorship is
#    recorded in managedFields, where authorship belongs.
```

One honest difference: the controller does not write kubectl's
`last-applied-configuration` annotation, because it is not kubectl. The SPEC
is identical; that annotation is kubectl bookkeeping. Section 8 re-applies
`network/` so the object ends indistinguishable from a human-applied one.

### 5b. The window, stated honestly

```text
Delete issued          17:01:03.275
Reachable (HTTP 200)   17:01:03.501    +0.226 s
Controller reports it  17:01:10.225    +6.950 s   (--interval=15s)
Baseline recreated     17:03:57.945  +174.670 s
Blocked again (probe)  17:03:59.036  +175.761 s
```

**Total unprotected: 174.670 s = 2 min 54.670 s** — and most of that is the
demo, not the controller: 96.950 s is stage 1 deliberately doing nothing, and
~68 s is the human gap between stopping one process and starting the other.
**The controller's own number is the 6.950 s detection latency**, bounded above
by one full interval plus an API round trip; at the shipped default of `30s`
that bound is ~30 s, and a single replica that is wedged or restarting has no
bound at all. Stage 2's 19 ms is reaction time once the scan fires — it is not
the exposure. The exposure is measured, once, at 226 ms, by a host that had
been timed out moments earlier.

## 6. Confirm the invariant holds again

`--once` is the CI shape: one scan, then exit — 0 if the invariant holds,
1 if it does not.

```bash
"C:\Program Files\Go\bin\go.exe" run . \
  --kubeconfig=C:/Users/josep/.kube/config --namespace=demo --once
# 17:06:58.270 scan=1 namespace=demo pods=3 networkpolicies=4 violations=0
#              verdict=HOLDS                                          (exit 0)
```

## 7. Limits, and what in-cluster would require

**Four gates stand between this controller and running on this cluster. None
can be opened by an agent.**

1. **The image does not exist.** `.github/workflows/supply-chain.yml` builds
   exactly one context, `app/signed-app`, and pushes on
   `push: branches: [main]`. A second image needs a second build/push job.
2. **A merge to `main`.** The publish step is gated on that branch; a feature
   branch cannot produce the image.
3. **A cosign signature.** `require-keyless-signed-ghcr` Denies any
   `ghcr.io/joesevv/k8s-security-lab/*` image in `demo` without a Sigstore
   keyless signature from the pinned workflow identity. CI would have to sign
   this image exactly as it signs `signed-app`. *(Not verified by experiment —
   read off the policy's own `matchConstraints` and scope. A server-side
   dry-run was deliberately not run.)*
4. **It could not reach the apiserver.** A pod in `demo` is Egress-isolated by
   `default-deny`, and the only carve-out is `allow-dns` — 53/UDP+TCP to
   CoreDNS. The apiserver is `kubernetes.default` → `10.96.0.1:443`, DNATed to
   the host-network endpoint `172.18.0.2:6443`, which no `podSelector` can
   select. A fifth NetworkPolicy with an `ipBlock` would be required.

```bash
kubectl get endpointslice -n default -o wide
# NAME         ADDRESSTYPE   PORTS   ENDPOINTS    AGE
# kubernetes   IPv4          6443    172.18.0.2   8d                  (exit 0)
```

Gate 4 was **not** worked around. `network/` is the baseline this invariant is
defined against, and widening it to host the watchdog would weaken the thing
being watched. The controller that guards a namespace is subject to that
namespace's rules; that is the honest cost of not exempting it.

**Least-privilege RBAC, and the contrast.** The committed `Role`
(`docs/evidence/phase-8-netpol-guard/rbac.yaml`) grants `list` on pods and
`get, list, create` on networkpolicies, in ONE namespace. No `update`, no
`patch`, no `delete`, nothing cluster-scoped, no secrets. So "it will never
modify or delete a policy it did not create" is enforced by the apiserver, not
by the code's good intentions. `watch` is deliberately absent because the
controller polls and never opens a watch — granting it would be unused
privilege. **Compare ArgoCD in this same cluster:** phase 7 section 2c found
the `argocd-application-controller` ClusterRole byte-identical to the built-in
`cluster-admin`. Both are "a controller that fixes drift". One has `*/*/*`;
this one has two resources in one namespace with no delete verb.

The manifests are committed and were validated client-side only — nothing was
written:

```bash
kubectl apply --dry-run=client -f docs/evidence/phase-8-netpol-guard/rbac.yaml
# serviceaccount/netpol-guard created (dry run)
# role.rbac.authorization.k8s.io/netpol-guard created (dry run)
# rolebinding.rbac.authorization.k8s.io/netpol-guard created (dry run) (exit 0)

kubectl apply --dry-run=client -f docs/evidence/phase-8-netpol-guard/deployment.yaml
# deployment.apps/netpol-guard created (dry run)                       (exit 0)

kubectl -n demo get deployment netpol-guard
# Error from server (NotFound): deployments.apps "netpol-guard" not found
# => confirming it is UNAPPLIED, not merely described as unapplied.    (exit 1)
```

## 8. Teardown — restore `network/` and confirm

**This one WAS executed.** Unlike phase 7's teardown, the outputs below are
observations, not expectations. The controller is a host process; stopping it
is the whole teardown. What needs restoring is the object it recreated, so
that it also carries the annotation a human `kubectl apply` would have
written.

```bash
kubectl apply -f network/
# Warning: resource networkpolicies/default-deny is missing the
# kubectl.kubernetes.io/last-applied-configuration annotation [...] The missing
# annotation will be patched automatically.
# networkpolicy.networking.k8s.io/default-deny configured
# networkpolicy.networking.k8s.io/allow-dns unchanged
# networkpolicy.networking.k8s.io/allow-nginx-ingress-from-client unchanged
# networkpolicy.networking.k8s.io/allow-client-egress-to-nginx unchanged
# => the warning IS the section-5a difference, now patched.            (exit 0)

kubectl diff -f network/
# (no output)
# => live matches every file in network/. This is the check, not the claim.
#                                                                      (exit 0)

kubectl get networkpolicy -n demo
# allow-client-egress-to-nginx   access=nginx   8d
# allow-dns                      <none>         8d
# allow-nginx-ingress-from-client app=nginx     8d
# default-deny                   <none>         2m46s
# => four policies. default-deny is young because it is the object the
#    controller recreated; the other three were never touched.         (exit 0)

docker exec seclab-worker curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://10.244.1.7:8080/
# HTTP:000 time=5.002432                                              (exit 28)
docker exec seclab-worker2 curl -m 5 -s -o /dev/null \
  -w "HTTP:%{http_code} time=%{time_total}\n" http://10.244.1.7:8080/
# HTTP:200 time=0.001126                                               (exit 0)
# => blocked from the remote node, still serving on its own. The final posture
#    is the starting posture.

kubectl get pods -n demo
# nginx-78c88678f4-gxqtl       1/1  Running  0
# nginx-78c88678f4-jfhzk       1/1  Running  0
# signed-app-d9c5dfcbb-8mzkm   1/1  Running  3 (5h37m ago)
# => same three pods, same restart counts as section 0. Nothing was restarted
#    or rescheduled by any of this.                    (abridged; exit 0)
```

Nothing under `docs/evidence/phase-8-netpol-guard/` was applied, no image was
pushed, no registry credential was used, and the cluster was neither deleted
nor recreated. The only object that changed identity across the whole phase is
`default-deny`: deleted, recreated by the controller, then re-applied from the
file — and `kubectl diff -f network/` at exit 0 is the check on that.
