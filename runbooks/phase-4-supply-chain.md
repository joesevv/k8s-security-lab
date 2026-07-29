# Runbook — Phase 4: Supply chain (cosign keyless signing + admission)

A replayable command log for the supply-chain layer: a GitHub Actions workflow
that builds the lab's own image, scans it, generates an SBOM and cosign
KEYLESS-signs it by digest — and a Kyverno `ImageValidatingPolicy` that refuses
to admit any image under this repo's GHCR path unless that signature verifies
against one exact workflow identity. Then a live attack proving the gate is a
real signature check: an image that genuinely exists in the registry but was
never signed is denied with the policy's own message, and the same reference is
denied in a Deployment as well as a bare Pod. Commands are in execution order;
each has a one-line purpose and the observed output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash
unless noted. Kubernetes node image v1.35.5, Kyverno v1.18.2.

**Two honesty caveats, up front — they are part of the deliverable, not
footnotes:**

1. **A signature attests PROVENANCE, not safety.** It proves which workflow
   built the bytes and that they have not changed since. Trivy in this pipeline
   runs with `exit-code: '0'` — report-only, by deliberate choice — so CVE
   findings never block signing. A vulnerable image is still signed and still
   admitted. Anyone reading "signed" as "safe" has misread the control.
2. **The two-job workflow has now run — exactly once.** Run 30174855073
   (2026-07-25, commit `b8483c5`) was the FIRST execution of the `build-scan` /
   `sign` split. Both jobs passed, including the cosign verify self-check
   against the exact identity the cluster policy pins, and it published a new
   signed digest `sha256:7fd13d22...` which the cluster now admits. One green
   run proves the shape works; it does not make it battle-tested. Note also
   that `app/signed-app/**` was byte-identical between the two builds
   (`git diff 4428b14 b8483c5 -- app/signed-app` is empty) yet the digest
   changed — this build is **not reproducible**, so a digest match cannot be
   used as an independent check on the builder.

---

## 0. The controls

- **The trusted producer — `.github/workflows/supply-chain.yml`** — builds
  `app/signed-app`, pushes it to GHCR under a per-commit tag, Trivy-scans it,
  generates an SPDX-JSON SBOM, then cosign KEYLESS-signs the resulting
  **digest**. **Why it is needed:** without a single trusted build path, "the
  image is in our registry" is the only provenance claim available, and anyone
  with push access can satisfy it.
- **Keyless signing (Sigstore), not a key pair** — cosign mints a short-lived
  OIDC token from the workflow's ambient GitHub identity, exchanges it for a
  short-lived Fulcio certificate that records that identity, signs, and logs
  the entry in the Rekor transparency log. **Why it is needed:** a key-based
  attestor would force us to mint, store and rotate a long-lived private key —
  a secret whose theft silently forges trusted images. Keyless has no such
  secret to steal: the certificate expires in minutes and the binding is to an
  identity (`workflow@ref`), not to a file. It also sidesteps the key-based
  `ImageValidatingPolicy` bug reported upstream as Kyverno #16435 ("key/
  certificate cosign verification fails (SIGSEGV + missing tlog support)"),
  which was closed as fixed against the 1.19.0 milestone — i.e. NOT in the
  1.18.2 this cluster runs, so the limitation is still live here.
- **Signing the DIGEST, not the tag** — `cosign sign` is called on
  `signed-app@sha256:...`, never on `signed-app:<tag>`. **Why it is needed:** a
  tag is a mutable pointer. Signing a tag would let an attacker with push
  access repoint it at different bytes AFTER signing, and the signature would
  still "verify" for whatever the tag now resolves to. A digest is the content
  hash; there is no swap to perform.
- **The consumer — `policies/supply-chain/require-signed-images.yaml`**
  (`ImageValidatingPolicy` `require-keyless-signed-ghcr`) — `Deny` +
  `failurePolicy: Fail`, matching `ghcr.io/joesevv/k8s-security-lab/*` in the
  `demo` and `demo-kyverno-only` namespaces, across Pods,
  `pods/ephemeralcontainers`, `apps/v1` workloads and `batch/v1` jobs. **Why it
  is needed:** producing signatures is worthless if nothing checks them. This is
  the enforcement half.
- **An EXACT pinned identity** — issuer
  `https://token.actions.githubusercontent.com`, subject the literal string
  `https://github.com/joesevv/k8s-security-lab/.github/workflows/supply-chain.yml@refs/heads/main`.
  **Why it is needed:** a regex here is a trap. The earlier `subjectRegExp` used
  `.+` for the workflow-file segment, and RE2's `.` matches `@` and `/` — so a
  branch named `evil@refs/heads/main` produced a subject the pattern accepted.
  A literal string admits exactly one workflow file on exactly one ref.

Scope is deliberately narrow: only the ghcr glob is matched, so the lab's
Docker Hub nginx workload is never asked to prove a signature it does not have.
That is a scoping decision, not a bypass — nginx is still bound by the four
phase-2b Deny policies.

---

## 1. The producer — build, scan, SBOM, keyless sign

The workflow is split into two jobs so the signing privilege is isolated:

```yaml
permissions: {}          # deny by default at workflow level

build-scan:              # contents: read, packages: write   — NO id-token
  # checkout, GHCR login, docker build+push, Trivy, syft SBOM, artifact uploads

sign:                    # contents: read, packages: write, id-token: write
  needs: build-scan
  # GHCR login, download THIS run's `sbom` artifact, cosign-installer,
  # cosign sign --yes <image>@<digest>, cosign attest --type spdxjson,
  # cosign verify + cosign verify-attestation self-checks, two evidence
  # uploads, record the signed digest
```

`id-token: write` is the permission that lets a job mint the OIDC token whose
subject Kyverno trusts. **Every third-party action runs in `build-scan`, which
holds no `id-token`** — docker, trivy and syft cannot mint the signing identity
even if one of them is compromised or its tag is moved. The `sign` job holds
`id-token: write` and runs GHCR login, cosign, and the first-party `actions/*`
artifact steps that move this run's own SBOM in and the verify transcripts out —
nothing else. It does **not** check out the repo, so no source tree exists in
the privileged job. Every action is pinned to a 40-char commit SHA for the same
reason a tag is not trusted for images. What the SBOM download costs in trust is
stated in section 1a: `sign` now attests bytes that `build-scan` produced.

The signing and self-check steps:

```yaml
- name: Keyless sign image by digest
  run: cosign sign --yes ghcr.io/joesevv/k8s-security-lab/signed-app@${{ needs.build-scan.outputs.digest }}

- name: Verify signature (self-check vs the identity Kyverno pins)
  shell: bash                    # explicit: the runner then uses -eo pipefail,
  run: |                         # without which `| tee` masks cosign's exit code
    cosign verify \
      --certificate-identity 'https://github.com/joesevv/k8s-security-lab/.github/workflows/supply-chain.yml@refs/heads/main' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      ghcr.io/joesevv/k8s-security-lab/signed-app@${{ needs.build-scan.outputs.digest }} \
      2>&1 | tee cosign-verify.txt
```

The self-check verifies against the EXACT identity string the cluster policy
pins, so a signature the cluster would reject fails the pipeline instead of
shipping silently. The transcript uploads with `if: always()` — a FAILED verify
is precisely the case worth keeping.

**Status, plainly: this two-job shape has now run in CI — once.** Run
30174855073 (2026-07-25, `push` on `main`, head `b8483c5`) was its first
execution: `build-scan` green in 53s, `sign` green in 10s, every step
succeeding including `Verify signature (self-check vs the identity Kyverno
pins)`. It signed a NEW artifact,
`signed-app:b8483c58...@sha256:7fd13d22...`, and
`workloads/signed-app/deployment.yaml` has since been repointed at that digest,
so the image the cluster admits today is the one this two-job workflow built
and verified. The previous digest `sha256:b4cb133e...`, from the earlier single
`build-sign` job, is still signed and still present in GHCR; its cosign
signature tag is the unsigned artifact section 3b attacks. The self-check
transcript, downloaded from that run's `cosign-verify` artifact, is at
`docs/evidence/phase-4-supply-chain/cosign-verify.txt`.

**Known gaps, stated rather than hidden:**

- **Trivy is report-only** (`exit-code: '0'`, severity `CRITICAL,HIGH`, SARIF
  uploaded as an artifact). CVEs are recorded, never enforced. The choice is
  deliberate — a lab that cannot produce a signed image because upstream shipped
  a HIGH in libc teaches nothing about signing — but it means **the signature
  says nothing about vulnerabilities.**
- **The SBOM is attested as of 2026-07-29 — for FUTURE builds, and not yet
  proven by a run.** Until that date this bullet read, in full: "**The SBOM is a
  CI artifact, not an attestation.** `sbom.spdx.json` is uploaded with
  `actions/upload-artifact`; it is not `cosign attest`-ed against the image
  digest, so it is not bound to the image and **no admission policy can verify
  it.** Closing this means switching to a cosign attestation and adding an
  attestation check to the policy. Not done." Half of that is now addressed and
  half is not, so it stays in this list. The `sign` job now runs `cosign attest
  --type spdxjson` against the build digest (section 1a), which binds the SBOM
  of every FUTURE build to that build's digest. Still open, precisely: the step
  has **never executed** — the workflow fires only on `push` to `main`, so the
  claim rests on a static read of the YAML until the first green run on main
  hands back a `cosign verify-attestation` transcript for
  `docs/evidence/phase-4-supply-chain/`; the digest the cluster runs today
  (`b8483c58...@sha256:7fd13d22...`) was built before the step existed and stays
  **unattested by design**, because the repo pins the digest it actually
  verified rather than repointing at an untested one; and **admission still
  verifies signatures only** — no policy checks attestations. A Kyverno
  attestation check is a deliberate follow-up, deferred until an attested digest
  is actually deployed.

---

## 1a. The SBOM attestation — added 2026-07-29, not yet exercised

Four steps were added to the `sign` job on 2026-07-29 so the SBOM stops being a
CI artifact that nothing can tie to an image: the three below, plus the evidence
upload that carries the transcript out. **None of them have run.** The
workflow triggers only on `push` to `main` (paths-filtered, plus
`workflow_dispatch`), so what follows documents what the YAML says, not what a
run observed — the first green run on main owes the transcript.

**1a-i. Move the SBOM into the privileged job.** It is generated in `build-scan`,
the job that deliberately cannot sign, so it crosses the job boundary as an
artifact:

```yaml
- name: Download SBOM artifact
  uses: actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131 # v7.0.0
  with:
    name: sbom          # byte-identical to build-scan's upload name
```

A same-run download needs no token input and no extra permission — the runner's
`ACTIONS_RUNTIME_TOKEN` already scopes it to this run — and it drops
`sbom.spdx.json` in the workspace root. That file is the only thing the `sign`
job reads from disk; the job still does not check out the repo.

**1a-ii. Attest the SBOM against the digest.**

```yaml
- name: Attest SBOM to the image digest
  run: |
    cosign attest --yes \
      --type spdxjson \
      --predicate sbom.spdx.json \
      ghcr.io/joesevv/k8s-security-lab/signed-app@${{ needs.build-scan.outputs.digest }}
```

cosign wraps the SBOM in an in-toto statement whose subject is that digest,
signs it with the same keyless OIDC identity as the image signature, publishes
it alongside the image in GHCR and records it in the public Rekor transparency
log. The SBOM is then a signed claim about one immutable digest instead of a
loose build artifact.

**1a-iii. Self-check the attestation.**

```yaml
- name: Verify attestation (self-check vs the identity Kyverno pins)
  shell: bash                    # explicit: -eo pipefail, without which `| tee`
  run: |                         # masks cosign's exit code (as in section 1)
    cosign verify-attestation \
      --type spdxjson \
      --certificate-identity 'https://github.com/joesevv/k8s-security-lab/.github/workflows/supply-chain.yml@refs/heads/main' \
      --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
      ghcr.io/joesevv/k8s-security-lab/signed-app@${{ needs.build-scan.outputs.digest }} \
      2>&1 | tee cosign-verify-attestation.txt
```

The identity and issuer strings are byte-identical to the signature self-check
in section 1 and to the pair the `ImageValidatingPolicy` pins. The transcript
uploads as its own `cosign-verify-attestation` artifact with `if: always()` — a
FAILED verification is the one worth keeping — and belongs at
`docs/evidence/phase-4-supply-chain/cosign-verify-attestation.txt` once a run
has produced one. Expect it to be large: `cosign verify-attestation` echoes the
verified payload, which is the whole SBOM.

**Where this sits in the pipeline — stated precisely.** Every cosign call in
this workflow, the two old ones and the two new ones, runs **after** the image
has already been pushed to GHCR. The attestation is created post-publication,
and neither self-check gates the push. A failing self-check fails the job loudly
after the fact; that is worth having, and it is not the same thing as a gate.

Three things this does **not** buy, said plainly so nobody reads more into it:

- **An attestation is not a truthful SBOM.** The SBOM is generated in
  `build-scan` and attested in `sign`, so the attestation extends trust to the
  build job: a compromised `build-scan` could emit a forged `sbom.spdx.json` and
  `sign` would attest it verbatim, under the exact identity Kyverno pins. The
  digest is content-addressed, so that attacker still cannot make `sign` attest
  a **different image** than the one `build-scan` pushed; the predicate is
  free-form JSON, so its contents are only as good as `build-scan`'s runtime.
  This is the accepted cost of attesting a build-job SBOM — generating the SBOM
  inside the privileged job would be worse, because it would put third-party
  syft under `id-token: write`. cosign **binds** the predicate to the digest; it
  does not **vouch** for what the predicate says.
- **The deployed digest is not covered.** `b8483c58...@sha256:7fd13d22...` was
  built on 2026-07-25, before this step existed. It carries no attestation and
  will not grow one — the repo pins the digest it verified rather than
  repointing the cluster at an untested build to make a document look tidier.
- **Nothing verifies attestations at admission.** The `ImageValidatingPolicy`
  checks signatures only, so an attestation adds no admission-time value today.
  A Kyverno attestation check is a deliberate follow-up, deferred until an
  attested digest is actually deployed — writing the check first would leave the
  cluster enforcing a rule that the running image cannot satisfy.

---

## 2. The consumer — apply the policy and confirm it is enforcing

```bash
kubectl apply -f policies/supply-chain/require-signed-images.yaml
# imagevalidatingpolicy.policies.kyverno.io/require-keyless-signed-ghcr unchanged

kubectl get imagevalidatingpolicy require-keyless-signed-ghcr
# NAME                          AGE   READY
# require-keyless-signed-ghcr   24h   true
```

`READY=true` is the gate to check before trusting any result below: a policy
that failed to compile its CEL would show `false` and silently enforce nothing.

Confirm the pinned identity is the literal subject, not a pattern:

```bash
kubectl get imagevalidatingpolicy require-keyless-signed-ghcr \
  -o jsonpath='{.spec.attestors[0].cosign.keyless.identities}'
# [{"issuer":"https://token.actions.githubusercontent.com",
#   "subject":"https://github.com/joesevv/k8s-security-lab/.github/workflows/supply-chain.yml@refs/heads/main"}]
```

The policy deliberately lives one directory down, in `policies/supply-chain/`.
`runbooks/phase-2b-admission.md` selects its Audit targets **by kind** — `for f
in $(grep -l '^kind: ValidatingPolicy' policies/*.yaml)` — because `policies/`
also holds a Namespace manifest that must not be piped through `sed`. It tears
down **by name**: `kubectl delete validatingpolicy disallow-privileged-containers
disallow-latest-and-bare-tag require-drop-all-capabilities restrict-registries`.
Neither form descends into `policies/supply-chain/`: the glob is shallow, and
the delete names only those four. So the phase-2b commands cannot flip this
policy to Audit or delete it — and even if the file sat directly in `policies/`,
`kind: ImageValidatingPolicy` matches neither the `^kind: ValidatingPolicy` grep
nor a `kubectl delete validatingpolicy`. The same holds for the `kubectl delete -f
policies/` that phase 2b explicitly warns against, since `-f <dir>` is
non-recursive without `-R`. Verified:

```bash
kubectl delete -f policies/ --dry-run=client   # deletes nothing; lists targets
# namespace "demo-kyverno-only" deleted (dry run)
# validatingpolicy.policies.kyverno.io "disallow-latest-and-bare-tag" ...
# validatingpolicy.policies.kyverno.io "disallow-privileged-containers" ...
# validatingpolicy.policies.kyverno.io "require-drop-all-capabilities" ...
# validatingpolicy.policies.kyverno.io "restrict-registries" ...
# => require-keyless-signed-ghcr is NOT in the list.
```

**Local `cosign verify` is not part of this replay** — cosign is not installed
on the lab host (`command -v cosign` -> exit 1). Signature verification is
nevertheless demonstrated in two independent places: in-cluster at admission
(section 3), and in CI by the self-check in section 1, which ran green in run
30174855073 against the identical certificate-identity and issuer strings the
`ImageValidatingPolicy` pins. That transcript is evidence, and it is at
`docs/evidence/phase-4-supply-chain/cosign-verify.txt`. What is still missing
is a third verification by a party that is neither the producer nor the
consumer of the signature.

---

## 3. Attack demo — an unsigned image is refused admission

Frame: an attacker can push to, or already has an image sitting at, the trusted
GHCR path. Registry allow-listing cannot tell that image from ours. Signature
verification can.

**3a. POSITIVE CONTROL — the signed image is admitted.** Use SERVER-SIDE apply
with a dry run (`--server-side --dry-run=server`), NOT a plain
`--dry-run=server`. An earlier version of this runbook used the plain form and
claimed it "forces the full admission chain." That was wrong for an UNCHANGED
object, and the correction is recorded here rather than quietly dropped:
kubectl diffs client-side first, and with no diff it computes an empty patch
and sends no write at all. Traced, the only verb it issues is a GET:

```bash
kubectl apply -f workloads/signed-app/deployment.yaml --dry-run=server -v=8 2>&1 \
  | grep -E 'round_trippers.*"Request" verb' | grep -v openapi
# I0725 18:04:41.410182 ... "Request" verb="GET"
#   url="https://127.0.0.1:61949/apis/apps/v1/namespaces/demo/deployments/signed-app"
# => one GET, no write, so no webhook is ever consulted. Unfiltered, that same
#    command still reports `deployment.apps/signed-app unchanged (server dry
#    run)` at exit 0 — a result that proves NOTHING about admission.
```

Server-side apply is the repeatable check because it always sends the PATCH
with `dryRun=All` — the request traverses the whole admission chain whether or
not the object changed, and the apiserver discards the result:

```bash
kubectl apply -f workloads/signed-app/deployment.yaml \
  --server-side --dry-run=server --field-manager=evidence-check -v=8 2>&1 \
  | grep -E 'round_trippers.*"Request" verb' | grep -v openapi
# "Request" verb="PATCH" url=".../deployments/signed-app?dryRun=All&fieldManager=evidence-check&fieldValidation=Strict&force=false"
# (three PATCHes, all dryRun=All — a real request, not a client diff)

kubectl apply -f workloads/signed-app/deployment.yaml \
  --server-side --dry-run=server --field-manager=evidence-check
# deployment.apps/signed-app serverside-applied (server dry run)      (exit 0)

kubectl -n demo get pod -l app=signed-app -o jsonpath='{.items[*].status.containerStatuses[*].imageID}'
# ghcr.io/joesevv/k8s-security-lab/signed-app@sha256:7fd13d22d934f420...3337b
# => the running container is the exact digest cosign signed in run 30174855073.
```

`--field-manager=evidence-check` is not cosmetic: the live object is owned by
`kubectl-client-side-apply`, and the default manager makes kubectl try to
migrate the `last-applied-configuration` annotation, printing a conflict
warning (non-fatal, still exit 0). A distinct manager keeps the transcript
clean. The apply is allowed to co-own the fields only because the values it
sends MATCH the live ones.

That the flag really reaches the signature webhook is proven on the SAME code
path, not inferred from a different one: re-apply the same Deployment with the
same flags and only the image swapped for the unsigned artifact of 3b. Same
object, same PATCH, one variable — and it is denied:

```bash
sed 's|^\( *image: \).*$|\1ghcr.io/joesevv/k8s-security-lab/signed-app:sha256-b4cb133e03a5c9b567511956055f668267425aa391d2797d1783d2c83b7c141e|' \
    workloads/signed-app/deployment.yaml \
  | kubectl apply -f - --server-side --force-conflicts --dry-run=server \
      --field-manager=evidence-check
# Error from server: admission webhook
# "ivpol.validate.kyverno.svc-fail-finegrained-require-keyless-signed-ghcr"
# denied the request: Policy require-keyless-signed-ghcr failed: Image must be
# cosign keyless-signed by the k8s-security-lab GitHub Actions workflow.
# (exit 1)
```

`--force-conflicts` is needed here and only here: changing the image claims a
field `kubectl-client-side-apply` owns, which returns a 409 conflict BEFORE
admission runs — and a conflict is not a policy verdict. Forcing ownership
lets the request reach the webhook. It is still a dry run; nothing is
persisted, and
`kubectl -n demo get deploy signed-app -o jsonpath='{..image}'` still reports
the signed `sha256:7fd13d22...` digest afterwards.

**3b. HEADLINE — an image that REALLY EXISTS and has NO signature is denied.**
The reference is cosign's own signature artifact for an earlier signed build of
this app (digest `sha256:b4cb133e...`, still present in GHCR), published under
the OCI 1.1 referrers-fallback tag `sha256-<digest-of-the-signed-image>`.
It is a genuine, pullable manifest under the enforced glob — and, being a
signature itself, nothing ever signed IT. The registry resolves it, so the
denial can only come from signature verification:

```bash
kubectl apply -f docs/evidence/phase-4-supply-chain/attack-unsigned-existing-artifact.yaml
# Error from server: ... admission webhook
# "ivpol.validate.kyverno.svc-fail-finegrained-require-keyless-signed-ghcr"
# denied the request: Policy require-keyless-signed-ghcr failed: Image must be
# cosign keyless-signed by the k8s-security-lab GitHub Actions workflow.
# (exit 1)
```

The Pod is fully compliant with every other control (allow-listed registry,
explicit non-bare tag, not privileged, drops ALL, runAsNonRoot, no privesc,
readOnlyRootFilesystem, RuntimeDefault seccomp, `automountServiceAccountToken:
false`), so signature verification is the only gate left that can deny it.

That the reference is real, not a typo — the package holds four tags today: two
per signed build, the image tag and cosign's referrers-fallback signature tag.
The anonymous token below works because the GHCR package is public in its own
right; that is independent of the source repo's visibility:

```bash
TOKEN=$(curl -s "https://ghcr.io/token?scope=repository:joesevv/k8s-security-lab/signed-app:pull" \
  | sed -E 's/.*"token":"([^"]+)".*/\1/')
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://ghcr.io/v2/joesevv/k8s-security-lab/signed-app/tags/list"
# {"name":"joesevv/k8s-security-lab/signed-app","tags":[
#   "4428b14a168491f5e67847ef7ec0ac770b899a05",
#   "sha256-b4cb133e03a5c9b567511956055f668267425aa391d2797d1783d2c83b7c141e",
#   "b8483c5892a16afb16c1a15aaaa35b3c8436dd65",
#   "sha256-7fd13d22d934f4202edc164e525436e190498590b62c41e348b1a4092eb3337b"]}
```

The list grows by two tags with every CI run on a new commit, so a replay
should check that the attack's target tag
`sha256-b4cb133e03a5c9b567511956055f668267425aa391d2797d1783d2c83b7c141e` is
present, not that the list has four entries.

**3c. FAIL-CLOSED — a DIFFERENT property, shown separately.** A reference CI
never built. The policy cannot even attempt verification, and `failurePolicy:
Fail` denies rather than admitting by default:

```bash
kubectl apply -f docs/evidence/phase-4-supply-chain/attack-unsigned-image.yaml
# ... Policy require-keyless-signed-ghcr error: failed to evaluate policy:
# GET https://ghcr.io/v2/.../signed-app/manifests/unsigned:
# MANIFEST_UNKNOWN: manifest unknown            (exit 1)
```

Read the two messages side by side: 3b says `failed: Image must be cosign
keyless-signed`, 3c says `error: failed to evaluate policy` + a registry 404.
Same outcome, different mechanism. 3c alone would NOT prove signature checking
— it proves the gate does not fail open. 3b is the signature proof.

**3d. CONTROLLER PATH — denied in a Deployment, not just a bare Pod.**
Enforcement on `apps/v1` comes from explicit `resourceRules`, not from Kyverno
autogen — the policy header records `spec.autogen.podControllers` as a no-op on
1.18.2, and the live object today carries no `spec.autogen` with
`status.autogen: {}`. Because that coverage rests on hand-written rules it is
proven separately. Take the REAL signed-app Deployment and rewrite only the
image (plus its name/labels, so a hypothetical admission could not adopt the
real pods) — every other field is byte-identical to 3a:

```bash
sed -e 's|^\( *image: \).*$|\1ghcr.io/joesevv/k8s-security-lab/signed-app:sha256-b4cb133e03a5c9b567511956055f668267425aa391d2797d1783d2c83b7c141e|' \
    -e 's|signed-app$|attack-unsigned-deploy|' \
    workloads/signed-app/deployment.yaml | kubectl apply -f -
# Error from server: error when creating "STDIN": ... denied the request:
# Policy require-keyless-signed-ghcr failed: Image must be cosign
# keyless-signed by the k8s-security-lab GitHub Actions workflow.   (exit 1)
# => rejected at apply, before any ReplicaSet or Pod exists.
```

**3e. NEGATIVE CONTROL — nginx is out of glob and unaffected:**

Same server-side form as 3a, for the same reason — a plain `--dry-run=server`
on this unchanged Deployment would never leave the client:

```bash
kubectl apply -f workloads/nginx/deployment.yaml \
  --server-side --dry-run=server --field-manager=evidence-check
# deployment.apps/nginx serverside-applied (server dry run)   (exit 0)
kubectl -n demo get pods -l app=nginx
# nginx-775678cbbd-mmrxb   1/1   Running   0   4h34m
# nginx-775678cbbd-q7ddt   1/1   Running   0   4h34m
```

A full server-side admission pass on an out-of-glob image succeeds and both
replicas keep running: the gate is scoped, not global.

Full verbatim captures, including the post-attack cluster state:
`docs/evidence/phase-4-supply-chain/attack-output.txt`.

---

## 4. Teardown

Nothing to tear down from the attacks: all three were rejected at admission, so
no attacker Pod, ReplicaSet or Deployment was ever created. Confirm:

```bash
kubectl -n demo get pods -l role=supply-chain-demo
# No resources found in demo namespace.       (both attack Pods carry this label)
kubectl get pods -A | grep -iE "attack"; echo $?
# 1   (no match, cluster-wide)
```

The layer itself stays so the demo is replayable: the policy, the signed-app
Deployment and its ServiceAccount, and the published GHCR image remain.

To remove the layer entirely (not done for the lab):

```bash
kubectl delete -f policies/supply-chain/require-signed-images.yaml  # stop enforcing
kubectl delete -f workloads/signed-app/                             # remove the workload
```

Note the deliberately shallow path: `kubectl delete -f policies/` is
non-recursive and will NOT remove this policy — that is the point of keeping it
in `policies/supply-chain/`.
