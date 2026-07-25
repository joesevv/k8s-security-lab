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
2. **The current two-job workflow has never run.** The signed artifact this lab
   admits was produced by an earlier single-job version. The `build-scan` /
   `sign` split, the SHA-pinned actions and the cosign verify self-check are
   written but unproven until the next push to `app/signed-app/**`.

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
  # GHCR login, cosign-installer, cosign sign --yes <image>@<digest>,
  # cosign verify self-check, evidence upload
```

`id-token: write` is the permission that lets a job mint the OIDC token whose
subject Kyverno trusts. **Every third-party action runs in `build-scan`, where
that permission is denied** — docker, trivy, syft and upload-artifact cannot
mint the signing identity even if one of them is compromised or its tag is
moved. The `sign` job holds `id-token: write` but runs nothing except GHCR
login and cosign, and does **not** check out the repo, so no source tree exists
in the privileged job. Every action is pinned to a 40-char commit SHA for the
same reason a tag is not trusted for images.

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

**Status, plainly: this two-job shape has not yet run in CI.** The image the
cluster admits today —
`signed-app:4428b14a...@sha256:b4cb133e...` — was produced by the earlier
single `build-sign` job. Consequently
`docs/evidence/phase-4-supply-chain/cosign-verify.txt` does not exist yet; it
lands there after the first run of the split workflow.

**Known gaps, stated rather than hidden:**

- **Trivy is report-only** (`exit-code: '0'`, severity `CRITICAL,HIGH`, SARIF
  uploaded as an artifact). CVEs are recorded, never enforced. The choice is
  deliberate — a lab that cannot produce a signed image because upstream shipped
  a HIGH in libc teaches nothing about signing — but it means **the signature
  says nothing about vulnerabilities.**
- **The SBOM is a CI artifact, not an attestation.** `sbom.spdx.json` is
  uploaded with `actions/upload-artifact`; it is not `cosign attest`-ed against
  the image digest, so it is not bound to the image and **no admission policy
  can verify it.** Closing this means switching to a cosign attestation and
  adding an attestation check to the policy. Not done.

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
on the lab host (`command -v cosign` -> exit 1). The only signature verification
actually demonstrated anywhere in this lab is in-cluster, at admission
(section 3). The CI self-check in section 1 is written but has never run, so it
is not evidence yet.

---

## 3. Attack demo — an unsigned image is refused admission

Frame: an attacker can push to, or already has an image sitting at, the trusted
GHCR path. Registry allow-listing cannot tell that image from ours. Signature
verification can.

**3a. POSITIVE CONTROL — the signed image is admitted.** Use `--dry-run=server`,
not a plain apply: an unchanged object reports `unchanged` as a no-op that can
short-circuit the webhooks. Server dry-run forces the full admission chain and
changes nothing.

```bash
kubectl apply -f workloads/signed-app/deployment.yaml --dry-run=server
# deployment.apps/signed-app unchanged (server dry run)      (exit 0)

kubectl -n demo get pod -l app=signed-app -o jsonpath='{.items[*].status.containerStatuses[*].imageID}'
# ghcr.io/joesevv/k8s-security-lab/signed-app@sha256:b4cb133e03a5c9b5675119...c141e
# => the running container is the exact digest cosign signed.
```

That the flag really exercises the webhook (rather than skipping it) is proven
by running the SAME flag against the unsigned manifest from 3b — it is denied:

```bash
kubectl apply -f docs/evidence/phase-4-supply-chain/attack-unsigned-existing-artifact.yaml \
  --dry-run=server
# ... denied the request: Policy require-keyless-signed-ghcr failed: Image must
# be cosign keyless-signed by the k8s-security-lab GitHub Actions workflow.
```

**3b. HEADLINE — an image that REALLY EXISTS and has NO signature is denied.**
The reference is cosign's own signature artifact for the signed app, published
under the OCI 1.1 referrers-fallback tag `sha256-<digest-of-the-signed-image>`.
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

That the reference is real, not a typo — the repo holds exactly two tags:

```bash
TOKEN=$(curl -s "https://ghcr.io/token?scope=repository:joesevv/k8s-security-lab/signed-app:pull" \
  | sed -E 's/.*"token":"([^"]+)".*/\1/')
curl -s -H "Authorization: Bearer $TOKEN" \
  "https://ghcr.io/v2/joesevv/k8s-security-lab/signed-app/tags/list"
# {"name":"joesevv/k8s-security-lab/signed-app","tags":[
#   "4428b14a168491f5e67847ef7ec0ac770b899a05",
#   "sha256-b4cb133e03a5c9b567511956055f668267425aa391d2797d1783d2c83b7c141e"]}
```

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

```bash
kubectl apply -f workloads/nginx/deployment.yaml --dry-run=server
# deployment.apps/nginx unchanged (server dry run)            (exit 0)
kubectl -n demo get pods -l app=nginx
# nginx-775678cbbd-mmrxb   1/1   Running   0   69m
# nginx-775678cbbd-q7ddt   1/1   Running   0   69m
```

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
