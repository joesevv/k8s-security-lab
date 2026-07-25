# Runbook — Phase 3: Secrets management (sealed-secrets)

A replayable command log for the secrets layer: install the sealed-secrets
controller into `kube-system`, seal a fake-but-realistic credential so only
RSA-encrypted ciphertext is committed to Git, apply it and watch the
controller materialize the real `Secret` in-cluster — then a live attack
proving the committed ciphertext is useless to a repo reader (base64 decodes
to garbage), that strict scope refuses a stolen-and-reused SealedSecret, and
that the plaintext never reaches Git. Commands are in execution order; each
has a one-line purpose and the observed output.

Host: Windows 11 + Docker Desktop (WSL2). Commands were run from Git Bash
unless noted. Kubernetes node image v1.35.5.

**Redaction caveat, up front:** the real demo credential (namespace `demo`,
Secret `demo-app-secret`, key `db-password`) is NEVER printed in this runbook
or in any committed file. It lives only in the gitignored
`secrets/plain/demo-app-secret-plain.yaml`. Every "does it match?" proof uses
SHA-256, and every command reads the value from that gitignored file rather
than typing it inline. If the plaintext appeared in a committed file, this
phase would have failed its own gate.

---

## 0. The controls

- **sealed-secrets controller (chart 2.19.1 / app 0.38.4) in `kube-system`** —
  a Kubernetes controller plus a `SealedSecret` CRD (`bitnami.com/v1alpha1`).
  On first start it generates an RSA keypair and stores the PRIVATE half as a
  Secret in `kube-system` that never leaves the cluster. **Why it is needed:**
  a normal Secret's `data` is base64 ENCODING, not encryption; committing one
  to Git hands the credential to anyone who can read the repo.
- **The committed artifact `secrets/demo-app-sealedsecret.yaml`** — RSA-OAEP +
  AES-GCM ciphertext produced by `kubeseal` against the controller's PUBLIC
  cert. **Why it is safe to commit:** the public cert can only ENCRYPT; only
  the in-cluster private key can decrypt, so the ciphertext is inert outside
  this specific cluster.
- **Default STRICT scope** — the ciphertext is cryptographically bound to its
  `namespace/name` (`demo/demo-app-secret`). **Why it is needed:** it stops an
  attacker who copies the committed SealedSecret from re-applying it into a
  namespace they control to farm out the plaintext — the controller refuses
  to decrypt a mismatched scope.
- **Gitignored `secrets/plain/`** — the plaintext original and the fetched
  public cert live here only; `.gitignore` already carries `secrets/plain/`,
  `*-secret-plain.yaml`, and `*.pem`, so they are never staged.

Least-privilege throughout: the controller lives in `kube-system` and touches
only its own CRD and the Secrets it owns; the `demo` Secret is created by the
controller, not by a human committing plaintext.

---

## 1. Install the controller

The upstream project moved GitHub orgs — the old `bitnami-labs.github.io`
Pages repo now 404s; the live chart repo is `bitnami.github.io/sealed-secrets`.
The chart version for app 0.38.4 is resolved empirically, not assumed.

```bash
helm repo add sealed-secrets https://bitnami.github.io/sealed-secrets
helm repo update sealed-secrets
helm search repo sealed-secrets -l | grep -E "0\.38\.4"
# sealed-secrets/sealed-secrets   2.19.1   0.38.4   Helm chart for the sealed-secrets controller.

helm install sealed-secrets sealed-secrets/sealed-secrets \
  --namespace kube-system --version 2.19.1 \
  --set fullnameOverride=sealed-secrets-controller
# STATUS: deployed

kubectl -n kube-system rollout status deploy/sealed-secrets-controller --timeout=120s
# deployment "sealed-secrets-controller" successfully rolled out

kubectl -n kube-system get pods | grep -i sealed
# sealed-secrets-controller-74d5bcfff-pfxql   1/1   Running   0   18s

kubectl get crd | grep -i sealed
# sealedsecrets.bitnami.com                    2026-07-23T22:40:26Z

kubectl api-resources | grep -i sealed
# sealedsecrets   bitnami.com/v1alpha1   true   SealedSecret
```

`fullnameOverride=sealed-secrets-controller` names the Service/Deployment to
match kubeseal's defaults. The served apiVersion `bitnami.com/v1alpha1` is
CORRECT for this controller — the lab's "avoid v1alpha1" rule is Kyverno-only.
Full install record: `clusters/sealed-secrets-install.md`.

---

## 2. Seal a secret — plaintext never touches Git

```bash
# 2a. Write the PLAINTEXT manifest ONLY to the gitignored path.
kubectl create secret generic demo-app-secret -n demo \
  --from-literal=db-password='<DEMO-CREDENTIAL — not shown; in secrets/plain/>' \
  --dry-run=client -o yaml > secrets/plain/demo-app-secret-plain.yaml
git check-ignore secrets/plain/demo-app-secret-plain.yaml
# secrets/plain/demo-app-secret-plain.yaml   (ignored — confirmed)

# 2b. Fetch the controller's PUBLIC cert (also gitignored: *.pem).
kubeseal --fetch-cert \
  --controller-namespace kube-system --controller-name sealed-secrets-controller \
  > secrets/plain/controller-cert.pem

# 2c. Seal with default STRICT scope into the COMMITTED artifact.
kubeseal --format yaml --cert secrets/plain/controller-cert.pem \
  < secrets/plain/demo-app-secret-plain.yaml \
  > secrets/demo-app-sealedsecret.yaml
# secrets/demo-app-sealedsecret.yaml: apiVersion bitnami.com/v1alpha1, kind
# SealedSecret, spec.encryptedData.db-password = ciphertext (a '#' rationale
# header is prepended by hand — see the committed file).

# 2d. Apply it; the controller unseals it into a real Secret it OWNS.
kubectl apply -f secrets/demo-app-sealedsecret.yaml
kubectl get sealedsecret,secret demo-app-secret -n demo
# sealedsecret.bitnami.com/demo-app-secret            True   3s
# secret/demo-app-secret                   Opaque   1      3s
# controller log: reason 'Unsealed' SealedSecret unsealed successfully
```

Both objects now exist: the `Secret` is created by the controller (owner
reference points at the `SealedSecret`), NOT committed as plaintext.

**Round-trip proof (SHA-256, no plaintext).** The value is read from the
gitignored plain file, so it is never echoed:

```bash
grep 'db-password:' secrets/plain/demo-app-secret-plain.yaml | awk '{print $2}' \
  | base64 -d | sha256sum
# 2a8d0a93a6387c37cba8af645e0cf275c712f5542c4c8440c703bd057011769c   (intended input)
kubectl get secret demo-app-secret -n demo -o jsonpath='{.data.db-password}' \
  | base64 -d | sha256sum
# 2a8d0a93a6387c37cba8af645e0cf275c712f5542c4c8440c703bd057011769c   (in-cluster decrypted)
# => MATCH: the controller unsealed exactly the intended credential.
```

---

## 3. Attack demo — a repo reader tries to recover the secret

Frame: an attacker clones the repo and tries to extract the credential.

**3a. BASELINE (the vulnerability) — base64 is not encryption.** Uses a
THROWAWAY value, never the real one:

```bash
kubectl create secret generic example-plain -n demo \
  --from-literal=example-key='hello-not-a-real-secret' --dry-run=client -o yaml \
  | grep 'example-key:'
# example-key: aGVsbG8tbm90LWEtcmVhbC1zZWNyZXQ=
echo aGVsbG8tbm90LWEtcmVhbC1zZWNyZXQ= | base64 -d
# hello-not-a-real-secret
# => anyone can decode a committed plaintext Secret. That is the threat.
```

**3b. CONTROL HOLDS — the real ciphertext decodes to garbage.** Straight from
the committed artifact:

```bash
# Read spec.encryptedData.db-password straight out of the COMMITTED manifest
# and decode it — no attacker-side setup, just what a repo reader can do.
grep 'db-password:' secrets/demo-app-sealedsecret.yaml | awk '{print $2}' \
  | base64 -d | xxd | head
# -> 00000000: 0200 5069 ecab 1154 8754 5ca2 e936 0984  ..Pi...T.T\..6..
# -> 00000010: 2ccc 6f66 ce5a abc0 6eaf b1e4 9447 e2cf  ,.of.Z..n....G..
# -> 00000020: 89fe 9e1d e945 7347 00b3 d471 51db f8cf  .....EsG...qQ...
# -> 00000030: 125c 9595 8378 7fb2 b2d9 85f7 acad d2e9  .\...x..........
# -> 00000040: e6af 4888 4556 99e5 4924 660b 73d8 defd  ..H.EV..I$f.s...
# -> 00000050: 7bda 2386 6fe4 ef79 3268 598c 191e df52  {.#.o..y2hY....R
# -> 00000060: 62d0 2e17 74e3 3637 b425 e6b5 db46 52ad  b...t.67.%...FR.
# -> 00000070: 5d4b 60b1 80b0 652d d659 8907 e869 235e  ]K`...e-.Y...i#^
# -> 00000080: b307 996c 52e5 bb2c 47e6 71a7 a3d8 8511  ...lR..,G.q.....
# -> 00000090: f496 1143 b7a7 ea84 e0ff 53f2 85e7 8488  ...C......S.....
# => 0200 is the SealedSecret binary envelope header; everything after it is
#    RSA-OAEP + AES-GCM ciphertext. No private key -> nothing recoverable.
```

The fetched cert is a PUBLIC key (encrypt-only). The private key is a Secret in
`kube-system` that never leaves the cluster, so offline unsealing is impossible.

**3c. STRICT-SCOPE ANTI-THEFT — reseal into an attacker namespace is refused.**
Copy the committed SealedSecret, change only `metadata.namespace`
(`demo` -> `attacker`), apply, and watch the controller refuse:

```bash
kubectl create namespace attacker
kubectl apply -f docs/evidence/phase-3-secrets/scope-theft-attacker-ns.yaml
kubectl get sealedsecret,secret demo-app-secret -n attacker
# demo-app-secret   no key could decrypt secret (db-password)   False   18s
# Error from server (NotFound): secrets "demo-app-secret" not found
kubectl get events -n attacker | grep -i unseal
# Warning  ErrUnsealFailed  Failed to unseal: no key could decrypt secret (db-password)
kubectl delete -f docs/evidence/phase-3-secrets/scope-theft-attacker-ns.yaml
kubectl delete namespace attacker
```

Same ciphertext, one namespace of difference: strict scope binds the
ciphertext to `demo/demo-app-secret`, so NO Secret is produced for the
attacker. Contrast with 2d, where the correctly-scoped apply produced the
Secret in milliseconds.

**3d. NO-PLAINTEXT-IN-GIT (headline).** `git grep --untracked` searches
tracked + untracked files but skips gitignored ones — exactly the to-be-
committed set. `VAL` = the literal credential, `B64` = its base64 form; both
are derived below FROM the gitignored plain file, never typed or printed:

```bash
# Define both forms first — the searches are meaningless without them.
B64=$(grep 'db-password:' secrets/plain/demo-app-secret-plain.yaml \
      | awk '{print $2}')
VAL=$(printf '%s' "$B64" | base64 -d)
[ -n "$B64" ] && [ -n "$VAL" ] && echo "VAL/B64 set (values not printed)"
# -> VAL/B64 set (values not printed)
# => The non-empty guard is not decoration: if either variable is UNSET the
#    commands below degrade to `git grep -n ""`, which matches EVERY line of
#    EVERY file and exits 0 — silently inverting this proof into an apparent
#    leak. Confirm the echo above before trusting anything after it.

git grep --no-index -l "$B64"          # positive control: value exists...
# -> secrets/plain/demo-app-secret-plain.yaml  # ...only in the IGNORED file
git grep --untracked -n "$VAL"; echo $?  # committed set, literal  -> 1 (no match)
git grep --untracked -n "$B64"; echo $?  # committed set, base64   -> 1 (no match)
git log --all -p -- secrets/ | grep "$VAL"; echo $?   # history    -> 1 (no match)
git check-ignore secrets/plain/demo-app-secret-plain.yaml secrets/plain/controller-cert.pem
# both paths echoed  => both ignored, never staged
```

Full verbatim captures: `docs/evidence/phase-3-secrets/attack-output.txt`.

---

## 4. Teardown

The attack objects (the `attacker` namespace and its stolen SealedSecret) are
removed in 3c. The layer itself stays: the committed
`secrets/demo-app-sealedsecret.yaml`, the in-cluster `Secret` it produces, and
the controller in `kube-system` remain so the demo is replayable. The plaintext
original and cert stay in the gitignored `secrets/plain/`.

To remove the layer entirely (not done for the lab):

```bash
kubectl delete -f secrets/demo-app-sealedsecret.yaml   # + its owned Secret
helm uninstall sealed-secrets -n kube-system           # the controller ONLY
```

**`helm uninstall` does NOT destroy the sealing key.** This is the trap in a
phase about key custody: the RSA private key is generated by the controller at
runtime, not rendered by the chart, so it is absent from the Helm release
manifest and carries no Helm ownership metadata — `helm uninstall` walks past
it. The CRD is likewise not Helm-owned (Helm never deletes CRDs). Both survive
in the cluster. Verify before believing either way:

```bash
kubectl -n kube-system get secret \
  -l sealedsecrets.bitnami.com/sealed-secrets-key -o name
# -> secret/sealed-secrets-key2t2vk      (the RSA keypair, still present)

kubectl -n kube-system get secret \
  -l sealedsecrets.bitnami.com/sealed-secrets-key \
  -o jsonpath='{.items[*].metadata.labels}{"\n"}'
# -> {"sealedsecrets.bitnami.com/sealed-secrets-key":"active"}

kubectl -n kube-system get secret \
  -l sealedsecrets.bitnami.com/sealed-secrets-key \
  -o jsonpath='{.items[*].metadata.annotations}{"\n"}'
# -> (blank line — the Secret carries NO annotations at all)
# => no app.kubernetes.io/managed-by: Helm label and no meta.helm.sh/
#    release-name annotation: Helm has no ownership record for this Secret.

helm get manifest sealed-secrets -n kube-system | grep -E '^kind:' | sort -u
# -> kind: ClusterRole
# -> kind: ClusterRoleBinding
# -> kind: Deployment
# -> kind: Role
# -> kind: RoleBinding
# -> kind: Service
# -> kind: ServiceAccount
# => the release manifest contains NO Secret and NO CustomResourceDefinition,
#    so the key Secret and the CRD are precisely what `helm uninstall` leaves
#    behind — it only deletes what it rendered.
```

Removing the key material and the CRD takes explicit follow-up commands. This
is IRREVERSIBLE — once the private key is gone, every committed SealedSecret
sealed against it is permanently undecryptable, including
`secrets/demo-app-sealedsecret.yaml`:

```bash
kubectl -n kube-system delete secret \
  -l sealedsecrets.bitnami.com/sealed-secrets-key   # destroys the RSA key
kubectl delete crd sealedsecrets.bitnami.com        # removes the CRD + any CRs
```
