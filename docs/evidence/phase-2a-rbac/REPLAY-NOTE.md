# Replay note — Phase 2a RBAC evidence

**When the 403 was captured:** the HTTP 403 in `attack-output.txt` and the
`can-i` matrix in `can-i-matrix.txt` were both first captured on **2026-07-21,
before Phase 2c (NetworkPolicy) existed** — that timing is what explains the
HTTP 000 replay described below. `attack-output.txt` is a verbatim
point-in-time artifact and has not been edited. `can-i-matrix.txt` is **not**
unedited: it was re-captured on 2026-07-24 to add the `--as=` flag its printed
commands had omitted, and all its answers are unchanged — see **Original
captures** at the end of this note for the detail.

## Why a naive replay today yields HTTP 000 instead of 403

Phase 2c later added a `default-deny` **egress** NetworkPolicy in the `demo`
namespace with only a DNS carve-out (kube-dns:53). It does **not** allow egress
to the Kubernetes API server on 443. So if you replay the Phase 2a token→API
attack today, the attacker pod cannot reach the API server at all: the curl times
out (`HTTP_STATUS:000`, ~5s) at the **network layer, before RBAC returns its
403**. The exact 403 in `attack-output.txt` is therefore not reproducible while
Phase 2c is applied — this is expected.

## How to reproduce the 403

To exercise the RBAC boundary and see the 403 specifically, either:

- replay the demo in `runbooks/phase-2a-rbac.md` **before** applying Phase 2c, or
- temporarily add a scoped API-server egress allow (443 to the API server) so the
  request reaches the authorization layer, then remove it afterward.

## Defense-in-depth framing

The secret-read path is now blocked by **two independent layers**:

1. **RBAC authorization** — `developer-sa` cannot list Secrets (403 Forbidden).
2. **NetworkPolicy egress default-deny** — the attacker pod has no route to the
   API server on 443 at all (HTTP 000 timeout).

Either layer alone stops the exfil; together they are defense-in-depth. The 403
capture demonstrates layer 1 in isolation, as it stood before layer 2 was added.

## The RBAC boundary is still continuously verifiable

`kubectl auth can-i` is evaluated at the API server via your kubeconfig and does
**not** traverse the attacker pod's network, so it still works today with Phase 2c
applied:

```bash
kubectl auth can-i list secrets -n demo \
  --as=system:serviceaccount:demo:developer-sa
# -> no
```

## Original captures

`attack-output.txt` remains an untouched point-in-time capture; do not edit.
`can-i-matrix.txt` was corrected once, on 2026-07-24 — see below. That
correction supersedes the "not edited" framing at the top of this note for
that one file only.

- `attack-output.txt` — verbatim 403 JSON + `pods list HTTP:200` contrast.
  Untouched point-in-time capture from 2026-07-21.
- `can-i-matrix.txt` — `auth can-i` matrix for `developer-sa`. **Corrected on
  2026-07-24.** The original 2026-07-21 capture recorded the correct answers,
  but its printed command lines omitted the `--as=` flag, so they were not
  directly replayable: pasted as written against an admin kubeconfig they
  evaluate the admin, not the ServiceAccount. The file was re-captured with
  `--as=` and now records the generating loop verbatim plus its real stdout.
  **The answers are unchanged** — all eight re-observed answers match the
  2026-07-21 capture. The correction is also documented inside the file itself.
