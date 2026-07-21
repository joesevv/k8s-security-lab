# Replay note — Phase 2a RBAC evidence

**When the 403 was captured:** the HTTP 403 in `attack-output.txt` (and the
`can-i` matrix in `can-i-matrix.txt`) were captured on **2026-07-21, before Phase
2c (NetworkPolicy) existed**. They are point-in-time, verbatim artifacts and are
not edited.

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

## Original captures (do not edit)

- `attack-output.txt` — verbatim 403 JSON + `pods list HTTP:200` contrast.
- `can-i-matrix.txt` — verbatim `auth can-i` matrix for `developer-sa`.
