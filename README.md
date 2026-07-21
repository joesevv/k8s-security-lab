# k8s-security-lab

Hardened Kubernetes cluster + secure software supply chain, built to demonstrate "attack → control blocks it".

## Goal

Security is the point of this project, not DevOps. Kubernetes and CI are only the substrate; the real deliverable is a set of concrete, defensible security controls. Every layer of the stack gets a documented attack demo with before/after evidence, so the effect of each control is observable rather than assumed. The aim is to prove that a specific attack succeeds when a control is absent and is blocked once the control is in place. Treat this repo as a case study you can read top to bottom.

## Architecture

A local kind cluster (1 control-plane + 2 workers) running on Docker Desktop with the WSL2 backend, defined entirely as code so the environment is reproducible. Kubernetes is pinned to v1.35.5 (node image pinned by digest) because the upcoming Kyverno 1.18 admission layer supports Kubernetes 1.33–1.35 only, so the cluster sits at the top of that supported window. Each security layer is added on top of this baseline cluster and exercised with its own attack demo. A diagram will be added later.

## Security layers

| Layer | Tool | Attack it blocks | Status |
| --- | --- | --- | --- |
| RBAC hardening | Kubernetes RBAC | Privilege escalation via over-broad service account permissions | done |
| Admission control | Kyverno | Deploying privileged / non-compliant workloads | done |
| Network policies | Kubernetes NetworkPolicy | Lateral movement between pods | done |
| Secrets management | sealed-secrets | Plaintext secrets committed to Git | planned |
| Supply chain | GitHub Actions + Trivy + SBOM + cosign | Shipping vulnerable or unsigned images | planned |
| GitOps CD | ArgoCD | Untracked / manual cluster drift | planned |
| Runtime detection | Falco | Malicious runtime behavior (shell in container, etc.) | planned |
| CIS compliance | kube-bench | Insecure cluster configuration | planned |
| Custom controller (stretch) | Go | Enforcing a bespoke security invariant | planned |

## Attack → control mapping

This section will grow one entry per demonstrated attack, each pairing the attack with the control that blocks it and linking to the captured before/after evidence.

| Control | Attack | Evidence |
| --- | --- | --- |
| Phase 2a RBAC — least-privilege `developer` Role (get/list/watch pods/services/deployments only) + no-token `nginx-sa` | Token-bearing pod (`developer-sa`) uses its mounted ServiceAccount token to read Secrets via the API | HTTP 403 Forbidden — [`docs/evidence/phase-2a-rbac/`](docs/evidence/phase-2a-rbac/) (attack-output.txt, can-i-matrix.txt); runbook [`runbooks/phase-2a-rbac.md`](runbooks/phase-2a-rbac.md). Layered defense: the secret-read path is now blocked by **both** RBAC (403) and Phase 2c NetworkPolicy egress default-deny — a replay today times out at the network layer before RBAC's 403, so see [`REPLAY-NOTE.md`](docs/evidence/phase-2a-rbac/REPLAY-NOTE.md) for the replay caveat |
| Phase 2b admission — 4 Kyverno CEL `ValidatingPolicy` rules in Enforce (no privileged, no `:latest`/bare tags, must drop ALL caps, registry allow-list) scoped to `demo` | Four pods, each violating exactly one rule (privileged, `:latest` tag, empty `capabilities.drop`, `registry.k8s.io` image), applied to the cluster | All four denied at admission by the Kyverno webhook, each rejection naming its policy; compliant nginx still rolls out — [`docs/evidence/phase-2b-admission/`](docs/evidence/phase-2b-admission/) (attack-output.txt, attack-*.yaml); runbook [`runbooks/phase-2b-admission.md`](runbooks/phase-2b-admission.md) |
| Phase 2c network — default-deny ingress+egress NetworkPolicies in `demo` with a CoreDNS carve-out (53/UDP+TCP) and a label-based allow pair (nginx ingress from `access=nginx` pods on TCP 8080, matching client egress) | Unauthorized pod (no `access=nginx` label, otherwise identical to the authorized client) curls `nginx.demo.svc.cluster.local` | Connection blocked by NetworkPolicy — HTTP:000 after a 5s timeout, while the labeled control pod gets HTTP:200 in milliseconds and both pods still resolve DNS — [`docs/evidence/phase-2c-network/`](docs/evidence/phase-2c-network/) (attack-output.txt, attacker-unauthorized.yaml, client-authorized.yaml); runbook [`runbooks/phase-2c-network.md`](runbooks/phase-2c-network.md) |

## Repo layout

Planned structure (documentation only — directories are added as each layer is built):

```
clusters/            # kind cluster config
workloads/           # sample app manifests
policies/            # Kyverno admission policies
rbac/                # RBAC roles and bindings
network/             # network policies
secrets/             # sealed-secrets manifests
.github/workflows/   # supply-chain CI (Trivy, SBOM, cosign)
docs/                # threat model, evidence
runbooks/            # replayable command logs
```

## Status

Cluster up — 3 nodes on Kubernetes v1.35.5; hardened nginx target workload (non-root, pinned image, restricted securityContext) running in the `demo` namespace. Phase 2a RBAC hardening landed — dedicated `nginx-sa` (no token mounted) and a least-privilege `developer` Role, with a captured attack demo showing a token-bearing pod blocked (HTTP 403) from reading Secrets — 2026-07-21.
