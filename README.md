# k8s-security-lab

Hardened Kubernetes cluster + secure software supply chain, built to demonstrate "attack → control blocks it".

## Goal

Security is the point of this project, not DevOps. Kubernetes and CI are only the substrate; the real deliverable is a set of concrete, defensible security controls. Every layer of the stack gets a documented attack demo with before/after evidence, so the effect of each control is observable rather than assumed. The aim is to prove that a specific attack succeeds when a control is absent and is blocked once the control is in place. Treat this repo as a case study you can read top to bottom.

## Architecture

A local kind cluster (1 control-plane + 2 workers) running on Docker Desktop with the WSL2 backend, defined entirely as code so the environment is reproducible. Each security layer is added on top of this baseline cluster and exercised with its own attack demo. A diagram will be added later.

## Security layers

| Layer | Tool | Attack it blocks | Status |
| --- | --- | --- | --- |
| RBAC hardening | Kubernetes RBAC | Privilege escalation via over-broad service account permissions | planned |
| Admission control | Kyverno | Deploying privileged / non-compliant workloads | planned |
| Network policies | Kubernetes NetworkPolicy | Lateral movement between pods | planned |
| Secrets management | sealed-secrets | Plaintext secrets committed to Git | planned |
| Supply chain | GitHub Actions + Trivy + SBOM + cosign | Shipping vulnerable or unsigned images | planned |
| GitOps CD | ArgoCD | Untracked / manual cluster drift | planned |
| Runtime detection | Falco | Malicious runtime behavior (shell in container, etc.) | planned |
| CIS compliance | kube-bench | Insecure cluster configuration | planned |
| Custom controller (stretch) | Go | Enforcing a bespoke security invariant | planned |

## Attack → control mapping

This section will grow one entry per demonstrated attack, each pairing the attack with the control that blocks it and linking to the captured before/after evidence.

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

Project scaffolding, no cluster components deployed yet — 2026-07-21.
