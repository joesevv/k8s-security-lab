# Phase 4 — supply-chain demo image. This is the app that CI (GitHub Actions)
# builds, scans with Trivy, generates an SBOM for, and cosign keyless-signs.
# Its provenance is then enforced on-cluster by the Kyverno ImageValidatingPolicy,
# which admits the image only when it carries a valid keyless signature tied to
# this repo's workflow identity.
#
# Base is PINNED by tag@sha256 digest — never bare/latest. This is the exact same
# trusted base the lab's nginx workload already runs (see workloads/nginx/
# deployment.yaml), so the no-latest / restrict-registries Kyverno policies are
# satisfied and the bytes cannot drift. nginx-unprivileged runs as non-root
# (uid 101) and listens on 8080, keeping it compatible with
# readOnlyRootFilesystem and the demo's service pattern.
FROM nginxinc/nginx-unprivileged:1.29.8-alpine@sha256:0c79d56aee561a1d81c63f00eee5fb5fe29279560cdc55e91425133104c7fbe6

# Ship only our own static page. No extra packages, no shell tooling added —
# minimal surface for Trivy to scan and for the SBOM to describe.
COPY index.html /usr/share/nginx/html/index.html
