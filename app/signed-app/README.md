<!-- Phase 4 — explains what the signed-app image is and the supply-chain
     guarantees around it, so a reader knows why this build context exists. -->
# signed-app — phase-4 supply-chain demo image

A minimal, hardened static web app used to demonstrate a secure software supply
chain end to end. It serves a single `index.html` from
`nginxinc/nginx-unprivileged` (pinned by `tag@sha256` digest), running as
non-root (uid 101) on port 8080 — compatible with `readOnlyRootFilesystem` and
the demo's service pattern.

## Supply chain

GitHub Actions CI builds this image and then:

- **Scans** it for vulnerabilities with Trivy.
- **Generates an SBOM** describing its contents.
- **Signs** it with **cosign keyless signing** (OIDC), binding the signature to
  the repository's workflow identity — no long-lived private key.

## Admission

Kyverno's **ImageValidatingPolicy** verifies the cosign keyless signature at
admission time. The image is admitted **only** when it carries a valid signature
from this repo's GitHub Actions workflow identity; unsigned or foreign-signed
images are rejected.

## Local build (verification only — do not push)

```sh
docker build -t signed-app:localtest app/signed-app
docker run --rm signed-app:localtest id            # uid=101 (non-root)
docker run --rm -d -p 18080:8080 --name signed-app-test signed-app:localtest
curl -s http://localhost:18080/
docker rm -f signed-app-test
```
