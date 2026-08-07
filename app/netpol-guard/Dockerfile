# Phase 8 — build context for the netpol-guard controller.
#
# THIS IMAGE HAS NEVER BEEN PUBLISHED. Phase 5b turned on the
# AlwaysPullImages admission plugin, so the kubelet must pull every image from
# a registry and `kind load` side-loading no longer works. CI
# (.github/workflows/supply-chain.yml) builds only app/signed-app and pushes
# only on push to `main`. Publishing this one by hand needs a registry
# credential, which is a human gate. Phase 8's demo therefore ran the
# controller OUT OF CLUSTER against the kubeconfig, and the in-cluster
# manifests in docs/evidence/phase-8-netpol-guard/ are committed UNAPPLIED.
# See that runbook's section 5 for exactly what in-cluster would require.
#
# Both bases are PINNED by tag@sha256, matching app/signed-app/Dockerfile.
# The two digests were resolved from the registries on 2026-08-07 with an
# anonymous manifest HEAD (no credential); they are the multi-arch index
# digests, not per-platform ones.

FROM golang:1.26.5-alpine@sha256:0178a641fbb4858c5f1b48e34bdaabe0350a330a1b1149aabd498d0699ff5fb2 AS build

WORKDIR /src

# Dependencies first so a code-only change does not re-resolve the module
# graph. go.sum is committed, so this step is reproducible.
COPY go.mod go.sum ./
RUN go mod download

COPY *.go ./

# CGO_ENABLED=0 is what makes the binary runnable on the static distroless
# base below — there is no libc there to dynamically link against.
# -trimpath keeps build-host paths out of the binary.
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/netpol-guard .

# Distroless static: no shell, no package manager, no libc. The controller
# talks to the apiserver over TLS and needs nothing else from userspace; the
# CA bundle it uses comes from the ServiceAccount projection at
# /var/run/secrets/kubernetes.io/serviceaccount/ca.crt, not from the image.
FROM gcr.io/distroless/static-debian12:nonroot@sha256:f5b485ea962d9bd1186b2f6b3a061191539b905b82ec395de78cbfae51f20e35

COPY --from=build /out/netpol-guard /usr/local/bin/netpol-guard

# 65532 is distroless' `nonroot` uid. Stated explicitly so the image cannot be
# read as root-by-default, and so it agrees with the runAsUser in the
# committed Deployment.
USER 65532:65532

ENTRYPOINT ["/usr/local/bin/netpol-guard"]

# Detect-only by default. Turning on enforcement has to be a deliberate act in
# the Deployment's args, not something inherited silently from the image.
CMD ["--namespace=demo", "--remediate=false", "--interval=30s"]
