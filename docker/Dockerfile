# syntax=docker/dockerfile:1.7
#
# transports-spark — single Dockerfile that produces an image
# with the compiled Ada test binaries baked in, plus every
# dependency the testbench needs to run (Alire-managed GNAT,
# gnatprove, openssl, gnutls-cli, Go, mosquitto).
#
# Designed for fast subsequent builds. The cache strategy is
# layered:
#
#   1.  Stage `base` — apt + Alire + GNAT toolchain + gnatprove.
#       Pinned versions; only invalidated when the apt list or
#       the ALIRE/GNAT versions in this file change.
#
#   2.  Stage `deps` — runs `alr -n update` per crate against
#       BuildKit cache mounts (`/root/.cache/alire` + the
#       Alire build cache at `/root/.local/share/alire/builds`).
#       Cache survives across `docker build` invocations on the
#       same host, so transitive dependency rebuilds skip the
#       network and the compile step.
#
#   3.  Stage `build` — copies source and runs `make build`
#       + `make tls-interop-build`. With cache mounts in place,
#       a source-only edit recompiles only the changed crates'
#       own objects (a few seconds), not the dependency tree.
#
#   4.  Stage `runtime` — the final image: built binaries +
#       test data + the host tools needed at run time. The
#       Alire toolchain is preserved so `make prove` works
#       inside the container.
#
# Build:   make docker-image
# Test:    make docker-test       (unit tests across crates)
# Prove:   make docker-prove      (gnatprove sweep)
# Interop: make docker-interop    (Ada TLS vs. openssl / gnutls / Go)
# CI:      make docker-ci         (all of the above, one image)
#
# Direct usage (no make wrapper):
#   docker buildx build --load -t transports-spark:ci -f docker/Dockerfile .
#   docker run --rm transports-spark:ci make tls-test
#   docker run --rm transports-spark:ci make tls-interop
#   docker run --rm transports-spark:ci make prove-quick

ARG UBUNTU_VERSION=24.04
ARG ALIRE_VERSION=2.1.0

# ──────────────────────────────────────────────────────────────
# Stage 1 — base: system packages + Alire + GNAT + gnatprove
# ──────────────────────────────────────────────────────────────
FROM ubuntu:${UBUNTU_VERSION} AS base
ENV DEBIAN_FRONTEND=noninteractive \
    LANG=C.UTF-8 \
    LC_ALL=C.UTF-8

# System packages. Two cache mounts: the apt archive
# (downloaded .deb files) and the dpkg state.  Both persist
# across docker build invocations under BuildKit.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean \
 && apt-get update \
 && apt-get install -y --no-install-recommends \
        ca-certificates curl unzip git make build-essential \
        python3 python3-pip \
        # TLS interop peers — apt-installable ones only.
        # rustls / boringssl / wolfssl need source builds and are
        # opt-in via overnight/Dockerfile.aarch64 if needed.
        openssl \
        gnutls-bin \
        golang-go \
        # MQTT broker used by the QoS round-trip demos
        mosquitto mosquitto-clients \
        # gprbuild's runtime + linker bits
        zlib1g-dev libgmp-dev libssl-dev

# Alire — pinned. Arch-aware so the image builds on both Apple
# Silicon hosts (aarch64) and x86_64 CI runners.
ARG ALIRE_VERSION
RUN ARCH=$(uname -m) \
 && case "$ARCH" in \
        aarch64) ALR_ARCH=aarch64-linux ;; \
        x86_64)  ALR_ARCH=x86_64-linux ;; \
        *) echo "unsupported arch: $ARCH" >&2; exit 1 ;; \
    esac \
 && curl -fsSL "https://github.com/alire-project/alire/releases/download/v${ALIRE_VERSION}/alr-${ALIRE_VERSION}-bin-${ALR_ARCH}.zip" -o /tmp/alr.zip \
 && unzip -q /tmp/alr.zip -d /opt/alire \
 && ln -s /opt/alire/bin/alr /usr/local/bin/alr \
 && rm /tmp/alr.zip \
 && alr --version

# Pre-install the GNAT toolchain Alire prefers, non-interactive.
# Only the download cache (/root/.cache/alire) is a BuildKit cache
# mount — the installed toolchain itself lives on the real image
# fs (/root/.local/share/alire/toolchains) so deps + build stages
# don't trigger a re-deploy.  If we had mounted the whole
# /root/.local/share/alire dir, the install would land in the cache
# and disappear when the mount detached.
RUN --mount=type=cache,target=/root/.cache/alire,sharing=locked \
    alr toolchain --select --disable-assistant gnat_native gprbuild

# Symlink the resolved toolchain binaries into /usr/local/bin so
# every later layer (and `docker run`) finds gcc/gnat/gprbuild on
# PATH without env mangling.
RUN GNAT_BIN=$(ls -d /root/.local/share/alire/toolchains/gnat_native_*/bin | head -1) \
 && GPR_BIN=$(ls -d /root/.local/share/alire/toolchains/gprbuild_*/bin | head -1) \
 && ln -sf "$GNAT_BIN"/* /usr/local/bin/ \
 && ln -sf "$GPR_BIN"/* /usr/local/bin/

# gnatprove — Alire crate; installs to /usr/local/bin via --prefix
# so the Makefile (with GNATPROVE=gnatprove) picks it up unchanged.
RUN --mount=type=cache,target=/root/.cache/alire,sharing=locked \
    alr -n install --prefix=/usr/local gnatprove \
 && gnatprove --version | head -1

# ──────────────────────────────────────────────────────────────
# Stage 2 — deps: warm the Alire crate cache for our manifests
# ──────────────────────────────────────────────────────────────
#
# Copy only the alire.toml + .gpr files first so the cache layer
# survives source edits.  `alr update --syncing` downloads the
# transitive deps for each crate; the actual library build is
# triggered by gprbuild in the next stage and reuses the same
# /root/.local/share/alire/builds cache mount.
FROM base AS deps
WORKDIR /work

# Copy the workspace umbrella so `with` resolution lines up
# with the host layout.
COPY transports_spark.gpr ./transports_spark.gpr

# Per-crate manifests + project files.  Listed explicitly so
# adding/removing a crate is a single-line diff and so the
# layer key is the manifest set, nothing more.
#  Note: `logger` is a library-only crate (no alire.toml) — only the
#  .gpr is needed; the .ads/.adb sources come in with the source COPY
#  in the build stage.
COPY crates/logger/logger.gpr             crates/logger/logger.gpr
COPY crates/rflx_runtime/alire.toml       crates/rflx_runtime/alire.toml
COPY crates/rflx_runtime/rflx_runtime.gpr crates/rflx_runtime/rflx_runtime.gpr
COPY crates/protobuf_core/alire.toml      crates/protobuf_core/alire.toml
COPY crates/protobuf_core/protobuf_core.gpr crates/protobuf_core/protobuf_core.gpr
COPY crates/protobuf_ada/alire.toml       crates/protobuf_ada/alire.toml
COPY crates/protobuf_ada/protobuf_ada.gpr crates/protobuf_ada/protobuf_ada.gpr
COPY crates/protobuf_ada_tests/alire.toml crates/protobuf_ada_tests/alire.toml
COPY crates/protobuf_ada_tests/protobuf_ada_tests.gpr crates/protobuf_ada_tests/protobuf_ada_tests.gpr
COPY crates/protoc_gen_grpc_ada/alire.toml crates/protoc_gen_grpc_ada/alire.toml
COPY crates/protoc_gen_grpc_ada/protoc_gen_grpc_ada.gpr crates/protoc_gen_grpc_ada/protoc_gen_grpc_ada.gpr
#  grpc_ada (v0.1 gRPC) pins vendor/aws — that fork is gitignored
#  + .dockerignored, so we drop the whole v0.1 stack from the
#  CI image.  The v0.2+ stack lives in grpc_core / http2_core,
#  which doesn't need vendor/aws.
COPY crates/http1_core/alire.toml         crates/http1_core/alire.toml
COPY crates/http1_core/http1_core.gpr     crates/http1_core/http1_core.gpr
COPY crates/http2_core/alire.toml         crates/http2_core/alire.toml
COPY crates/http2_core/http2_core.gpr     crates/http2_core/http2_core.gpr
COPY crates/http2_core_tests/alire.toml   crates/http2_core_tests/alire.toml
COPY crates/http2_core_tests/http2_core_tests.gpr crates/http2_core_tests/http2_core_tests.gpr
COPY crates/grpc_core/alire.toml          crates/grpc_core/alire.toml
COPY crates/grpc_core/grpc_core.gpr       crates/grpc_core/grpc_core.gpr
COPY crates/grpc_core_tests/alire.toml    crates/grpc_core_tests/alire.toml
COPY crates/grpc_core_tests/grpc_core_tests.gpr crates/grpc_core_tests/grpc_core_tests.gpr
COPY crates/mqtt_core/alire.toml          crates/mqtt_core/alire.toml
COPY crates/mqtt_core/mqtt_core.gpr       crates/mqtt_core/mqtt_core.gpr
COPY crates/tls_core/alire.toml           crates/tls_core/alire.toml
COPY crates/tls_core/tls_core.gpr         crates/tls_core/tls_core.gpr
COPY crates/tls_transport/alire.toml      crates/tls_transport/alire.toml
COPY crates/tls_transport/tls_transport.gpr crates/tls_transport/tls_transport.gpr
COPY crates/tls_interop/alire.toml        crates/tls_interop/alire.toml
COPY crates/tls_interop/tls_interop.gpr   crates/tls_interop/tls_interop.gpr
COPY crates/tls_cli/alire.toml            crates/tls_cli/alire.toml
COPY crates/tls_cli/tls_cli.gpr           crates/tls_cli/tls_cli.gpr
#  examples crate depends on grpc_ada → AWS → dropped, as above.
#  The tls_cli binary the interop matrix needs is built from the
#  standalone tls_cli crate above, which `with`s tls_core only.

# Resolve + fetch dep crates.  Cache mounts make this a no-op on
# warm builds.  We touch only the crates that pull external deps;
# the rest just `with` their siblings.
RUN --mount=type=cache,target=/root/.cache/alire,sharing=locked \
    --mount=type=cache,target=/root/.local/share/alire/builds,sharing=locked \
    for c in tls_core tls_interop tls_cli protoc_gen_grpc_ada \
             mqtt_core http2_core http1_core grpc_core \
             rflx_runtime protobuf_core protobuf_ada \
             protobuf_ada_tests http2_core_tests grpc_core_tests \
             tls_transport; do \
        if [ -f "crates/$c/alire.toml" ]; then \
            echo "==> alr update $c"; \
            ( cd crates/$c && alr -n update ) || exit 1; \
        fi; \
    done

# ──────────────────────────────────────────────────────────────
# Stage 3 — build: copy source + compile the binaries
# ──────────────────────────────────────────────────────────────
FROM deps AS build
WORKDIR /work

# Now the full source.  Anything in .dockerignore is excluded,
# so this is the SPARK code + scripts + Makefile + fixtures.
COPY . .

# gnatprove on PATH from base stage; let the Makefile pick it up.
ENV GNATPROVE=gnatprove

# Build the v0.5+ crates we care about for the CI image:
#   * tls_core / tls_transport / tls_interop  — interop matrix harness
#   * tls_core/tests                          — tls unit-test binary
#   * http2_core (+ tests if present)         — HTTP/2 unit tests
#   * mqtt_core (+ tests if present)          — MQTT unit tests
#   * grpc_core (+ tests if present)          — gRPC framing
#
# Cache mounts on /root/.cache/alire and /root/.local/share/alire/builds
# turn this into a near-incremental compile on second build — the cold
# dep tree (gnatcoll etc.) is reused from the cache rather than rebuilt.
#
# We do NOT run `make build` (which would pull in grpc_ada → AWS) or
# `make examples-build` (same reason).  The v0.1 stack is out of scope
# for this CI image.
#  We don't invoke `make tls-interop-build` because its examples
#  build step pulls in the v0.1 grpc_ada → AWS dependency.  We
#  call its other components directly: tls_core, the Go peer
#  helpers, and the tls_interop matrix harness itself.
RUN --mount=type=cache,target=/root/.cache/alire,sharing=locked \
    --mount=type=cache,target=/root/.local/share/alire/builds,sharing=locked \
    set -eux \
 && make tls-build \
 && make tls-interop-go-helpers \
 && alr -C crates/tls_interop build \
 && alr -C crates/tls_cli build \
 && make mqtt-build \
 && make http2-build \
 && alr -C crates/tls_core/tests build \
 && for c in http2_core_tests mqtt_core_tests grpc_core_tests; do \
        if [ -d crates/$c ] && [ -f crates/$c/alire.toml ]; then \
            alr -C crates/$c build; \
        fi; \
    done

# Quick smoke — fail fast if a key binary didn't land.
RUN test -x crates/tls_core/tests/bin/tls_core_tests \
 && test -x crates/tls_interop/bin/tls_interop \
 && test -x crates/tls_cli/bin/tls_cli \
 && echo "build OK"

# ──────────────────────────────────────────────────────────────
# Stage 4 — runtime: the shippable image
# ──────────────────────────────────────────────────────────────
#
# Same toolchain image (so `make prove` and re-builds work
# inside a `docker run`) plus the compiled artifacts copied
# in from `build`.  We do NOT strip the build context — the
# repo is mounted-equivalent, so the Makefile targets work
# unchanged.
FROM build AS runtime

LABEL org.opencontainers.image.source="https://github.com/mathissprlch/transports-spark" \
      org.opencontainers.image.title="transports-spark CI image" \
      org.opencontainers.image.description="SPARK-verified TLS 1.3 + HTTP/2 + MQTT + gRPC stack, with the unit tests + interop matrix + gnatprove pre-installed." \
      org.opencontainers.image.licenses="MIT OR Apache-2.0 WITH LLVM-exception"

WORKDIR /work
ENV GNATPROVE=gnatprove

# Default: print the available targets and stop.  Specific
# subcommands are invoked via `docker run img <make-target>`.
CMD ["make", "help"]
