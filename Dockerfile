# LatchGate — unified multi-stage build.
#
# ── Stages ────────────────────────────────────────────────────────────────────
#
#   builder        Rust 1.93 Alpine. Produces static musl binary, WASM
#                  provider modules, and verifies manifest digests.
#   runtime-base   Alpine 3.20. Shared runtime environment (uid/gid 10001,
#                  ca-certificates, healthcheck, entrypoint, labels).
#   local-release  Copies pre-built artifacts from the host. Used by
#                  `make release-docker` after `make release-build`.
#   ci-release     Copies artifacts from the builder stage. Default target —
#                  used by `docker build .`, CI, and compose quickstart.
#
# Multi-arch: supports linux/amd64 and linux/arm64 via BuildKit TARGETARCH.
# Requires BuildKit (Docker 23+).

# ── Builder ──────────────────────────────────────────────────────────────────

FROM rust:1.93-alpine@sha256:4fec02de605563c297c78a31064c8335bc004fa2b0bf406b1b99441da64e2d2d AS builder

# TARGETARCH is set automatically by BuildKit (amd64, arm64).
ARG TARGETARCH

RUN apk add --no-cache musl-dev build-base

# Map Docker TARGETARCH to Rust target triple.
RUN set -e; \
    case "${TARGETARCH}" in \
      amd64) RUST_TARGET=x86_64-unknown-linux-musl ;; \
      arm64) RUST_TARGET=aarch64-unknown-linux-musl ;; \
      *)     echo "Unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    echo "${RUST_TARGET}" > /rust-target; \
    rustup target add "${RUST_TARGET}" wasm32-wasip2

WORKDIR /build

# ── Dependency cache layer ──────────────────────────────────────────────
COPY Cargo.toml Cargo.lock ./

COPY crates/latchgate-api/Cargo.toml          crates/latchgate-api/Cargo.toml
COPY crates/latchgate-auth/Cargo.toml         crates/latchgate-auth/Cargo.toml
COPY crates/latchgate-bin/Cargo.toml          crates/latchgate-bin/Cargo.toml
COPY crates/latchgate-cli/Cargo.toml          crates/latchgate-cli/Cargo.toml
COPY crates/latchgate-client/Cargo.toml       crates/latchgate-client/Cargo.toml
COPY crates/latchgate-config/Cargo.toml       crates/latchgate-config/Cargo.toml
COPY crates/latchgate-core/Cargo.toml         crates/latchgate-core/Cargo.toml
COPY crates/latchgate-crypto/Cargo.toml       crates/latchgate-crypto/Cargo.toml
COPY crates/latchgate-embed/Cargo.toml        crates/latchgate-embed/Cargo.toml
COPY crates/latchgate-kernel/Cargo.toml       crates/latchgate-kernel/Cargo.toml
COPY crates/latchgate-ledger/Cargo.toml       crates/latchgate-ledger/Cargo.toml
COPY crates/latchgate-mcp/Cargo.toml          crates/latchgate-mcp/Cargo.toml
COPY crates/latchgate-policy/Cargo.toml       crates/latchgate-policy/Cargo.toml
COPY crates/latchgate-providers/Cargo.toml    crates/latchgate-providers/Cargo.toml
COPY crates/latchgate-registry/Cargo.toml     crates/latchgate-registry/Cargo.toml
COPY crates/latchgate-sandbox/Cargo.toml      crates/latchgate-sandbox/Cargo.toml
COPY crates/latchgate-state/Cargo.toml        crates/latchgate-state/Cargo.toml
COPY crates/latchgate-tui/Cargo.toml          crates/latchgate-tui/Cargo.toml
COPY crates/latchgate-webhooks/Cargo.toml     crates/latchgate-webhooks/Cargo.toml

COPY tests/Cargo.toml                         tests/Cargo.toml
COPY tests/stress/Cargo.toml                  tests/stress/Cargo.toml

COPY providers/Cargo.toml providers/Cargo.lock providers/
COPY providers/http_api/Cargo.toml            providers/http_api/Cargo.toml
COPY providers/fs/Cargo.toml                  providers/fs/Cargo.toml

RUN find crates -name Cargo.toml -exec sh -c \
        'dir="$(dirname "$1")/src"; mkdir -p "$dir"; \
         echo "" > "$dir/lib.rs"; \
         grep -q "src/main.rs" "$1" && echo "fn main(){}" > "$dir/main.rs"; \
         true' _ {} \; && \
    find providers -name Cargo.toml ! -path providers/Cargo.toml -exec sh -c \
        'mkdir -p "$(dirname "$1")/src" && echo "" > "$(dirname "$1")/src/lib.rs"' _ {} \; && \
    mkdir -p tests/integration tests/standalone \
             tests/stress/src tests/stress/benches && \
    echo "fn main(){}" > tests/integration/main.rs && \
    echo "fn main(){}" > tests/standalone/main.rs && \
    echo "" > tests/stress/src/lib.rs && \
    echo "fn main(){}" > tests/stress/benches/hot_paths.rs

RUN RUST_TARGET=$(cat /rust-target) && \
    cargo fetch --locked --target "${RUST_TARGET}" && \
    cargo fetch --locked --manifest-path providers/Cargo.toml --target wasm32-wasip2

# ── Full source ─────────────────────────────────────────────────────────
COPY . .

# Static musl binary. --frozen: no network, no lockfile updates.
RUN RUST_TARGET=$(cat /rust-target) && \
    CARGO_BUILD_TARGET="${RUST_TARGET}" \
    RUSTFLAGS="-C target-feature=+crt-static" \
    cargo build --locked --frozen --release -p latchgate-bin

# WASM providers. RUSTFLAGS remap paths so the output is byte-identical
# regardless of host workspace path or CARGO_HOME location. Same source +
# same toolchain -> same SHA-256 everywhere. `--workspace` builds every
# provider in providers/Cargo.toml (http_api, fs, ...) so the image ships
# the same module set as the release tarball — no capability drift.
RUN mkdir -p target/providers && \
    RUSTFLAGS="--remap-path-prefix=/usr/local/cargo=/cargo --remap-path-prefix=/build=/build" \
    cargo build --locked --frozen --manifest-path providers/Cargo.toml \
        --workspace --target wasm32-wasip2 --release && \
    for src in providers/target/wasm32-wasip2/release/latchgate_provider_*.wasm; do \
        [ -f "$src" ] || continue; \
        name=$(basename "$src" | sed "s/^latchgate_provider_//"); \
        cp "$src" "target/providers/$name"; \
    done && \
    test -n "$(ls -A target/providers/*.wasm 2>/dev/null)" || \
        { echo "ERROR: no provider modules built" >&2; exit 1; }

# Verify freshly compiled providers against committed manifest digests.
# Uses the in-tree Python verifier (same as the release workflow) — no extra
# Rust compilation, and builtin: providers are skipped automatically.
# Any digest mismatch fails the build.
RUN apk add --no-cache python3 py3-yaml && \
    python3 deploy/verify-manifest-digests.py \
        --manifests-dir definitions/manifests --providers-dir target/providers

# Copy the final binary to a well-known path for ci-release.
# This avoids shell expansion in COPY --from which Docker does not support.
RUN cp "target/$(cat /rust-target)/release/latchgate" /latchgate-bin

# ── Runtime base ─────────────────────────────────────────────────────────────

FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b AS runtime-base

ARG VERSION=dev

LABEL org.opencontainers.image.source="https://github.com/latchgate-ai/latchgate" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.description="LatchGate execution security kernel" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apk add --no-cache ca-certificates netcat-openbsd && \
    addgroup -S -g 10001 latchgate && \
    adduser  -S -u 10001 -G latchgate -H -D latchgate && \
    mkdir -p /var/lib/latchgate /run/latchgate && \
    chown -R latchgate:latchgate /var/lib/latchgate /run/latchgate

USER latchgate

EXPOSE 3000

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD ["sh", "-c", "printf 'GET /healthz HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n' | nc -U /run/latchgate/gate.sock | head -1 | grep -q '200 OK'"]

ENTRYPOINT ["latchgate"]
CMD ["serve"]

# ── Local release ────────────────────────────────────────────────────────────
# Used by `make release-docker` after building on the host.
# Pass --build-arg RUST_TARGET=<triple> to match the host toolchain target.

FROM runtime-base AS local-release

ARG RUST_TARGET=x86_64-unknown-linux-musl

COPY --chmod=0555 target/${RUST_TARGET}/release/latchgate /usr/local/bin/latchgate
COPY target/providers/  /opt/latchgate/providers/
COPY definitions/manifests/    /opt/latchgate/definitions/manifests/
COPY definitions/policies/     /opt/latchgate/policies/

# ── CI release (default target) ──────────────────────────────────────────────

FROM runtime-base AS ci-release

COPY --chmod=0555 --from=builder /latchgate-bin /usr/local/bin/latchgate
COPY --from=builder /build/target/providers/  /opt/latchgate/providers/
COPY --from=builder /build/definitions/manifests/    /opt/latchgate/definitions/manifests/
COPY --from=builder /build/definitions/policies/     /opt/latchgate/policies/
