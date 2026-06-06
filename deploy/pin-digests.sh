#!/usr/bin/env bash
# LatchGate — pin all base image digests for supply chain security.
set -euo pipefail
#
# Usage:  make pin-digests
#    or:  ./deploy/pin-digests.sh
#
# WHEN TO USE:
#   - Initial setup (before Dependabot has opened its first PR)
#   - After manually changing a base image tag
#   - CI verification that digests are pinned (grep for @sha256:)
#
# ONGOING UPDATES:
#   Dependabot handles this automatically via .github/dependabot.yml
#   (docker + docker-compose ecosystems). It opens PRs when upstream
#   publishes new digests (security patches, rebuilds).
#
# Requires: docker (with BuildKit), jq, sed


RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

die() { printf "${RED}error:${NC} %s\n" "$1" >&2; exit 1; }
ok()  { printf "${GREEN}  ✓${NC} %s\n" "$1"; }

command -v docker >/dev/null 2>&1 || die "docker is required"
command -v jq     >/dev/null 2>&1 || die "jq is required"
command -v sed    >/dev/null 2>&1 || die "sed is required"

# Resolve manifest list digest for a given image:tag.
get_digest() {
    local image="$1"
    docker buildx imagetools inspect "$image" --format '{{json .}}' 2>/dev/null \
        | jq -r '.manifest.digest' 2>/dev/null \
        || docker manifest inspect "$image" 2>/dev/null \
            | jq -r '.digest // (.manifests[0].digest)' 2>/dev/null \
        || die "cannot resolve digest for $image"
}

pin() {
    local file="$1" old_pattern="$2" tag="$3" digest="$4"
    local pinned="${tag}@${digest}"

    if [ -z "$digest" ] || [ "$digest" = "null" ]; then
        printf "  ✗ skipped %s (digest lookup failed)\n" "$tag"
        return
    fi

    sed -i "s|${old_pattern}|${pinned}|g" "$file"
    ok "$tag -> ${digest:0:19}... ($file)"
}

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

echo ""
echo "  LatchGate — pinning base image digests"
echo ""

# ── Collect current digests ─────────────────────────────────────────────

ALPINE_DIGEST=$(get_digest "alpine:3.20")
ALPINE_SQUID_DIGEST=$(get_digest "alpine:3.23")
RUST_DIGEST=$(get_digest "rust:1.93-alpine")
RUST_SLIM_DIGEST=$(get_digest "rust:1.93-slim")
REDIS_DIGEST=$(get_digest "redis:7-alpine")
OPA_DIGEST=$(get_digest "openpolicyagent/opa:1.16.1")
PROM_DIGEST=$(get_digest "prom/prometheus:v2.54.1")

echo ""
echo "  Resolved digests:"
echo "    alpine:3.20                  ${ALPINE_DIGEST:0:19}..."
echo "    alpine:3.23 (squid)          ${ALPINE_SQUID_DIGEST:0:19}..."
echo "    rust:1.93-alpine             ${RUST_DIGEST:0:19}..."
echo "    rust:1.93-slim               ${RUST_SLIM_DIGEST:0:19}..."
echo "    redis:7-alpine               ${REDIS_DIGEST:0:19}..."
echo "    openpolicyagent/opa:1.16.1   ${OPA_DIGEST:0:19}..."
echo "    prom/prometheus:v2.54.1      ${PROM_DIGEST:0:19}..."
echo ""

# ── Pin Dockerfile (builder stage + runtime-base stage) ─────────────────

pin Dockerfile \
    "rust:1.93-alpine\(@sha256:[a-f0-9]*\)\?" \
    "rust:1.93-alpine" "$RUST_DIGEST"

sed -i "s|FROM alpine:3\.20\(@sha256:[a-f0-9]*\)\?|FROM alpine:3.20@${ALPINE_DIGEST}|g" Dockerfile
ok "alpine:3.20 -> ${ALPINE_DIGEST:0:19}... (Dockerfile)"

# deploy/squid/Dockerfile
sed -i "s|FROM alpine:3\.23\(@sha256:[a-f0-9]*\)\?|FROM alpine:3.23@${ALPINE_SQUID_DIGEST}|g" \
    deploy/squid/Dockerfile
ok "alpine:3.23 -> ${ALPINE_SQUID_DIGEST:0:19}... (deploy/squid/Dockerfile)"

# ── Pin docker-compose.yml ──────────────────────────────────────────────

sed -i "s|image: redis:7-alpine\(@sha256:[a-f0-9]*\)\?|image: redis:7-alpine@${REDIS_DIGEST}|g" \
    docker-compose.yml
ok "redis:7-alpine -> ${REDIS_DIGEST:0:19}... (docker-compose.yml)"

sed -i "s|image: openpolicyagent/opa:1\.16\.1\(@sha256:[a-f0-9]*\)\?|image: openpolicyagent/opa:1.16.1@${OPA_DIGEST}|g" \
    docker-compose.yml
ok "opa:1.16.1 -> ${OPA_DIGEST:0:19}... (docker-compose.yml)"

sed -i "s|image: prom/prometheus:v2\.54\.1\(@sha256:[a-f0-9]*\)\?|image: prom/prometheus:v2.54.1@${PROM_DIGEST}|g" \
    docker-compose.yml
ok "prometheus:v2.54.1 -> ${PROM_DIGEST:0:19}... (docker-compose.yml)"

# ── Pin Makefile (REHASH_IMAGE for containerised provider builds) ───────

sed -i "s|REHASH_IMAGE\s*:=\s*rust:1\.93-slim\(@sha256:[a-f0-9]*\)\?|REHASH_IMAGE      := rust:1.93-slim@${RUST_SLIM_DIGEST}|g" \
    Makefile
ok "rust:1.93-slim -> ${RUST_SLIM_DIGEST:0:19}... (Makefile)"

# ── Pin release.yml (PROVIDER_BUILD_IMAGE for CI provider builds) ───────

sed -i "s|PROVIDER_BUILD_IMAGE:.*\"rust:1\.93-slim\(@sha256:[a-f0-9]*\)\?\"|PROVIDER_BUILD_IMAGE: \"rust:1.93-slim@${RUST_SLIM_DIGEST}\"|g" \
    .github/workflows/release.yml
ok "rust:1.93-slim -> ${RUST_SLIM_DIGEST:0:19}... (.github/workflows/release.yml)"

echo ""
echo "  Done. All base images pinned to immutable digests."
echo "  Re-run after updating image tags to refresh digests."
echo ""
