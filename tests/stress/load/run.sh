#!/usr/bin/env bash
# LatchGate hot-path load test — manual operator tool, NOT wired to CI.
#
# Prerequisites:
#   - vegeta (https://github.com/tsenart/vegeta)
#   - latchgate running in embedded mode: `latchgate up`
#   - A valid lease JWT (see below)
#
# Success criteria (developer laptop, embedded mode):
#   p99 < 200 ms at 50 rps sustained for 30 s
#
# Usage:
#   export LATCHGATE_LEASE_JWT="<jwt>"
#   export LATCHGATE_DPoP_PROOF="<proof>"
#   ./run.sh [rps] [duration]
#
# Arguments:
#   rps       Requests per second (default: 50)
#   duration  Test duration (default: 30s)
set -euo pipefail

RPS="${1:-50}"
DURATION="${2:-30s}"
BASE_URL="${LATCHGATE_BASE_URL:-http://localhost:3000}"
ACTION_ID="${LATCHGATE_ACTION_ID:-http_get}"

RED='\033[0;31m'
GREEN='\033[0;32m'
BOLD='\033[1m'
RESET='\033[0m'

info()  { printf "${BOLD}%s${RESET}\n" "$*"; }
ok()    { printf "  ${GREEN}✓${RESET} %s\n" "$*"; }
fail()  { printf "  ${RED}✗ %s${RESET}\n" "$*" >&2; }

# ── Preflight ──────────────────────────────────────────────────────────────

command -v vegeta >/dev/null 2>&1 \
    || { fail "vegeta not found. Install: go install github.com/tsenart/vegeta@latest"; exit 1; }

if [ -z "${LATCHGATE_LEASE_JWT:-}" ]; then
    fail "LATCHGATE_LEASE_JWT not set."
    echo ""
    echo "  Obtain a lease:"
    echo "    curl -s ${BASE_URL}/v1/leases -d '{\"dpop_jwk\": ..., \"scopes\": [\"tools:call\"]}'"
    echo ""
    exit 1
fi

info ""
info "  LatchGate Load Test"
info ""
info "  Target:   ${BASE_URL}/v1/actions/${ACTION_ID}/execute"
info "  Rate:     ${RPS} rps"
info "  Duration: ${DURATION}"
info ""

# ── Target definition ─────────────────────────────────────────────────────

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

BODY='{"url":"https://httpbin.org/get"}'

cat > "${TMPDIR}/targets.txt" <<EOF
POST ${BASE_URL}/v1/actions/${ACTION_ID}/execute
Content-Type: application/json
Authorization: DPoP ${LATCHGATE_LEASE_JWT}
@${TMPDIR}/body.json
EOF

echo "${BODY}" > "${TMPDIR}/body.json"

# ── Attack ────────────────────────────────────────────────────────────────

info "  Running..."
echo ""

vegeta attack \
    -targets="${TMPDIR}/targets.txt" \
    -rate="${RPS}/1s" \
    -duration="${DURATION}" \
    -timeout=5s \
    | tee "${TMPDIR}/results.bin" \
    | vegeta report

echo ""

# ── Evaluation ────────────────────────────────────────────────────────────

P99=$(vegeta report -type=text "${TMPDIR}/results.bin" \
    | grep "99th" \
    | awk '{print $NF}' \
    | sed 's/ms//' \
    | head -1)

if [ -n "$P99" ]; then
    P99_INT="${P99%%.*}"
    if [ "${P99_INT:-999}" -lt 200 ]; then
        ok "p99 = ${P99}ms (< 200ms target)"
    else
        fail "p99 = ${P99}ms (>= 200ms target)"
    fi
fi

# ── Save report ───────────────────────────────────────────────────────────

REPORT_DIR="$(dirname "$0")/reports"
mkdir -p "$REPORT_DIR"
TIMESTAMP="$(date -u +%Y%m%d-%H%M%S)"
REPORT_FILE="${REPORT_DIR}/${TIMESTAMP}-${RPS}rps.txt"
vegeta report -type=text "${TMPDIR}/results.bin" > "$REPORT_FILE"
ok "Report saved: ${REPORT_FILE}"
echo ""
