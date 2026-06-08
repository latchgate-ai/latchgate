#!/usr/bin/env bash
# deploy/audit-freshness.sh — reject crates published <7 days ago.
# Mirrors the CI freshness gate so violations are caught locally.
# Optimisation: only queries crates whose version changed vs HEAD.
set -euo pipefail

MIN_AGE_DAYS="${MIN_AGE_DAYS:-7}"
NOW=$(date +%s)
FAILED=0

echo "── Cargo dependency freshness check (min age: ${MIN_AGE_DAYS}d) ─────────────"

# Extract name=version pairs from a Cargo.lock file.
_lock_pairs() {
    awk '/^name = /{name=$3} /^version = /{print name "=" $3}' "$1" \
        | tr -d '"' | sort -u
}

# Build the set of crates to check: only those added or version-bumped.
CURRENT=$(_lock_pairs Cargo.lock)

if git rev-parse HEAD -- >/dev/null 2>&1 && git show HEAD:Cargo.lock >/dev/null 2>&1; then
    BASELINE=$(git show HEAD:Cargo.lock | _lock_pairs /dev/stdin)
    CANDIDATES=$(comm -23 <(echo "$CURRENT") <(echo "$BASELINE"))
else
    # No git baseline — check everything (first run / CI).
    CANDIDATES="$CURRENT"
fi

TOTAL=$(echo "$CANDIDATES" | grep -c . || true)
if [ "$TOTAL" -eq 0 ]; then
    echo "  No new or bumped crates — nothing to check ✓"
    exit 0
fi
echo "  Checking $TOTAL changed crate(s)..."

while IFS='=' read -r name version; do
    [ -z "$name" ] && continue

    # Skip workspace (path/git) crates.
    SOURCE=$(awk -v n="$name" -v v="$version" '
        /^\[\[package\]\]/ { n_ok=0; v_ok=0 }
        $0 ~ "^name = \"" n "\"" { n_ok=1 }
        $0 ~ "^version = \"" v "\"" { v_ok=1 }
        /^source = / { if (n_ok && v_ok) print }
    ' Cargo.lock 2>/dev/null || true)
    case "$SOURCE" in
        *\"path+*|*\"git+*|"") continue ;;
    esac

    # Query crates.io.
    _tmp=$(mktemp)
    if ! curl -sf "https://crates.io/api/v1/crates/${name}/${version}" \
         -H "User-Agent: latchgate-audit (supply-chain-check)" \
         -o "$_tmp" 2>/dev/null; then
        rm -f "$_tmp"
        continue
    fi

    PUBLISHED=$(python3 -c "import json,sys; print(json.load(open('$_tmp'))['version']['created_at'])" 2>/dev/null) || { rm -f "$_tmp"; continue; }
    rm -f "$_tmp"

    PUB_EPOCH=$(date -d "$PUBLISHED" +%s 2>/dev/null) || continue
    AGE_DAYS=$(( (NOW - PUB_EPOCH) / 86400 ))

    if [ "$AGE_DAYS" -lt "$MIN_AGE_DAYS" ]; then
        echo "Error: ${name}@${version} published ${AGE_DAYS}d ago (minimum: ${MIN_AGE_DAYS}d)"
        FAILED=1
    fi
done <<< "$CANDIDATES"

if [ "$FAILED" -ne 0 ]; then
    echo ""
    echo "Crate(s) above were published less than ${MIN_AGE_DAYS} days ago."
    echo "Fix: cargo update <crate>@<new-ver> --precise <older-ver>"
    exit 1
fi

echo "  All changed crates are ≥${MIN_AGE_DAYS}d old ✓"
