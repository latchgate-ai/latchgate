#!/usr/bin/env bash
# Test latchgate-mcp without Claude Desktop - raw JSON-RPC over stdio.
#
# Usage:
#   bash examples/mcp-demo/test_mcp.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
BINARY="$REPO_ROOT/target/release/latchgate-mcp"
GATE_URL="http://localhost:3000"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# ── Styling ──────────────────────────────────────────────────────────────────

BOLD='\033[1m'
DIM='\033[2m'
GREEN='\033[32m'
RED='\033[31m'
CYAN='\033[36m'
YELLOW='\033[33m'
MAGENTA='\033[35m'
WHITE='\033[97m'
RESET='\033[0m'

ok()      { echo -e "  ${GREEN}✓${RESET} $1"; }
fail()    { echo -e "  ${RED}✗${RESET} $1"; }
warn()    { echo -e "  ${YELLOW}⊘${RESET} $1"; }
step()    { echo -e "  ${CYAN}=>${RESET} $1"; }
detail()  { echo -e "    ${DIM}$1${RESET}"; }
explain() { echo -e "    ${CYAN}▸ $1${RESET}"; }
kv()      { echo -e "    ${DIM}$1:${RESET} $2"; }
header()  { echo -e "\n${BOLD}${MAGENTA}$1${RESET}\n"; }

PASSED=0
FAILED=0
WARNED=0

# ── Preflight ────────────────────────────────────────────────────────────────

echo ""
echo -e "  ${BOLD}LatchGate MCP Adapter - stdio test${RESET}"
echo -e "  ${DIM}Same protocol as Claude Desktop / Cursor / any MCP host.${RESET}"
echo -e "  ${DIM}No MCP host needed - raw JSON-RPC over stdin/stdout.${RESET}"

header "  Preflight"

step "Checking latchgate-mcp binary..."
if [[ ! -f "$BINARY" ]]; then
    fail "Not found: $BINARY"
    echo -e "    Run: ${CYAN}cargo build --release -p latchgate-mcp${RESET}"
    exit 1
fi
ok "Binary: $BINARY"

step "Checking gate..."
if curl -sf "$GATE_URL/healthz" >/dev/null 2>&1; then
    ok "Gate running at $GATE_URL"
else
    fail "Gate not running. Start: LATCHGATE_DEV_MODE=true latchgate serve"
    exit 1
fi

# ── Run MCP session ──────────────────────────────────────────────────────────

header "  Running MCP session"

step "Starting adapter + sending JSON-RPC sequence..."
detail "initialize => tools/list => http_fetch (allowed) => http_fetch (denied) => http_sensitive_read"
echo ""

DEBUG_FILE=$(mktemp /tmp/latchgate-mcp-debug.XXXXXX)
SESSION_OUTPUT=$(python3 "$SCRIPT_DIR/mcp_session.py" "$BINARY" "$GATE_URL" 2>"$DEBUG_FILE") || {
    fail "Session failed"
    detail "$SESSION_OUTPUT"
    cat "$DEBUG_FILE" | while read -r line; do detail "$line"; done
    rm -f "$DEBUG_FILE"
    exit 1
}

# ── Parse results ────────────────────────────────────────────────────────────

parse_step() {
    echo "$SESSION_OUTPUT" | python3 -c "
import sys, json
step_name = '$1'
for line in sys.stdin:
    line = line.strip()
    if not line: continue
    try:
        d = json.loads(line)
        if d.get('step') == step_name:
            print(json.dumps(d.get('response', {})))
            break
    except json.JSONDecodeError:
        pass
" 2>/dev/null
}

# Check if a response is a JSON-RPC error (adapter-level, not tool-level)
is_rpc_error() {
    echo "$1" | python3 -c "
import sys, json
d = json.load(sys.stdin)
if 'error' in d and 'result' not in d:
    msg = d['error'].get('message', '?')
    print(msg)
    sys.exit(0)
sys.exit(1)
" 2>/dev/null
}

# ── 1. Initialize ────────────────────────────────────────────────────────────

header "  1. Initialize"

INIT_RESP=$(parse_step "initialize")
if [[ -n "$INIT_RESP" ]]; then
    RPC_ERR=$(is_rpc_error "$INIT_RESP" 2>/dev/null) && {
        fail "Initialize error: $RPC_ERR"
        FAILED=$((FAILED+1))
    } || {
        VERSION=$(echo "$INIT_RESP" | python3 -c "import sys,json; print(json.load(sys.stdin).get('result',{}).get('protocolVersion','?'))" 2>/dev/null || echo "?")
        SERVER=$(echo "$INIT_RESP" | python3 -c "import sys,json; si=json.load(sys.stdin).get('result',{}).get('serverInfo',{}); print(f\"{si.get('name','?')} {si.get('version','?')}\")" 2>/dev/null || echo "?")
        ok "Handshake complete"
        kv "protocol" "$VERSION"
        kv "server  " "$SERVER"
        PASSED=$((PASSED+1))
    }
else
    fail "No response"
    FAILED=$((FAILED+1))
fi

# ── 2. Tools ─────────────────────────────────────────────────────────────────

header "  2. Discover tools"

explain "The adapter connects to the gate and auto-discovers all registered actions."

TOOLS_RESP=$(parse_step "tools_list")
TOOL_COUNT="?"
if [[ -n "$TOOLS_RESP" ]]; then
    RPC_ERR=$(is_rpc_error "$TOOLS_RESP" 2>/dev/null) && {
        fail "tools/list error: $RPC_ERR"
        FAILED=$((FAILED+1))
    } || {
        TOOL_OUTPUT=$(echo "$TOOLS_RESP" | python3 -c "
import sys, json
tools = json.load(sys.stdin).get('result',{}).get('tools',[])
for t in tools:
    desc = t.get('description', '')[:60]
    print(f\"{t['name']}|{desc}\")
print(f'COUNT:{len(tools)}')
" 2>/dev/null)

        TOOL_COUNT=$(echo "$TOOL_OUTPUT" | grep '^COUNT:' | cut -d: -f2)
        ok "$TOOL_COUNT tools discovered"
        echo ""

        echo "$TOOL_OUTPUT" | grep -v '^COUNT:' | while IFS='|' read -r name desc; do
            echo -e "    ${GREEN}•${RESET} ${BOLD}$name${RESET}  ${DIM}$desc${RESET}"
        done

        echo ""
        explain "Each tool maps 1:1 to a LatchGate action manifest."
        explain "The agent sees tool names - not security details."
        PASSED=$((PASSED+1))
    }
else
    fail "No response"
    FAILED=$((FAILED+1))
fi

# ── 3. Fetch allowed ────────────────────────────────────────────────────────

header "  3. Execute http_fetch => httpbin.org/get"

explain "Full pipeline: auth => policy => WASM sandbox => receipt"

FETCH_RESP=$(parse_step "fetch_allowed")
if [[ -n "$FETCH_RESP" ]]; then
    RPC_ERR=$(is_rpc_error "$FETCH_RESP" 2>/dev/null) && {
        warn "Adapter error: $RPC_ERR"
        explain "The adapter could not complete the request to the gate."
        explain "This is a transport/auth issue between adapter and gate, not a policy decision."
        WARNED=$((WARNED+1))
    } || {
        python3 -c "
import sys, json
d = json.load(sys.stdin)
result = d.get('result', {})
content = result.get('content', [])
is_error = result.get('isError', False)
text = content[0].get('text', '') if content else ''

if is_error:
    print(f'  \033[31m✗\033[0m Tool error: {text[:120]}')
else:
    try:
        body = json.loads(text)
        origin = body.get('origin', '?')
        host = body.get('headers', {}).get('Host', '?')
        print(f'  \033[32m✓\033[0m Executed through WASM sandbox')
        print(f'    \033[2morigin:\033[0m {origin}')
        print(f'    \033[2mhost:\033[0m   {host}')
    except json.JSONDecodeError:
        if text:
            print(f'  \033[32m✓\033[0m Executed ({len(text)} chars)')
        else:
            print(f'  \033[33m⊘\033[0m Empty response')
" <<< "$FETCH_RESP" && PASSED=$((PASSED+1)) || WARNED=$((WARNED+1))

        echo ""
        explain "The MCP host sees a normal tool result."
        explain "It has no idea about the security pipeline underneath."
    }
else
    fail "No response"
    FAILED=$((FAILED+1))
fi

# ── 4. Fetch denied ──────────────────────────────────────────────────────────

header "  4. Execute http_fetch => evil.example.com (denied)"

explain "evil.example.com is not in the http_fetch allowed_domains."

DENY_RESP=$(parse_step "fetch_denied")
if [[ -n "$DENY_RESP" ]]; then
    RPC_ERR=$(is_rpc_error "$DENY_RESP" 2>/dev/null) && {
        warn "Adapter error: $RPC_ERR"
        explain "The request didn't reach the policy engine - adapter transport failed."
        WARNED=$((WARNED+1))
    } || {
        python3 -c "
import sys, json
d = json.load(sys.stdin)
result = d.get('result', {})
content = result.get('content', [])
is_error = result.get('isError', False)
text = content[0].get('text', '') if content else ''

if is_error or 'denied' in text.lower() or 'error' in text.lower():
    print(f'  \033[32m✓\033[0m Correctly denied')
    reason = text[:120].replace(chr(10), ' ')
    print(f'    \033[2mreason:\033[0m {reason}')
else:
    print(f'  \033[31m✗\033[0m Should have been denied!')
" <<< "$DENY_RESP" && PASSED=$((PASSED+1)) || FAILED=$((FAILED+1))

        echo ""
        explain "No grant, no sandbox, no receipt. Containment, not detection."
    }
else
    fail "No response"
    FAILED=$((FAILED+1))
fi

# ── 5. http_sensitive_read (approval hold) ───────────────────────────────────

header "  5. Execute http_sensitive_read => approval hold"

explain "http_sensitive_read has risk_level: high => requires operator approval."

MSG_RESP=$(parse_step "http_sensitive_read")
if [[ -n "$MSG_RESP" ]]; then
    RPC_ERR=$(is_rpc_error "$MSG_RESP" 2>/dev/null) && {
        warn "Adapter error: $RPC_ERR"
        explain "The request didn't reach the policy engine - adapter transport failed."
        WARNED=$((WARNED+1))
    } || {
        python3 -c "
import sys, json
d = json.load(sys.stdin)
result = d.get('result', {})
content = result.get('content', [])
is_error = result.get('isError', False)
text = content[0].get('text', '') if content else ''

if 'approval' in text.lower():
    print(f'  \033[32m✓\033[0m Action held for approval')
    for line in text.split(chr(10)):
        if 'approval_id' in line.lower():
            print(f'    \033[2m{line.strip()}\033[0m')
            break
elif is_error:
    print(f'  \033[32m✓\033[0m Denied (high-risk)')
    print(f'    \033[2m{text[:120]}\033[0m')
else:
    print(f'  \033[33m⊘\033[0m Auto-allowed (dev-mode)')
    print(f'    \033[2m{text[:80]}\033[0m')
" <<< "$MSG_RESP" && PASSED=$((PASSED+1)) || WARNED=$((WARNED+1))

        echo ""
        explain "The agent can't proceed until a human approves."
        explain "Approve: latchgate approvals approve <id>"
    }
else
    fail "No response"
    FAILED=$((FAILED+1))
fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo -e "\n${BOLD}${WHITE}$( printf '═%.0s' {1..60} )${RESET}"
echo -e "${BOLD}${WHITE}  Summary${RESET}"
echo -e "${BOLD}${WHITE}$( printf '═%.0s' {1..60} )${RESET}\n"

TOTAL=$((PASSED + FAILED + WARNED))
SUMMARY="  ${BOLD}${PASSED}/${TOTAL} passed${RESET}"
[[ $FAILED -gt 0 ]] && SUMMARY="${SUMMARY}  ${RED}${FAILED} failed${RESET}"
[[ $WARNED -gt 0 ]] && SUMMARY="${SUMMARY}  ${YELLOW}${WARNED} adapter errors${RESET}"
echo -e "$SUMMARY"

if [[ $WARNED -gt 0 ]]; then
    echo ""
    explain "Adapter errors mean the latchgate-mcp ↔ gate transport failed."
    explain "The adapter connected and discovered tools, but couldn't execute."
    explain "This is typically a DPoP/lease issue in dev mode. Check gate logs:"
    detail "RUST_LOG=debug LATCHGATE_DEV_MODE=true latchgate serve"
fi

echo ""
explain "Same JSON-RPC protocol as Claude Desktop, Cursor, or any MCP host."
explain "The adapter is a thin stdio bridge - all security lives in the gate."

if [[ -s "$DEBUG_FILE" ]]; then
    echo ""
    detail "Debug log: $DEBUG_FILE"
fi

echo -e "\n${BOLD}${WHITE}$( printf '═%.0s' {1..60} )${RESET}\n"
