#!/usr/bin/env bash
# Test Suite: Layer 0 — PreToolUse URL Blocklist
# Tests pretooluse-guard.sh for URL blocking before tool execution
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PRETOOLUSE_HOOK="$SCRIPT_DIR/../hooks/pretooluse-guard.sh"

PASSED=0
FAILED=0
TOTAL=0

pass() { ((PASSED++)); ((TOTAL++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAILED++)); ((TOTAL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

# Setup temp files
CONF_TMP="$(mktemp)"
BLOCKLIST_TMP="$(mktemp)"

cleanup() { rm -f "$CONF_TMP" "$BLOCKLIST_TMP"; }
trap cleanup EXIT

# Create test blocklist
cat > "$BLOCKLIST_TMP" <<'EOF'
*.malicious.com
evil.example.org
*.pastebin.ws
EOF

cat > "$CONF_TMP" <<EOF
ENABLE_LAYER0=true
BLOCKLIST_FILE=$BLOCKLIST_TMP
EOF

echo "=== Layer 0: PreToolUse Blocklist Tests ==="
echo ""

# --- Test 1: URL matching blocklist is blocked (exit 2) ---
echo "--- Blocked URL detection ---"

BLOCKED_PAYLOAD='{"tool_name":"WebFetch","tool_input":{"url":"https://api.malicious.com/steal-data"}}'

output=$(echo "$BLOCKED_PAYLOAD" | \
    GUARD_CONFIG="$CONF_TMP" ENABLE_LAYER0=true BLOCKLIST_FILE="$BLOCKLIST_TMP" \
    bash "$PRETOOLUSE_HOOK" 2>/dev/null)
exit_code=$?

if [[ "$exit_code" == "2" ]]; then
    pass "blocked URL: *.malicious.com blocked (exit 2)"
else
    fail "blocked URL: expected exit 2, got $exit_code" "$output"
fi

# Verify output contains blocked message
if echo "$output" | grep -q "BLOCKED"; then
    pass "blocked URL: output contains BLOCKED message"
else
    fail "blocked URL: expected BLOCKED in output" "$output"
fi

# --- Test 2: URL not on blocklist passes (exit 0) ---
echo ""
echo "--- Clean URL pass ---"

CLEAN_PAYLOAD='{"tool_name":"WebFetch","tool_input":{"url":"https://api.github.com/repos"}}'

output=$(echo "$CLEAN_PAYLOAD" | \
    GUARD_CONFIG="$CONF_TMP" ENABLE_LAYER0=true BLOCKLIST_FILE="$BLOCKLIST_TMP" \
    bash "$PRETOOLUSE_HOOK" 2>/dev/null)
exit_code=$?

if [[ "$exit_code" == "0" ]]; then
    pass "clean URL: github.com passes (exit 0)"
else
    fail "clean URL: expected exit 0, got $exit_code" "$output"
fi

# --- Test 3: Wildcard domain matching ---
echo ""
echo "--- Wildcard domain matching ---"

# Subdomain of blocked wildcard
SUBDOMAIN_PAYLOAD='{"tool_name":"WebFetch","tool_input":{"url":"https://deep.sub.malicious.com/path"}}'

output=$(echo "$SUBDOMAIN_PAYLOAD" | \
    GUARD_CONFIG="$CONF_TMP" ENABLE_LAYER0=true BLOCKLIST_FILE="$BLOCKLIST_TMP" \
    bash "$PRETOOLUSE_HOOK" 2>/dev/null)
exit_code=$?

if [[ "$exit_code" == "2" ]]; then
    pass "wildcard: deep.sub.malicious.com blocked (exit 2)"
else
    fail "wildcard: expected exit 2, got $exit_code" "$output"
fi

# Exact host match
EXACT_PAYLOAD='{"tool_name":"WebFetch","tool_input":{"url":"https://evil.example.org/data"}}'

output=$(echo "$EXACT_PAYLOAD" | \
    GUARD_CONFIG="$CONF_TMP" ENABLE_LAYER0=true BLOCKLIST_FILE="$BLOCKLIST_TMP" \
    bash "$PRETOOLUSE_HOOK" 2>/dev/null)
exit_code=$?

if [[ "$exit_code" == "2" ]]; then
    pass "exact host: evil.example.org blocked (exit 2)"
else
    fail "exact host: expected exit 2, got $exit_code" "$output"
fi

# --- Test 4: ENABLE_LAYER0=false bypasses all blocking ---
echo ""
echo "--- Layer 0 disabled ---"

output=$(echo "$BLOCKED_PAYLOAD" | \
    GUARD_CONFIG="$CONF_TMP" ENABLE_LAYER0=false BLOCKLIST_FILE="$BLOCKLIST_TMP" \
    bash "$PRETOOLUSE_HOOK" 2>/dev/null)
exit_code=$?

if [[ "$exit_code" == "0" ]]; then
    pass "disabled: ENABLE_LAYER0=false allows all URLs (exit 0)"
else
    fail "disabled: expected exit 0 when disabled, got $exit_code" "$output"
fi

# --- Test 5: No URL in payload passes ---
echo ""
echo "--- No URL in payload ---"

NO_URL_PAYLOAD='{"tool_name":"Bash","tool_input":{"command":"ls -la"}}'

output=$(echo "$NO_URL_PAYLOAD" | \
    GUARD_CONFIG="$CONF_TMP" ENABLE_LAYER0=true BLOCKLIST_FILE="$BLOCKLIST_TMP" \
    bash "$PRETOOLUSE_HOOK" 2>/dev/null)
exit_code=$?

if [[ "$exit_code" == "0" ]]; then
    pass "no URL: non-URL payload passes (exit 0)"
else
    fail "no URL: expected exit 0, got $exit_code" "$output"
fi

echo ""
echo "--- Layer 0 Summary: $PASSED/$TOTAL passed, $FAILED failed ---"
exit $((FAILED > 0 ? 1 : 0))
