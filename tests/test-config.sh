#!/usr/bin/env bash
# Test Suite 3: Config Toggle Tests
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$HOME/.claude/hooks/injection-guard.sh"
PAYLOADS_DIR="$SCRIPT_DIR/fixtures/payloads"

export GUARD_PATTERNS="$HOME/.claude/hooks/injection-patterns.conf"

PASSED=0
FAILED=0
TOTAL=0

pass() { ((PASSED++)); ((TOTAL++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAILED++)); ((TOTAL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

run_hook_with_config() {
    local fixture="$1" config_content="$2"
    local conf_file
    conf_file="$(mktemp)"
    echo "$config_content" > "$conf_file"
    local output exit_code
    output=$(GUARD_CONFIG="$conf_file" bash "$HOOK" < "$fixture" 2>/dev/null)
    exit_code=$?
    rm -f "$conf_file"
    echo "$exit_code:$output"
}

echo "=== Config Toggle Tests ==="
echo ""

HIGH_PAYLOAD="$PAYLOADS_DIR/obvious-injection.json"
MED_PAYLOAD="$PAYLOADS_DIR/encoded-base64.json"
LOW_PAYLOAD="$SCRIPT_DIR/fixtures/benign/normal-github-issue.json"

# Test 1: HIGH_THREAT_ACTION=block → HIGH payload → exit 2
echo "--- HIGH_THREAT_ACTION tests ---"
result=$(run_hook_with_config "$HIGH_PAYLOAD" "
ENABLE_LAYER1=true
HIGH_THREAT_ACTION=block
LOG_FILE=/tmp/cq-test-config.log
LOG_THRESHOLD=LOW
")
exit_code="${result%%:*}"
if [[ "$exit_code" == "2" ]]; then
    pass "HIGH_THREAT_ACTION=block → HIGH payload → exit 2"
else
    fail "HIGH_THREAT_ACTION=block → HIGH payload → expected exit 2, got $exit_code" "${result#*:}"
fi

# Test 2: HIGH_THREAT_ACTION=warn → same HIGH payload → exit 0 with systemMessage
result=$(run_hook_with_config "$HIGH_PAYLOAD" "
ENABLE_LAYER1=true
HIGH_THREAT_ACTION=warn
LOG_FILE=/tmp/cq-test-config.log
LOG_THRESHOLD=LOW
")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "0" ]] && echo "$output" | grep -q "systemMessage"; then
    pass "HIGH_THREAT_ACTION=warn → HIGH payload → exit 0 + systemMessage"
else
    fail "HIGH_THREAT_ACTION=warn → expected exit 0 with systemMessage, got exit $exit_code" "$output"
fi

# Test 3: ENABLE_LAYER1=false → bypasses scanning entirely
echo ""
echo "--- Layer toggle tests ---"
result=$(run_hook_with_config "$HIGH_PAYLOAD" "
ENABLE_LAYER1=false
HIGH_THREAT_ACTION=block
LOG_FILE=/tmp/cq-test-config.log
LOG_THRESHOLD=LOW
")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "0" ]] && ! echo "$output" | grep -q "systemMessage"; then
    pass "ENABLE_LAYER1=false → bypass scanning → clean pass"
else
    fail "ENABLE_LAYER1=false → expected clean pass, got exit $exit_code" "$output"
fi

# Test 4: LOG_THRESHOLD=LOW → LOW payload → log entry written (even for clean content, logged because it ran)
echo ""
echo "--- Logging threshold tests ---"
LOG_TMP="/tmp/cq-test-log-low-$$.log"
rm -f "$LOG_TMP"
run_hook_with_config "$MED_PAYLOAD" "
ENABLE_LAYER1=true
HIGH_THREAT_ACTION=block
LOG_FILE=$LOG_TMP
LOG_THRESHOLD=LOW
" > /dev/null
if [[ -f "$LOG_TMP" ]] && grep -q "MED" "$LOG_TMP"; then
    pass "LOG_THRESHOLD=LOW → MED payload → log entry written"
else
    fail "LOG_THRESHOLD=LOW → expected log entry for MED payload" "$(cat "$LOG_TMP" 2>/dev/null || echo 'no log file')"
fi
rm -f "$LOG_TMP"

# Test 5: LOG_THRESHOLD=HIGH → MED payload → NO log entry written
LOG_TMP="/tmp/cq-test-log-high-$$.log"
rm -f "$LOG_TMP"
run_hook_with_config "$MED_PAYLOAD" "
ENABLE_LAYER1=true
HIGH_THREAT_ACTION=block
LOG_FILE=$LOG_TMP
LOG_THRESHOLD=HIGH
" > /dev/null
if [[ ! -f "$LOG_TMP" ]] || ! grep -q "MED" "$LOG_TMP"; then
    pass "LOG_THRESHOLD=HIGH → MED payload → no log entry"
else
    fail "LOG_THRESHOLD=HIGH → expected NO log for MED payload" "$(cat "$LOG_TMP")"
fi
rm -f "$LOG_TMP"

echo ""
echo "--- Config Summary: $PASSED/$TOTAL passed, $FAILED failed ---"
exit $((FAILED > 0 ? 1 : 0))
