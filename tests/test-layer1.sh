#!/usr/bin/env bash
# Test Suite 1: Layer 1 — Pattern Scanner Unit Tests
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$HOME/.claude/hooks/injection-guard.sh"
PAYLOADS_DIR="$SCRIPT_DIR/fixtures/payloads"
BENIGN_DIR="$SCRIPT_DIR/fixtures/benign"

# Use a test config that forces block mode for deterministic testing
TEST_CONF="$(mktemp)"
cat > "$TEST_CONF" <<'EOF'
ENABLE_LAYER1=true
ENABLE_LAYER2=false
ENABLE_RATE_LIMIT=false
HIGH_THREAT_ACTION=block
LOG_FILE=/tmp/injection-guard-test.log
LOG_THRESHOLD=LOW
EOF

export GUARD_CONFIG="$TEST_CONF"
export GUARD_PATTERNS="$HOME/.claude/hooks/injection-patterns.conf"
export ENABLE_RATE_LIMIT=false
export GUARD_CONFIRMED=/dev/null
export LOG_FILE=/tmp/injection-guard-test.log

PASSED=0
FAILED=0
TOTAL=0

pass() { ((PASSED++)); ((TOTAL++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAILED++)); ((TOTAL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

run_hook() {
    local fixture="$1"
    local output exit_code
    output=$(cat "$fixture" | bash "$HOOK" 2>/dev/null)
    exit_code=$?
    echo "$exit_code:$output"
}

echo "=== Layer 1: Pattern Scanner Tests ==="
echo ""
echo "--- Malicious Payloads (should detect) ---"

# obvious-injection.json — should be HIGH (has instruction_override + tool_manipulation + credential_exfil)
result=$(run_hook "$PAYLOADS_DIR/obvious-injection.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]]; then
    pass "obvious-injection: blocked (exit 2)"
else
    fail "obvious-injection: expected exit 2, got $exit_code" "$output"
fi

# role-injection.json — should be HIGH (role_injection)
result=$(run_hook "$PAYLOADS_DIR/role-injection.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]]; then
    pass "role-injection: blocked (exit 2)"
else
    fail "role-injection: expected exit 2, got $exit_code" "$output"
fi

# encoded-base64.json — should be MED (encoded_payload)
result=$(run_hook "$PAYLOADS_DIR/encoded-base64.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "0" ]] && echo "$output" | grep -q "systemMessage"; then
    pass "encoded-base64: warned (exit 0 + systemMessage)"
else
    fail "encoded-base64: expected exit 0 with systemMessage, got exit $exit_code" "$output"
fi

# unicode-obfuscation.json — should be HIGH (unicode + instruction_override)
result=$(run_hook "$PAYLOADS_DIR/unicode-obfuscation.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]]; then
    pass "unicode-obfuscation: blocked (exit 2)"
else
    fail "unicode-obfuscation: expected exit 2, got $exit_code" "$output"
fi

# html-comment-hidden.json — should be HIGH (system_impersonation + tool_manipulation)
result=$(run_hook "$PAYLOADS_DIR/html-comment-hidden.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]]; then
    pass "html-comment-hidden: blocked (exit 2)"
else
    fail "html-comment-hidden: expected exit 2, got $exit_code" "$output"
fi

# tool-manipulation.json — should be HIGH (tool_manipulation)
result=$(run_hook "$PAYLOADS_DIR/tool-manipulation.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]]; then
    pass "tool-manipulation: blocked (exit 2)"
else
    fail "tool-manipulation: expected exit 2, got $exit_code" "$output"
fi

# credential-exfil.json — should be HIGH (credential_exfil)
result=$(run_hook "$PAYLOADS_DIR/credential-exfil.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]]; then
    pass "credential-exfil: blocked (exit 2)"
else
    fail "credential-exfil: expected exit 2, got $exit_code" "$output"
fi

# system-impersonation.json — should be HIGH (system_impersonation)
result=$(run_hook "$PAYLOADS_DIR/system-impersonation.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]]; then
    pass "system-impersonation: blocked (exit 2)"
else
    fail "system-impersonation: expected exit 2, got $exit_code" "$output"
fi

# subtle-social-engineering.json — should be MED or HIGH (social_engineering)
result=$(run_hook "$PAYLOADS_DIR/subtle-social-engineering.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]] || { [[ "$exit_code" == "0" ]] && echo "$output" | grep -q "systemMessage"; }; then
    pass "subtle-social-engineering: detected (exit $exit_code)"
else
    fail "subtle-social-engineering: expected detection, got exit $exit_code" "$output"
fi

# multi-signal-high.json — should be HIGH (multiple categories)
result=$(run_hook "$PAYLOADS_DIR/multi-signal-high.json")
exit_code="${result%%:*}"
output="${result#*:}"
if [[ "$exit_code" == "2" ]]; then
    pass "multi-signal-high: blocked (exit 2)"
else
    fail "multi-signal-high: expected exit 2, got $exit_code" "$output"
fi

echo ""
echo "--- Benign Content (should pass clean) ---"

for fixture in "$BENIGN_DIR"/*.json; do
    name=$(basename "$fixture" .json)
    result=$(run_hook "$fixture")
    exit_code="${result%%:*}"
    output="${result#*:}"
    if [[ "$exit_code" == "0" ]] && ! echo "$output" | grep -q "systemMessage"; then
        pass "$name: clean pass"
    else
        fail "$name: expected clean pass, got exit $exit_code" "$output"
    fi
done

echo ""
echo "--- JSONL Log Format Validation ---"

# The log should exist and have entries from the malicious payloads above
LOG_TMP="/tmp/injection-guard-test.log"
if [[ -f "$LOG_TMP" ]] && [[ -s "$LOG_TMP" ]]; then
    # Every line should be valid JSON
    all_valid=true
    line_count=0
    while IFS= read -r log_line; do
        ((line_count++))
        if ! python3 -c "import json; json.loads('''$log_line''')" 2>/dev/null; then
            # Try feeding via stdin for lines with special chars
            if ! echo "$log_line" | python3 -c "import json,sys; json.load(sys.stdin)" 2>/dev/null; then
                all_valid=false
                break
            fi
        fi
    done < "$LOG_TMP"

    if $all_valid && (( line_count > 0 )); then
        pass "JSONL log: all $line_count entries are valid JSON"
    else
        fail "JSONL log: invalid JSON found in log" "line_count=$line_count"
    fi

    # Check required fields in first entry
    has_fields=$(head -1 "$LOG_TMP" | python3 -c "
import json, sys
entry = json.load(sys.stdin)
required = ['id', 'timestamp', 'tool', 'severity', 'categories', 'indicators', 'snippet', 'status']
missing = [f for f in required if f not in entry]
print('ok' if not missing else 'missing: ' + ', '.join(missing))
" 2>/dev/null)

    if [[ "$has_fields" == "ok" ]]; then
        pass "JSONL log: first entry has all required fields"
    else
        fail "JSONL log: $has_fields" ""
    fi

    # Check status is "unreviewed" (default)
    status_check=$(head -1 "$LOG_TMP" | python3 -c "
import json, sys
entry = json.load(sys.stdin)
print(entry.get('status', ''))
" 2>/dev/null)

    if [[ "$status_check" == "unreviewed" ]]; then
        pass "JSONL log: entries default to status=unreviewed"
    else
        fail "JSONL log: expected status=unreviewed, got $status_check" ""
    fi

    # Check snippet is populated (non-empty)
    snippet_check=$(head -1 "$LOG_TMP" | python3 -c "
import json, sys
entry = json.load(sys.stdin)
print('ok' if entry.get('snippet', '') else 'empty')
" 2>/dev/null)

    if [[ "$snippet_check" == "ok" ]]; then
        pass "JSONL log: snippet field is populated"
    else
        fail "JSONL log: snippet is empty" ""
    fi
else
    fail "JSONL log: log file missing or empty" "$LOG_TMP"
    fail "JSONL log: (skipping field checks)" ""
    fail "JSONL log: (skipping status check)" ""
    fail "JSONL log: (skipping snippet check)" ""
fi

# Cleanup
rm -f "$TEST_CONF" "$LOG_TMP"

echo ""
echo "--- Layer 1 Summary: $PASSED/$TOTAL passed, $FAILED failed ---"
exit $((FAILED > 0 ? 1 : 0))
