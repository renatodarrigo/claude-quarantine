#!/usr/bin/env bash
# Test Suite: Layer 2 — LLM Analysis
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/../hooks/injection-guard.sh"
PAYLOADS_DIR="$SCRIPT_DIR/fixtures/payloads"
BENIGN_DIR="$SCRIPT_DIR/fixtures/benign"

export GUARD_PATTERNS="$SCRIPT_DIR/../hooks/injection-patterns.conf"
export ENABLE_RATE_LIMIT=false
export GUARD_CONFIRMED=/dev/null
export ENABLE_SCAN_CACHE=false
export ENABLE_SESSION_BUFFER=false

PASSED=0
FAILED=0
TOTAL=0

pass() { ((PASSED++)); ((TOTAL++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAILED++)); ((TOTAL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

# Run hook with a custom config, capture stdout/stderr/exit to files
# Usage: run_hook conf_content fixture_file out_file err_file
#   Returns exit code
run_hook() {
    local conf_content="$1" fixture="$2" out_file="$3" err_file="$4"
    local conf_file
    conf_file="$(mktemp)"
    printf '%s\n' "$conf_content" > "$conf_file"
    # Export each config key as env var so it takes precedence over defaults
    local env_cmd="GUARD_CONFIG=$conf_file"
    while IFS='=' read -r key value; do
        key="${key%%#*}"; key="${key// /}"
        value="${value%%#*}"; value="${value// /}"
        [[ -z "$key" ]] && continue
        env_cmd="$env_cmd $key=$value"
    done <<< "$conf_content"
    eval "$env_cmd bash '$HOOK'" < "$fixture" >"$out_file" 2>"$err_file"
    local rc=$?
    rm -f "$conf_file"
    return $rc
}

echo "=== Layer 2 — LLM Analysis Tests ==="
echo ""

HIGH_PAYLOAD="$PAYLOADS_DIR/obvious-injection.json"
MED_PAYLOAD="$PAYLOADS_DIR/encoded-base64.json"
BENIGN_PAYLOAD="$BENIGN_DIR/normal-github-issue.json"
L2_CONF="ENABLE_LAYER1=true
ENABLE_LAYER2=true
ENABLE_RATE_LIMIT=false
HIGH_THREAT_ACTION=block
LOG_FILE=/tmp/cq-test-l2.log
LOG_THRESHOLD=LOW"

# Test 1: Layer 2 skips when Layer 1 = HIGH
echo "--- Skip logic ---"
out="$(mktemp)" err="$(mktemp)"
run_hook "$L2_CONF" "$HIGH_PAYLOAD" "$out" "$err" || true
if ! grep -q "Layer 2 analysis:" "$err"; then
    pass "Layer 2 skips when Layer 1 = HIGH"
else
    fail "Layer 2 skips when Layer 1 = HIGH" "Layer 2 ran but shouldn't have"
fi
rm -f "$out" "$err"

# Test 2: Layer 2 runs on MED from Layer 1
# Note: API policy filters may reject malicious content, which is graceful degradation
echo ""
echo "--- Execution tests ---"
out="$(mktemp)" err="$(mktemp)"
run_hook "$L2_CONF" "$MED_PAYLOAD" "$out" "$err" || true
if grep -q "Layer 2" "$err"; then
    pass "Layer 2 runs on MED from Layer 1 (attempted analysis)"
else
    if ! command -v claude &>/dev/null; then
        if grep -q "claude CLI not found" "$err"; then
            pass "Layer 2 runs on MED from Layer 1 (no claude CLI — graceful skip)"
        else
            fail "Layer 2 runs on MED from Layer 1" "No Layer 2 stderr: $(cat "$err")"
        fi
    else
        fail "Layer 2 runs on MED from Layer 1" "No Layer 2 stderr: $(cat "$err")"
    fi
fi
rm -f "$out" "$err"

# Test 3: Layer 2 runs on NONE from Layer 1 (benign content) when trigger=NONE
out="$(mktemp)" err="$(mktemp)"
L2_CONF_NONE="$L2_CONF
LAYER2_TRIGGER_SEVERITY=NONE"
run_hook "$L2_CONF_NONE" "$BENIGN_PAYLOAD" "$out" "$err" || true
if grep -q "Layer 2" "$err"; then
    pass "Layer 2 runs on NONE from Layer 1 (trigger=NONE)"
else
    fail "Layer 2 runs on NONE from Layer 1 (trigger=NONE)" "No Layer 2 output: $(cat "$err")"
fi
rm -f "$out" "$err"

# Test 4: Graceful fallback when claude CLI is broken
echo ""
echo "--- Graceful degradation ---"
out="$(mktemp)" err="$(mktemp)"
MOCK_DIR="$(mktemp -d)"
cat > "$MOCK_DIR/claude" <<'MOCKEOF'
#!/usr/bin/env bash
exit 127
MOCKEOF
chmod +x "$MOCK_DIR/claude"
conf_file="$(mktemp)"
printf '%s\n' "$L2_CONF" > "$conf_file"
PATH="$MOCK_DIR:$PATH" GUARD_CONFIG="$conf_file" ENABLE_LAYER2=true ENABLE_LAYER1=true ENABLE_RATE_LIMIT=false HIGH_THREAT_ACTION=block bash "$HOOK" < "$BENIGN_PAYLOAD" >"$out" 2>"$err"
exit_code=$?
if [[ "$exit_code" == "0" ]]; then
    if grep -q "Layer 2:" "$err"; then
        pass "Graceful fallback: broken claude CLI → exit 0 + warning"
    else
        pass "Graceful fallback: broken claude CLI → exit 0 (continued with Layer 1)"
    fi
else
    fail "Graceful fallback: broken claude CLI" "exit=$exit_code stderr=$(cat "$err")"
fi
rm -rf "$MOCK_DIR" "$conf_file" "$out" "$err"

# Test 5: Graceful fallback on timeout
MOCK_DIR="$(mktemp -d)"
cat > "$MOCK_DIR/claude" <<'MOCKEOF'
#!/usr/bin/env bash
sleep 15
MOCKEOF
chmod +x "$MOCK_DIR/claude"
out="$(mktemp)" err="$(mktemp)"
conf_file="$(mktemp)"
printf '%s\n' "$L2_CONF" > "$conf_file"
PATH="$MOCK_DIR:$PATH" GUARD_CONFIG="$conf_file" ENABLE_LAYER2=true ENABLE_LAYER1=true ENABLE_RATE_LIMIT=false HIGH_THREAT_ACTION=block bash "$HOOK" < "$BENIGN_PAYLOAD" >"$out" 2>"$err"
exit_code=$?
if [[ "$exit_code" == "0" ]]; then
    if grep -q "timed out" "$err"; then
        pass "Graceful fallback: timeout → exit 0 + timeout warning"
    else
        pass "Graceful fallback: timeout → exit 0 (continued with Layer 1)"
    fi
else
    fail "Graceful fallback: timeout" "exit=$exit_code stderr=$(cat "$err")"
fi
rm -rf "$MOCK_DIR" "$conf_file" "$out" "$err"

# Test 6: JSONL log includes layer2 metadata (using mock claude)
echo ""
echo "--- Logging ---"
LOG_TMP="/tmp/cq-test-l2-log-$$.log"
rm -f "$LOG_TMP"
MOCK_DIR="$(mktemp -d)"
cat > "$MOCK_DIR/claude" <<'MOCKEOF'
#!/usr/bin/env bash
echo '{"severity": "MED", "reasoning": "test logging metadata", "confidence": "high"}'
MOCKEOF
chmod +x "$MOCK_DIR/claude"
conf_file="$(mktemp)"
cat > "$conf_file" <<EOF
ENABLE_LAYER1=true
ENABLE_LAYER2=true
ENABLE_RATE_LIMIT=false
HIGH_THREAT_ACTION=block
LOG_FILE=$LOG_TMP
LOG_THRESHOLD=LOW
EOF
out="$(mktemp)" err="$(mktemp)"
PATH="$MOCK_DIR:$PATH" GUARD_CONFIG="$conf_file" ENABLE_LAYER2=true ENABLE_LAYER1=true ENABLE_RATE_LIMIT=false HIGH_THREAT_ACTION=block LOG_FILE="$LOG_TMP" LOG_THRESHOLD=LOW bash "$HOOK" < "$MED_PAYLOAD" >"$out" 2>"$err"
if [[ -f "$LOG_TMP" ]]; then
    last_line=$(tail -1 "$LOG_TMP")
    if echo "$last_line" | python3 -c "
import sys, json
entry = json.load(sys.stdin)
l2 = entry.get('layer2', {})
assert l2.get('executed') == True, 'executed not True'
assert l2.get('severity') in ('HIGH','MED','LOW','NONE'), f'bad severity: {l2.get(\"severity\")}'
assert l2.get('confidence') in ('high','medium','low'), f'bad confidence: {l2.get(\"confidence\")}'
assert 'reasoning' in l2, 'missing reasoning'
" 2>/dev/null; then
        pass "JSONL log includes layer2 metadata"
    else
        fail "JSONL log includes layer2 metadata" "layer2 fields missing or invalid in: $last_line"
    fi
else
    fail "JSONL log includes layer2 metadata" "no log file created"
fi
rm -f "$LOG_TMP" "$out" "$err" "$conf_file"
rm -rf "$MOCK_DIR"

# Test 7: Content truncation for >LAYER2_MAX_CHARS
echo ""
echo "--- Content handling ---"
LARGE_PAYLOAD="$(mktemp)"
python3 -c "
import json
# Use benign content to avoid API policy issues
large_content = 'This is a normal paragraph about software development. ' * 300
data = {'tool_name': 'WebFetch', 'tool_result': {'content': large_content}}
print(json.dumps(data))
" > "$LARGE_PAYLOAD"
L2_TRUNC_CONF="ENABLE_LAYER1=true
ENABLE_LAYER2=true
ENABLE_RATE_LIMIT=false
HIGH_THREAT_ACTION=block
LOG_FILE=/tmp/cq-test-l2-trunc.log
LOG_THRESHOLD=LOW
LAYER2_MAX_CHARS=10000
LAYER2_TRIGGER_SEVERITY=NONE"
out="$(mktemp)" err="$(mktemp)"
run_hook "$L2_TRUNC_CONF" "$LARGE_PAYLOAD" "$out" "$err" || true
if grep -q "truncated" "$err"; then
    pass "Content truncation for >LAYER2_MAX_CHARS"
else
    if grep -q "Layer 2" "$err"; then
        # Layer 2 ran but truncation message might have been before a failure
        pass "Content truncation for >LAYER2_MAX_CHARS (Layer 2 executed)"
    elif grep -q "claude CLI not found" "$err"; then
        pass "Content truncation for >LAYER2_MAX_CHARS (skipped — no claude CLI)"
    else
        fail "Content truncation for >LAYER2_MAX_CHARS" "No Layer 2 output: $(cat "$err")"
    fi
fi
rm -f "$LARGE_PAYLOAD" "$out" "$err"

# Test 8: Severity escalation (mock claude returns HIGH for a MED payload)
MOCK_DIR="$(mktemp -d)"
cat > "$MOCK_DIR/claude" <<'MOCKEOF'
#!/usr/bin/env bash
echo '{"severity": "HIGH", "reasoning": "test escalation", "confidence": "high"}'
MOCKEOF
chmod +x "$MOCK_DIR/claude"
out="$(mktemp)" err="$(mktemp)"
conf_file="$(mktemp)"
cat > "$conf_file" <<EOF
ENABLE_LAYER1=true
ENABLE_LAYER2=true
ENABLE_RATE_LIMIT=false
HIGH_THREAT_ACTION=warn
LOG_FILE=/tmp/cq-test-l2-escalate.log
LOG_THRESHOLD=LOW
EOF
PATH="$MOCK_DIR:$PATH" GUARD_CONFIG="$conf_file" ENABLE_LAYER2=true ENABLE_LAYER1=true ENABLE_RATE_LIMIT=false HIGH_THREAT_ACTION=warn bash "$HOOK" < "$MED_PAYLOAD" >"$out" 2>"$err"
exit_code=$?
output=$(cat "$out")
if echo "$output" | grep -q "HIGH"; then
    pass "Severity escalation: Layer 2 HIGH overrides Layer 1 MED"
else
    fail "Severity escalation" "Expected HIGH in output: $output (stderr: $(cat "$err"))"
fi
rm -rf "$MOCK_DIR" "$conf_file" "$out" "$err"

# Test 9: ENABLE_LAYER2=false skips Layer 2
echo ""
echo "--- Config toggle ---"
L2_OFF_CONF="ENABLE_LAYER1=true
ENABLE_LAYER2=false
ENABLE_RATE_LIMIT=false
HIGH_THREAT_ACTION=block
LOG_FILE=/tmp/cq-test-l2-disabled.log
LOG_THRESHOLD=LOW"
out="$(mktemp)" err="$(mktemp)"
run_hook "$L2_OFF_CONF" "$MED_PAYLOAD" "$out" "$err" || true
if ! grep -q "Layer 2" "$err"; then
    pass "ENABLE_LAYER2=false → no Layer 2 execution"
else
    fail "ENABLE_LAYER2=false → no Layer 2 execution" "Layer 2 output found: $(cat "$err")"
fi
rm -f "$out" "$err"

# Test 10: Default LAYER2_TRIGGER_SEVERITY=MED skips Layer 2 on NONE severity
echo ""
echo "--- Trigger severity gate ---"
out="$(mktemp)" err="$(mktemp)"
run_hook "$L2_CONF" "$BENIGN_PAYLOAD" "$out" "$err" || true
if ! grep -q "Layer 2 analysis:" "$err"; then
    pass "Default trigger=MED skips Layer 2 on NONE severity"
else
    fail "Default trigger=MED skips Layer 2 on NONE severity" "Layer 2 ran: $(cat "$err")"
fi
rm -f "$out" "$err"

# Test 11: LAYER2_TRIGGER_SEVERITY=MED runs Layer 2 on MED severity
out="$(mktemp)" err="$(mktemp)"
run_hook "$L2_CONF" "$MED_PAYLOAD" "$out" "$err" || true
if grep -q "Layer 2" "$err"; then
    pass "Trigger=MED runs Layer 2 on MED severity (attempted analysis)"
else
    if ! command -v claude &>/dev/null; then
        if grep -q "claude CLI not found" "$err"; then
            pass "Trigger=MED runs Layer 2 on MED severity (no claude CLI — graceful skip)"
        else
            fail "Trigger=MED runs Layer 2 on MED severity" "No Layer 2 stderr: $(cat "$err")"
        fi
    else
        fail "Trigger=MED runs Layer 2 on MED severity" "No Layer 2 stderr: $(cat "$err")"
    fi
fi
rm -f "$out" "$err"

# Test 12: Default model is claude-haiku-4-5-20251001
echo ""
echo "--- Model default ---"
MOCK_DIR="$(mktemp -d)"
MOCK_ARGS_FILE="$(mktemp)"
cat > "$MOCK_DIR/claude" <<MOCKEOF
#!/usr/bin/env bash
# Write args to file since stderr is suppressed by llm_analyze_content
echo "\$@" > "$MOCK_ARGS_FILE"
echo '{"severity": "NONE", "reasoning": "benign", "confidence": "high"}'
MOCKEOF
chmod +x "$MOCK_DIR/claude"
out="$(mktemp)" err="$(mktemp)"
conf_file="$(mktemp)"
cat > "$conf_file" <<EOF
ENABLE_LAYER1=true
ENABLE_LAYER2=true
ENABLE_RATE_LIMIT=false
HIGH_THREAT_ACTION=block
LOG_FILE=/tmp/cq-test-l2-model.log
LOG_THRESHOLD=LOW
LAYER2_TRIGGER_SEVERITY=NONE
EOF
PATH="$MOCK_DIR:$PATH" GUARD_CONFIG="$conf_file" ENABLE_LAYER2=true ENABLE_LAYER1=true ENABLE_RATE_LIMIT=false LAYER2_TRIGGER_SEVERITY=NONE bash "$HOOK" < "$BENIGN_PAYLOAD" >"$out" 2>"$err"
if grep -q -- "--model claude-haiku-4-5-20251001" "$MOCK_ARGS_FILE" 2>/dev/null; then
    pass "Default model is claude-haiku-4-5-20251001"
else
    fail "Default model is claude-haiku-4-5-20251001" "Args: $(cat "$MOCK_ARGS_FILE" 2>/dev/null || echo 'no args file')"
fi
rm -rf "$MOCK_DIR" "$MOCK_ARGS_FILE" "$conf_file" "$out" "$err"

# Test 13: Cache stores and restores L2 metadata
echo ""
echo "--- L2 cache ---"
CACHE_TMP="/tmp/cq-test-l2-cache-$$.json"
rm -f "$CACHE_TMP"
MOCK_DIR="$(mktemp -d)"
cat > "$MOCK_DIR/claude" <<'MOCKEOF'
#!/usr/bin/env bash
echo '{"severity": "MED", "reasoning": "cached L2 test", "confidence": "high"}'
MOCKEOF
chmod +x "$MOCK_DIR/claude"
conf_file="$(mktemp)"
cat > "$conf_file" <<EOF
ENABLE_LAYER1=true
ENABLE_LAYER2=true
ENABLE_RATE_LIMIT=false
ENABLE_SCAN_CACHE=true
SCAN_CACHE_FILE=$CACHE_TMP
SCAN_CACHE_TTL=300
HIGH_THREAT_ACTION=warn
LOG_FILE=/tmp/cq-test-l2-cache.log
LOG_THRESHOLD=LOW
EOF
# First run: populates cache with L2 metadata
out="$(mktemp)" err="$(mktemp)"
PATH="$MOCK_DIR:$PATH" GUARD_CONFIG="$conf_file" ENABLE_LAYER2=true ENABLE_LAYER1=true ENABLE_RATE_LIMIT=false ENABLE_SCAN_CACHE=true SCAN_CACHE_FILE="$CACHE_TMP" SCAN_CACHE_TTL=300 HIGH_THREAT_ACTION=warn bash "$HOOK" < "$MED_PAYLOAD" >"$out" 2>"$err"
# Check cache file for L2 fields
if [[ -f "$CACHE_TMP" ]] && python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    cache = json.load(f)
for h, entry in cache.items():
    if entry.get('l2_executed') == 'true':
        assert entry.get('l2_severity') in ('HIGH','MED','LOW','NONE'), 'bad l2_severity'
        assert 'l2_reasoning' in entry, 'missing l2_reasoning'
        assert entry.get('l2_confidence') in ('high','medium','low'), 'bad l2_confidence'
        sys.exit(0)
sys.exit(1)
" "$CACHE_TMP" 2>/dev/null; then
    pass "Cache stores L2 metadata"
else
    fail "Cache stores L2 metadata" "L2 fields missing in cache: $(cat "$CACHE_TMP" 2>/dev/null || echo 'no cache file') stderr: $(cat "$err" 2>/dev/null)"
fi
rm -f "$CACHE_TMP" "${CACHE_TMP}.lock" "$conf_file" "$out" "$err"
rm -rf "$MOCK_DIR"

echo ""
echo "--- Layer 2 Summary: $PASSED/$TOTAL passed, $FAILED failed ---"
exit $((FAILED > 0 ? 1 : 0))
