#!/usr/bin/env bash
# Test Suite 4: False Positive Validation
# All benign fixtures must pass ALL layers clean
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOOK="$SCRIPT_DIR/../hooks/injection-guard.sh"
BENIGN_DIR="$SCRIPT_DIR/fixtures/benign"

TEST_CONF="$(mktemp)"
cat > "$TEST_CONF" <<'EOF'
ENABLE_LAYER1=true
ENABLE_LAYER2=false
ENABLE_RATE_LIMIT=false
HIGH_THREAT_ACTION=block
LOG_FILE=/tmp/injection-guard-fp-test.log
LOG_THRESHOLD=LOW
EOF

export GUARD_CONFIG="$TEST_CONF"
export GUARD_PATTERNS="$SCRIPT_DIR/../hooks/injection-patterns.conf"
export ENABLE_RATE_LIMIT=false

PASSED=0
FAILED=0
TOTAL=0

pass() { ((PASSED++)); ((TOTAL++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAILED++)); ((TOTAL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

echo "=== False Positive Validation ==="
echo ""
echo "All benign fixtures must pass cleanly (no systemMessage, exit 0)"
echo ""

for fixture in "$BENIGN_DIR"/*.json; do
    name=$(basename "$fixture" .json)

    output=$(cat "$fixture" | bash "$HOOK" 2>/dev/null)
    exit_code=$?

    if [[ "$exit_code" != "0" ]]; then
        fail "$name: exit code $exit_code (expected 0)" "$output"
        continue
    fi

    if echo "$output" | grep -q "systemMessage"; then
        fail "$name: false positive — systemMessage generated" "$output"
        continue
    fi

    pass "$name: clean pass (no false positive)"
done

# Cleanup
rm -f "$TEST_CONF" /tmp/injection-guard-fp-test.log

echo ""
echo "--- False Positive Summary: $PASSED/$TOTAL passed, $FAILED failed ---"
exit $((FAILED > 0 ? 1 : 0))
