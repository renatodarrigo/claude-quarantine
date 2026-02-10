#!/usr/bin/env bash
# claude-quarantine — Test Runner
# Runs all test suites, prints summary, exits non-zero on any failure
# Usage: ./tests/run-all.sh [--verbose]
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERBOSE=false
[[ "${1:-}" == "--verbose" ]] && VERBOSE=true

SUITES=(
    "test-layer1.sh:Layer 1 — Pattern Scanner"
    "test-config.sh:Config Toggles"
    "test-false-positives.sh:False Positive Validation"
    "test-confirmed-threats.sh:Confirmed Threats"
    "test-layer3.sh:Layer 3 — MCP Proxy"
)

SUITE_PASSED=0
SUITE_FAILED=0
SUITE_TOTAL=0
FAILED_SUITES=()

echo "╔══════════════════════════════════════════════╗"
echo "║   claude-quarantine — Test Suite Runner      ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

for entry in "${SUITES[@]}"; do
    script="${entry%%:*}"
    label="${entry#*:}"
    suite_file="$SCRIPT_DIR/$script"

    ((SUITE_TOTAL++))

    if [[ ! -f "$suite_file" ]]; then
        printf '\033[31m✗\033[0m %s — script not found: %s\n' "$label" "$suite_file"
        ((SUITE_FAILED++))
        FAILED_SUITES+=("$label")
        continue
    fi

    echo "━━━ $label ━━━"
    if $VERBOSE; then
        bash "$suite_file"
        rc=$?
    else
        output=$(bash "$suite_file" 2>&1)
        rc=$?
        echo "$output" | grep -E '(PASS|FAIL|Summary)'
    fi

    if [[ $rc -eq 0 ]]; then
        printf '\033[32m✓\033[0m %s\n' "$label"
        ((SUITE_PASSED++))
    else
        printf '\033[31m✗\033[0m %s\n' "$label"
        ((SUITE_FAILED++))
        FAILED_SUITES+=("$label")
        if ! $VERBOSE; then
            echo "$output"
        fi
    fi
    echo ""
done

echo "════════════════════════════════════════════════"
echo "Summary: $SUITE_PASSED/$SUITE_TOTAL suites passed, $SUITE_FAILED failed"

if [[ ${#FAILED_SUITES[@]} -gt 0 ]]; then
    echo ""
    echo "Failed suites:"
    for s in "${FAILED_SUITES[@]}"; do
        printf '  \033[31m✗\033[0m %s\n' "$s"
    done
fi

echo "════════════════════════════════════════════════"
exit $((SUITE_FAILED > 0 ? 1 : 0))
