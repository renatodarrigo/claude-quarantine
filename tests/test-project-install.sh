#!/usr/bin/env bash
# Test Suite: Project-Level Installation
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$REPO_DIR/install.sh"

PASSED=0
FAILED=0
TOTAL=0

pass() { ((PASSED++)); ((TOTAL++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAILED++)); ((TOTAL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

echo "=== Project-Level Installation Tests ==="
echo ""

# Test 1: --help shows usage
echo "--- Argument parsing ---"
help_output=$(bash "$INSTALLER" --help 2>&1)
if echo "$help_output" | grep -q "USAGE:"; then
    pass "--help shows usage"
else
    fail "--help shows usage" "No USAGE in output: $help_output"
fi

# Test 2: Unknown flag errors
unknown_output=$(bash "$INSTALLER" --bogus 2>&1)
exit_code=$?
if [[ "$exit_code" != "0" ]] && echo "$unknown_output" | grep -q "Unknown option"; then
    pass "Unknown flag errors with message"
else
    fail "Unknown flag errors" "exit=$exit_code output=$unknown_output"
fi

# Test 3: --project creates .claude/ structure
echo ""
echo "--- Project install ---"
TEMP_PROJECT="$(mktemp -d)"
cd "$TEMP_PROJECT"
bash "$INSTALLER" --project > /dev/null 2>&1
structure_ok=true
for dir in ".claude/hooks" ".claude/mcp" ".claude/commands"; do
    if [[ ! -d "$TEMP_PROJECT/$dir" ]]; then
        structure_ok=false
        break
    fi
done
if $structure_ok; then
    pass "--project creates .claude/ directory structure"
else
    fail "--project creates .claude/ directory structure" "Missing directories in $TEMP_PROJECT"
fi

# Test 4: settings.json uses relative paths
if [[ -f "$TEMP_PROJECT/.claude/settings.json" ]]; then
    if grep -q '".claude/hooks/injection-guard.sh"' "$TEMP_PROJECT/.claude/settings.json" && \
       ! grep -q '"~/.claude/' "$TEMP_PROJECT/.claude/settings.json"; then
        pass "settings.json uses relative .claude/ paths"
    else
        fail "settings.json uses relative paths" "$(cat "$TEMP_PROJECT/.claude/settings.json")"
    fi
else
    fail "settings.json uses relative paths" "settings.json not created"
fi

# Test 5: Config LOG_FILE is project-relative
if [[ -f "$TEMP_PROJECT/.claude/hooks/injection-guard.conf" ]]; then
    if grep -q 'LOG_FILE=.claude/hooks/' "$TEMP_PROJECT/.claude/hooks/injection-guard.conf"; then
        pass "Config LOG_FILE uses project-relative path"
    else
        fail "Config LOG_FILE uses project-relative path" "$(grep LOG_FILE "$TEMP_PROJECT/.claude/hooks/injection-guard.conf")"
    fi
else
    fail "Config LOG_FILE uses project-relative path" "injection-guard.conf not created"
fi

# Test 6: .gitignore created with correct entries
if [[ -f "$TEMP_PROJECT/.claude/.gitignore" ]]; then
    gi_ok=true
    for entry in "settings.local.json" "hooks/injection-guard.log" "hooks/confirmed-threats.json"; do
        if ! grep -q "$entry" "$TEMP_PROJECT/.claude/.gitignore"; then
            gi_ok=false
            break
        fi
    done
    if $gi_ok; then
        pass ".gitignore created with correct entries"
    else
        fail ".gitignore created with correct entries" "$(cat "$TEMP_PROJECT/.claude/.gitignore")"
    fi
else
    fail ".gitignore created" ".claude/.gitignore not found"
fi

# Test 7: Hook executes from project location
echo ""
echo "--- Hook execution ---"
if [[ -x "$TEMP_PROJECT/.claude/hooks/injection-guard.sh" ]]; then
    # Pipe benign JSON and check for clean pass
    test_input='{"tool_name":"WebFetch","tool_result":{"content":"Hello world, nothing suspicious here."}}'
    hook_output=$(echo "$test_input" | GUARD_CONFIG="$TEMP_PROJECT/.claude/hooks/injection-guard.conf" \
        GUARD_PATTERNS="$TEMP_PROJECT/.claude/hooks/injection-patterns.conf" \
        bash "$TEMP_PROJECT/.claude/hooks/injection-guard.sh" 2>/dev/null)
    exit_code=$?
    if [[ "$exit_code" == "0" ]] && echo "$hook_output" | grep -q "{}"; then
        pass "Hook executes from project location with clean pass"
    else
        fail "Hook executes from project location" "exit=$exit_code output=$hook_output"
    fi
else
    fail "Hook executes from project location" "injection-guard.sh not executable"
fi

rm -rf "$TEMP_PROJECT"

# Test 8: Default install (no flag) goes to ~/.claude/ with ~/ paths
echo ""
echo "--- Default install ---"
FAKE_HOME="$(mktemp -d)"
HOME="$FAKE_HOME" bash "$INSTALLER" > /dev/null 2>&1
if [[ -f "$FAKE_HOME/.claude/settings.json" ]]; then
    if grep -q '"~/.claude/hooks/injection-guard.sh"' "$FAKE_HOME/.claude/settings.json" && \
       grep -q '"~/.claude/mcp/claude-quarantine/dist/index.js"' "$FAKE_HOME/.claude/settings.json"; then
        pass "Default install uses ~/.claude/ with ~/ paths"
    else
        fail "Default install uses ~/.claude/ paths" "$(cat "$FAKE_HOME/.claude/settings.json")"
    fi
else
    fail "Default install uses ~/.claude/ paths" "settings.json not created at $FAKE_HOME/.claude/"
fi
rm -rf "$FAKE_HOME"

echo ""
echo "--- Project Install Summary: $PASSED/$TOTAL passed, $FAILED failed ---"
exit $((FAILED > 0 ? 1 : 0))
