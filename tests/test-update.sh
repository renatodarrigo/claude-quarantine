#!/usr/bin/env bash
# Test Suite: Update Mechanism
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
INSTALLER="$REPO_DIR/install.sh"

PASSED=0
FAILED=0
TOTAL=0

pass() { ((PASSED++)); ((TOTAL++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAILED++)); ((TOTAL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

echo "=== Update Mechanism Tests ==="
echo ""

# Test 1: VERSION file exists and is valid
echo "--- VERSION file ---"
if [[ -f "$REPO_DIR/VERSION" ]]; then
    version_content=$(cat "$REPO_DIR/VERSION" | tr -d '[:space:]')
    if [[ "$version_content" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        pass "VERSION file exists and contains valid semver ($version_content)"
    else
        fail "VERSION file contains valid semver" "Got: '$version_content'"
    fi
else
    fail "VERSION file exists" "Not found at $REPO_DIR/VERSION"
fi

# Test 2: Installer writes version marker (user-level)
echo ""
echo "--- User-level install ---"
FAKE_HOME="$(mktemp -d)"
HOME="$FAKE_HOME" bash "$INSTALLER" > /dev/null 2>&1
expected_version=$(cat "$REPO_DIR/VERSION" | tr -d '[:space:]')

if [[ -f "$FAKE_HOME/.claude/.quarantine-version" ]]; then
    installed_version=$(cat "$FAKE_HOME/.claude/.quarantine-version" | tr -d '[:space:]')
    if [[ "$installed_version" == "$expected_version" ]]; then
        pass "Installer writes .quarantine-version marker ($installed_version)"
    else
        fail "Version marker matches VERSION" "Expected '$expected_version', got '$installed_version'"
    fi
else
    fail "Installer writes .quarantine-version marker" "File not found at $FAKE_HOME/.claude/.quarantine-version"
fi

# Test 3: Installer copies update-quarantine.md (user-level)
if [[ -f "$FAKE_HOME/.claude/commands/update-quarantine.md" ]]; then
    pass "Installer copies update-quarantine.md to commands/"
else
    fail "Installer copies update-quarantine.md" "File not found at $FAKE_HOME/.claude/commands/update-quarantine.md"
fi
rm -rf "$FAKE_HOME"

# Test 4: Project-level install writes version marker
echo ""
echo "--- Project-level install ---"
TEMP_PROJECT="$(mktemp -d)"
bash "$INSTALLER" --project="$TEMP_PROJECT" > /dev/null 2>&1

if [[ -f "$TEMP_PROJECT/.claude/.quarantine-version" ]]; then
    proj_version=$(cat "$TEMP_PROJECT/.claude/.quarantine-version" | tr -d '[:space:]')
    if [[ "$proj_version" == "$expected_version" ]]; then
        pass "Project-level install writes .quarantine-version marker ($proj_version)"
    else
        fail "Project-level version marker matches VERSION" "Expected '$expected_version', got '$proj_version'"
    fi
else
    fail "Project-level install writes .quarantine-version marker" "File not found at $TEMP_PROJECT/.claude/.quarantine-version"
fi

# Test 5: Project-level install copies update skill
if [[ -f "$TEMP_PROJECT/.claude/commands/update-quarantine.md" ]]; then
    pass "Project-level install copies update-quarantine.md"
else
    fail "Project-level install copies update-quarantine.md" "File not found at $TEMP_PROJECT/.claude/commands/update-quarantine.md"
fi
rm -rf "$TEMP_PROJECT"

# Test 6: Re-install preserves config but updates version
echo ""
echo "--- Re-install preservation ---"
FAKE_HOME2="$(mktemp -d)"
HOME="$FAKE_HOME2" bash "$INSTALLER" > /dev/null 2>&1

# Modify config to detect preservation
echo "# custom user setting" >> "$FAKE_HOME2/.claude/hooks/injection-guard.conf"
config_before=$(cat "$FAKE_HOME2/.claude/hooks/injection-guard.conf")

# Re-run installer
HOME="$FAKE_HOME2" bash "$INSTALLER" > /dev/null 2>&1
config_after=$(cat "$FAKE_HOME2/.claude/hooks/injection-guard.conf")

if [[ "$config_before" == "$config_after" ]]; then
    reinstall_version=$(cat "$FAKE_HOME2/.claude/.quarantine-version" | tr -d '[:space:]')
    if [[ "$reinstall_version" == "$expected_version" ]]; then
        pass "Re-install preserves config and updates version marker"
    else
        fail "Re-install updates version marker" "Expected '$expected_version', got '$reinstall_version'"
    fi
else
    fail "Re-install preserves config" "Config was overwritten"
fi
rm -rf "$FAKE_HOME2"

# Test 7: update-quarantine.md contains required sections
echo ""
echo "--- Skill validation ---"
skill_file="$REPO_DIR/update-quarantine.md"
skill_ok=true
for section in "File locations" "Procedure" "Important rules"; do
    if ! grep -q "$section" "$skill_file"; then
        skill_ok=false
        fail "update-quarantine.md contains '$section' section" "Section not found"
    fi
done
if $skill_ok; then
    pass "update-quarantine.md contains all required sections"
fi

echo ""
echo "--- Update Mechanism Summary: $PASSED/$TOTAL passed, $FAILED failed ---"
exit $((FAILED > 0 ? 1 : 0))
