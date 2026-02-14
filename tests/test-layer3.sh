#!/usr/bin/env bash
# Test Suite 2: Layer 3 — MCP Proxy Integration Tests
# Spawns a local HTTP server with test fixtures, then tests the MCP scanner
set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MCP_DIR="$SCRIPT_DIR/../mcp"
PAYLOADS_DIR="$SCRIPT_DIR/fixtures/payloads"
BENIGN_DIR="$SCRIPT_DIR/fixtures/benign"

# We need nvm for node
export NVM_DIR="$HOME/.nvm"
[ -s "$NVM_DIR/nvm.sh" ] && . "$NVM_DIR/nvm.sh"

PASSED=0
FAILED=0
TOTAL=0

pass() { ((PASSED++)); ((TOTAL++)); printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { ((FAILED++)); ((TOTAL++)); printf '  \033[31mFAIL\033[0m %s — %s\n' "$1" "$2"; }

# --- Start a simple HTTP server serving fixture content ---
HTTP_PORT=0
HTTP_PID=""
HTTP_DIR="$(mktemp -d)"

setup_http_server() {
    # Create pages from fixtures (extract tool_result.content)
    for f in "$PAYLOADS_DIR"/*.json "$BENIGN_DIR"/*.json; do
        local name
        name=$(basename "$f" .json)
        python3 -c "
import json, sys
data = json.load(open('$f'))
result = data.get('tool_result', {})
content = result.get('content', '') if isinstance(result, dict) else str(result)
print(content)
" > "$HTTP_DIR/$name.html"
    done

    # Start Python HTTP server on random port
    python3 -c "
import http.server, socketserver, sys, os
os.chdir('$HTTP_DIR')
handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(('127.0.0.1', 0), handler) as httpd:
    port = httpd.server_address[1]
    sys.stdout.write(str(port))
    sys.stdout.flush()
    httpd.serve_forever()
" &
    HTTP_PID=$!

    # Wait for server to start and get the port
    sleep 1

    # Find the port the server is listening on
    HTTP_PORT=$(ss -tlnp 2>/dev/null | grep "pid=$HTTP_PID" | awk '{print $4}' | grep -oE '[0-9]+$' | head -1)

    if [[ -z "$HTTP_PORT" ]]; then
        # Fallback: try lsof
        HTTP_PORT=$(lsof -p $HTTP_PID -iTCP -sTCP:LISTEN 2>/dev/null | awk 'NR>1{print $9}' | grep -oE '[0-9]+$' | head -1)
    fi

    if [[ -z "$HTTP_PORT" ]]; then
        echo "ERROR: Could not determine HTTP server port"
        cleanup
        exit 1
    fi
}

cleanup() {
    [[ -n "$HTTP_PID" ]] && kill "$HTTP_PID" 2>/dev/null
    rm -rf "$HTTP_DIR"
}
trap cleanup EXIT

# --- Test the scanner module directly via Node ---
test_scanner() {
    local content="$1" expected_severity="$2" label="$3"

    local result
    result=$(node -e "
import { scanContent } from '$MCP_DIR/dist/scanner.js';
const content = $(python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" <<< "$content");
const result = scanContent(content);
console.log(JSON.stringify(result));
" 2>/dev/null)

    local severity
    severity=$(echo "$result" | python3 -c "import json,sys; print(json.load(sys.stdin).get('severity',''))" 2>/dev/null)

    if [[ "$severity" == "$expected_severity" ]]; then
        pass "$label: severity=$severity"
    else
        fail "$label: expected severity=$expected_severity, got $severity" "$result"
    fi
}

# --- Test the sanitizer module directly via Node ---
test_sanitizer() {
    local content="$1" should_modify="$2" marker="$3" label="$4"

    local result
    result=$(node -e "
import { sanitizeContent } from '$MCP_DIR/dist/sanitizer.js';
const content = $(python3 -c "import json,sys; print(json.dumps(sys.stdin.read()))" <<< "$content");
const result = sanitizeContent(content);
console.log(JSON.stringify({ modified: result.modified, hasMarker: result.content.includes('$marker'), severity: result.scan.severity }));
" 2>/dev/null)

    local modified has_marker
    modified=$(echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(str(d.get('modified','')).lower())" 2>/dev/null)
    has_marker=$(echo "$result" | python3 -c "import json,sys; d=json.load(sys.stdin); print(str(d.get('hasMarker','')).lower())" 2>/dev/null)

    if [[ "$modified" == "$should_modify" ]]; then
        if [[ "$should_modify" == "true" ]] && [[ "$has_marker" == "true" ]]; then
            pass "$label: sanitized with $marker marker"
        elif [[ "$should_modify" == "false" ]]; then
            pass "$label: passed through unchanged"
        else
            fail "$label: modified but missing $marker marker" "$result"
        fi
    else
        fail "$label: expected modified=$should_modify, got $modified" "$result"
    fi
}

echo "=== Layer 3: MCP Proxy Tests ==="
echo ""

echo "--- Scanner Tests (pattern matching) ---"

# Test HIGH severity payloads
for f in "$PAYLOADS_DIR"/obvious-injection.json "$PAYLOADS_DIR"/role-injection.json \
         "$PAYLOADS_DIR"/system-impersonation.json "$PAYLOADS_DIR"/multi-signal-high.json \
         "$PAYLOADS_DIR"/tool-manipulation.json "$PAYLOADS_DIR"/credential-exfil.json; do
    name=$(basename "$f" .json)
    content=$(python3 -c "import json; d=json.load(open('$f')); r=d.get('tool_result',{}); print(r.get('content','') if isinstance(r,dict) else str(r))")
    test_scanner "$content" "HIGH" "scanner/$name"
done

# Test MED severity
content=$(python3 -c "import json; d=json.load(open('$PAYLOADS_DIR/encoded-base64.json')); r=d.get('tool_result',{}); print(r.get('content','') if isinstance(r,dict) else str(r))")
test_scanner "$content" "MED" "scanner/encoded-base64"

# Test benign (NONE)
for f in "$BENIGN_DIR"/normal-github-issue.json "$BENIGN_DIR"/git-log-output.json \
         "$BENIGN_DIR"/documentation-page.json; do
    name=$(basename "$f" .json)
    content=$(python3 -c "import json; d=json.load(open('$f')); r=d.get('tool_result',{}); print(r.get('content','') if isinstance(r,dict) else str(r))")
    test_scanner "$content" "NONE" "scanner/$name"
done

echo ""
echo "--- Sanitizer Tests (content modification) ---"

# HIGH → should be modified with REDACTED marker
content=$(python3 -c "import json; d=json.load(open('$PAYLOADS_DIR/obvious-injection.json')); r=d.get('tool_result',{}); print(r.get('content','') if isinstance(r,dict) else str(r))")
test_sanitizer "$content" "true" "REDACTED" "sanitizer/obvious-injection"

# HIGH → should preserve non-malicious lines
result=$(node -e "
import { sanitizeContent } from '$MCP_DIR/dist/sanitizer.js';
import { readFileSync } from 'fs';
const data = JSON.parse(readFileSync('$PAYLOADS_DIR/obvious-injection.json', 'utf-8'));
const content = typeof data.tool_result === 'object' ? data.tool_result.content : data.tool_result;
const result = sanitizeContent(content);
const hasLegitimate = result.content.includes('npm install');
console.log(JSON.stringify({ hasLegitimate }));
" 2>/dev/null)
has_legit=$(echo "$result" | python3 -c "import json,sys; print(str(json.load(sys.stdin).get('hasLegitimate','')).lower())" 2>/dev/null)
if [[ "$has_legit" == "true" ]]; then
    pass "sanitizer/preserves-legitimate: kept non-malicious content"
else
    fail "sanitizer/preserves-legitimate: lost legitimate content" "$result"
fi

# MED → should be modified with SEC-WARNING marker
content=$(python3 -c "import json; d=json.load(open('$PAYLOADS_DIR/encoded-base64.json')); r=d.get('tool_result',{}); print(r.get('content','') if isinstance(r,dict) else str(r))")
test_sanitizer "$content" "true" "SEC-WARNING" "sanitizer/encoded-base64"

# Benign → should NOT be modified
content=$(python3 -c "import json; d=json.load(open('$BENIGN_DIR/normal-github-issue.json')); r=d.get('tool_result',{}); print(r.get('content','') if isinstance(r,dict) else str(r))")
test_sanitizer "$content" "false" "" "sanitizer/normal-github-issue"

echo ""
echo "--- Layer 3 Summary: $PASSED/$TOTAL passed, $FAILED failed ---"
exit $((FAILED > 0 ? 1 : 0))
