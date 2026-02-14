#!/usr/bin/env bash
# claude-guard — Scan cache and session buffer library
# Sourced by injection-guard.sh

# --- Scan Cache ---

# Compute SHA-256 hash of content
compute_content_hash() {
    printf '%s' "$1" | sha256sum | cut -d' ' -f1
}

# Check scan cache for a content hash
# Returns 0 if cache hit (sets CACHE_HIT_SEVERITY, CACHE_HIT_CATEGORIES, CACHE_HIT_INDICATORS,
#   and optionally CACHE_HIT_L2_EXECUTED, CACHE_HIT_L2_SEVERITY, CACHE_HIT_L2_REASONING, CACHE_HIT_L2_CONFIDENCE)
# Returns 1 if cache miss
check_scan_cache() {
    local content_hash="$1"
    local cache_file="${SCAN_CACHE_FILE:-}"
    cache_file="${cache_file/#\~/$HOME}"
    local cache_ttl="${SCAN_CACHE_TTL:-300}"

    CACHE_HIT_SEVERITY=""
    CACHE_HIT_CATEGORIES=""
    CACHE_HIT_INDICATORS=""
    CACHE_HIT_L2_EXECUTED=""
    CACHE_HIT_L2_SEVERITY=""
    CACHE_HIT_L2_REASONING=""
    CACHE_HIT_L2_CONFIDENCE=""

    [[ "${ENABLE_SCAN_CACHE:-true}" != "true" ]] && return 1
    [[ -z "$cache_file" ]] && return 1
    [[ -f "$cache_file" ]] || return 1

    local result
    result=$(python3 -c "
import json, sys, time

try:
    with open(sys.argv[1]) as f:
        cache = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    sys.exit(1)

h = sys.argv[2]
ttl = int(sys.argv[3])
now = time.time()

entry = cache.get(h)
if not entry:
    sys.exit(1)

if now - entry.get('ts', 0) > ttl:
    sys.exit(1)

print(entry.get('severity', 'NONE'))
print(entry.get('categories', ''))
print(entry.get('indicators', ''))
print(entry.get('l2_executed', 'false'))
print(entry.get('l2_severity', ''))
print(entry.get('l2_reasoning', ''))
print(entry.get('l2_confidence', ''))
sys.exit(0)
" "$cache_file" "$content_hash" "$cache_ttl" 2>/dev/null)

    if [[ $? -eq 0 ]] && [[ -n "$result" ]]; then
        CACHE_HIT_SEVERITY=$(sed -n '1p' <<< "$result")
        CACHE_HIT_CATEGORIES=$(sed -n '2p' <<< "$result")
        CACHE_HIT_INDICATORS=$(sed -n '3p' <<< "$result")
        CACHE_HIT_L2_EXECUTED=$(sed -n '4p' <<< "$result")
        CACHE_HIT_L2_SEVERITY=$(sed -n '5p' <<< "$result")
        CACHE_HIT_L2_REASONING=$(sed -n '6p' <<< "$result")
        CACHE_HIT_L2_CONFIDENCE=$(sed -n '7p' <<< "$result")
        return 0
    fi
    return 1
}

# Update scan cache with a new result
# Args: hash severity categories indicators [l2_executed l2_severity l2_reasoning l2_confidence]
update_scan_cache() {
    local content_hash="$1" severity="$2" categories="$3" indicators="$4"
    local l2_executed="${5:-false}" l2_severity="${6:-}" l2_reasoning="${7:-}" l2_confidence="${8:-}"
    local cache_file="${SCAN_CACHE_FILE:-}"
    cache_file="${cache_file/#\~/$HOME}"
    local cache_ttl="${SCAN_CACHE_TTL:-300}"

    [[ "${ENABLE_SCAN_CACHE:-true}" != "true" ]] && return 0
    [[ -z "$cache_file" ]] && return 0

    # Truncate reasoning to 200 chars to prevent unbounded cache growth
    l2_reasoning="${l2_reasoning:0:200}"

    local cache_dir
    cache_dir="$(dirname "$cache_file")"
    [[ -d "$cache_dir" ]] || mkdir -p "$cache_dir"

    (
        if ! flock -w 5 200; then
            return 1
        fi

        python3 -c "
import json, sys, os, time, tempfile

cache_file = sys.argv[1]
h = sys.argv[2]
severity = sys.argv[3]
categories = sys.argv[4]
indicators = sys.argv[5]
ttl = int(sys.argv[6])
l2_executed = sys.argv[7]
l2_severity = sys.argv[8]
l2_reasoning = sys.argv[9]
l2_confidence = sys.argv[10]
now = time.time()

try:
    with open(cache_file) as f:
        cache = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    cache = {}

# Prune expired entries
cache = {k: v for k, v in cache.items() if now - v.get('ts', 0) <= ttl}

# Add new entry
entry = {
    'ts': now,
    'severity': severity,
    'categories': categories,
    'indicators': indicators
}

# Include L2 metadata if LLM was executed
if l2_executed == 'true':
    entry['l2_executed'] = 'true'
    entry['l2_severity'] = l2_severity
    entry['l2_reasoning'] = l2_reasoning
    entry['l2_confidence'] = l2_confidence

cache[h] = entry

# Write atomically
with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=os.path.dirname(cache_file) or '.') as tmp:
    json.dump(cache, tmp)
    tmp_name = tmp.name
os.rename(tmp_name, cache_file)
" "$cache_file" "$content_hash" "$severity" "$categories" "$indicators" "$cache_ttl" \
  "$l2_executed" "$l2_severity" "$l2_reasoning" "$l2_confidence" 2>/dev/null

    ) 200>"${cache_file}.lock"
}

# --- Session Buffer (Split Payload Detection) ---

# Update session buffer with new tool output
update_session_buffer() {
    local content="$1"
    local buffer_file="${SESSION_BUFFER_FILE:-}"
    buffer_file="${buffer_file/#\~/$HOME}"
    local buffer_size="${SESSION_BUFFER_SIZE:-5}"
    local buffer_ttl="${SESSION_BUFFER_TTL:-60}"

    [[ "${ENABLE_SESSION_BUFFER:-true}" != "true" ]] && return 0
    [[ -z "$buffer_file" ]] && return 0

    local buffer_dir
    buffer_dir="$(dirname "$buffer_file")"
    [[ -d "$buffer_dir" ]] || mkdir -p "$buffer_dir"

    # Truncate content to 2000 chars
    local truncated="${content:0:2000}"

    (
        if ! flock -w 5 200; then
            return 1
        fi

        python3 -c "
import json, sys, os, time, tempfile

buffer_file = sys.argv[1]
content = sys.stdin.read()
max_size = int(sys.argv[2])
ttl = int(sys.argv[3])
now = time.time()

try:
    with open(buffer_file) as f:
        buffer = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    buffer = []

# Prune expired entries
buffer = [e for e in buffer if now - e.get('ts', 0) <= ttl]

# Add new entry
buffer.append({'ts': now, 'content': content})

# Keep only last N entries
buffer = buffer[-max_size:]

# Write atomically
with tempfile.NamedTemporaryFile(mode='w', delete=False, dir=os.path.dirname(buffer_file) or '.') as tmp:
    json.dump(buffer, tmp)
    tmp_name = tmp.name
os.rename(tmp_name, buffer_file)
" "$buffer_file" "$buffer_size" "$buffer_ttl" <<< "$truncated" 2>/dev/null

    ) 200>"${buffer_file}.lock"
}

# Get concatenated buffer content for multi-turn scanning
get_concatenated_buffer() {
    local buffer_file="${SESSION_BUFFER_FILE:-}"
    buffer_file="${buffer_file/#\~/$HOME}"
    local buffer_ttl="${SESSION_BUFFER_TTL:-60}"

    [[ "${ENABLE_SESSION_BUFFER:-true}" != "true" ]] && return 1
    [[ -z "$buffer_file" ]] && return 1
    [[ -f "$buffer_file" ]] || return 1

    python3 -c "
import json, sys, time

buffer_file = sys.argv[1]
ttl = int(sys.argv[2])
now = time.time()

try:
    with open(buffer_file) as f:
        buffer = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    sys.exit(1)

# Filter valid entries and concatenate (strip trailing whitespace from here-string)
parts = [e['content'].strip() for e in buffer if now - e.get('ts', 0) <= ttl and e.get('content')]
if len(parts) < 2:
    sys.exit(1)  # Need at least 2 entries for multi-turn detection

print(' '.join(parts))
" "$buffer_file" "$buffer_ttl" 2>/dev/null
}
