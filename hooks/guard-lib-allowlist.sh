#!/usr/bin/env bash
# claude-guard — Allowlist loading and matching library
# Sourced by injection-guard.sh

# Global allowlist patterns array
declare -a ALLOWLIST_PATTERNS=()

# Load allowlist from file
load_allowlist() {
    local file="${ALLOWLIST_FILE:-}"
    file="${file/#\~/$HOME}"

    ALLOWLIST_PATTERNS=()

    [[ -z "$file" ]] && return 0
    [[ -f "$file" ]] || return 0

    while IFS= read -r line; do
        line="${line%%#*}"     # strip comments
        line="${line// /}"     # strip spaces
        [[ -z "$line" ]] && continue
        ALLOWLIST_PATTERNS+=("$line")
    done < "$file"
}

# Check if a URL matches the allowlist
# Returns 0 if allowlisted (should skip scanning), 1 otherwise
is_allowlisted() {
    local url="$1"

    [[ ${#ALLOWLIST_PATTERNS[@]} -eq 0 ]] && return 1

    # Extract host and port from URL
    local host=""
    host=$(printf '%s' "$url" | sed -n 's|^https\?://\([^/]*\).*|\1|p')
    [[ -z "$host" ]] && return 1

    for pattern in "${ALLOWLIST_PATTERNS[@]}"; do
        # Exact URL match
        if [[ "$url" == "$pattern" ]]; then
            return 0
        fi

        # Wildcard domain match: *.example.com
        if [[ "$pattern" == \*.* ]]; then
            local domain_suffix="${pattern#\*}"
            # Match host ending with the suffix (e.g., *.github.com matches api.github.com)
            if [[ "$host" == *"$domain_suffix" ]] || [[ ".$host" == *"$domain_suffix" ]]; then
                return 0
            fi
        fi

        # Port wildcard: localhost:*
        if [[ "$pattern" == *:\* ]]; then
            local pattern_host="${pattern%%:\*}"
            local host_only="${host%%:*}"
            if [[ "$host_only" == "$pattern_host" ]]; then
                return 0
            fi
        fi

        # Exact host match (no wildcard)
        if [[ "$host" == "$pattern" ]]; then
            return 0
        fi
    done

    return 1
}
