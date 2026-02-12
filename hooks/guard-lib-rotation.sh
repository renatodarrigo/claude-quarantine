#!/usr/bin/env bash
# claude-guard — Log rotation library
# Sourced by injection-guard.sh

# Parse size suffixes (K/M/G) to bytes
parse_size() {
    local size_str="$1"
    local num="${size_str//[^0-9]/}"
    local suffix="${size_str//[0-9]/}"
    suffix="${suffix^^}"  # uppercase

    case "$suffix" in
        K) echo $(( num * 1024 )) ;;
        M) echo $(( num * 1024 * 1024 )) ;;
        G) echo $(( num * 1024 * 1024 * 1024 )) ;;
        *)  echo "$num" ;;
    esac
}

# Check and perform log rotation if needed
check_log_rotation() {
    local log_file="$1"
    local max_size_str="${LOG_MAX_SIZE:-10M}"
    local max_entries="${LOG_MAX_ENTRIES:-10000}"
    local rotate_count="${LOG_ROTATE_COUNT:-3}"

    [[ -f "$log_file" ]] || return 0

    local should_rotate=false

    # Check file size
    local file_size max_bytes
    file_size=$(stat -c%s "$log_file" 2>/dev/null || stat -f%z "$log_file" 2>/dev/null || echo 0)
    max_bytes=$(parse_size "$max_size_str")

    if (( file_size > max_bytes )); then
        should_rotate=true
    fi

    # Check entry count if not already rotating
    if [[ "$should_rotate" != "true" ]]; then
        local entry_count
        entry_count=$(wc -l < "$log_file" 2>/dev/null || echo 0)
        if (( entry_count > max_entries )); then
            should_rotate=true
        fi
    fi

    [[ "$should_rotate" != "true" ]] && return 0

    # Perform rotation under flock
    (
        if ! flock -w 5 200; then
            echo "Warning: Could not acquire lock for log rotation" >&2
            return 1
        fi

        # Rotate: .log.2 → .log.3, .log.1 → .log.2, .log → .log.1
        local i
        for (( i = rotate_count; i > 1; i-- )); do
            local prev=$(( i - 1 ))
            if [[ -f "${log_file}.${prev}" ]]; then
                mv "${log_file}.${prev}" "${log_file}.${i}"
            fi
        done

        # Move current log to .1
        if [[ -f "$log_file" ]]; then
            mv "$log_file" "${log_file}.1"
        fi

        # Delete files beyond rotate count
        for (( i = rotate_count + 1; i <= rotate_count + 5; i++ )); do
            rm -f "${log_file}.${i}"
        done

    ) 200>"${log_file}.rotate.lock"
}
