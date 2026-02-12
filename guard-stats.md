You are generating a security dashboard from the claude-guard detection log and rate-limit state. Your job is to parse all log data and present a comprehensive overview of guard activity.

## File locations

Check project-level first, then fall back to user-level:

- **Log file (JSONL)**: `.claude/hooks/injection-guard.log` (project) or `~/.claude/hooks/injection-guard.log` (user)
- **Rotated logs**: Same path with `.1`, `.2`, `.3` suffixes (e.g., `injection-guard.log.1`)
- **Rate limit state**: `.claude/hooks/rate-limit-state.json` (project) or `~/.claude/hooks/rate-limit-state.json` (user)
- **Config file**: `.claude/hooks/injection-guard.conf` (project) or `~/.claude/hooks/injection-guard.conf` (user)

To determine which to use: check if `.claude/hooks/injection-guard.log` exists. If so, use the `.claude/hooks/` paths. Otherwise, use `~/.claude/hooks/` paths.

## Procedure

1. **Locate files** — check for the log file at the project-level path first, then user-level. Record which location is active. If neither exists, tell the user "No detections recorded yet. The log file will be created when claude-guard first detects a threat." and stop.

2. **Read all log files** — read the primary log file and any rotated files (`.log.1`, `.log.2`, `.log.3`) that exist. Each line in each file is a JSON object with fields: `id`, `timestamp`, `tool`, `severity`, `categories`, `indicators`, `snippet`, `status`, and optionally `mode` (audit/enforce) and `layer2` object. Collect all entries into a single list. If a rotated file does not exist, skip it silently.

3. **Read rate limit state** — read `rate-limit-state.json` from the same location. Parse the JSON. It has structure `{"sources": {...}, "version": 1}` where each source entry contains `source_id`, `source_type`, `blocked_until`, `violation_count`, `backoff_level`, `first_violation`, `last_violation`. If the file does not exist, note "Rate limiting: no state file found".

4. **Read config** — read `injection-guard.conf` to determine the current `GUARD_MODE` setting (enforce or audit).

5. **Calculate statistics** from all collected log entries:

   - **Total scans**: count of all log lines across all files (primary + rotated)
   - **Threats by severity**: count entries grouped by `severity` field (HIGH, MED, LOW)
   - **Threats by category**: count entries grouped by each value in the `categories` array; show top categories sorted by count descending
   - **False positive rate**: count entries with `status="dismissed"` divided by (count `status="confirmed"` + count `status="dismissed"`). If no confirmed or dismissed entries exist, show "N/A (no reviewed entries)"
   - **Top 5 triggered patterns**: count occurrences of each value in the `indicators` arrays across all entries; show the top 5 by frequency
   - **Time breakdowns**: group entries by `timestamp` into buckets: last 24 hours, last 7 days, last 30 days, and all-time. Show total count for each bucket
   - **Log file sizes**: report the size of each log file (primary + rotated) and the total count of rotated files found
   - **Audit vs enforce split**: count entries where `mode` field equals `"audit"` vs entries without `mode` or with `mode="enforce"`. Show as a ratio
   - **Status breakdown**: count entries by `status` field (unreviewed, confirmed, dismissed)

6. **Calculate rate limit statistics** from the state file:

   - **Active blocks**: count sources where `blocked_until` is in the future (compare to current time)
   - **Total sources tracked**: count of all entries in `sources`
   - **Highest backoff level**: the maximum `backoff_level` across all sources
   - **Total violations**: sum of all `violation_count` values

7. **Format as a dashboard** — present the results in a clean, readable format:

```
===== Claude Guard Security Dashboard =====
Mode: {GUARD_MODE} | Log: {path_used}

--- Scan Summary ---
Total scans:       {total}
  Last 24h:        {24h_count}
  Last 7d:         {7d_count}
  Last 30d:        {30d_count}

--- Severity Breakdown ---
  HIGH:  {high_count}  ({high_pct}%)
  MED:   {med_count}   ({med_pct}%)
  LOW:   {low_count}   ({low_pct}%)

--- Top Categories ---
  1. {category}  ({count})
  2. {category}  ({count})
  ...

--- Top 5 Triggered Patterns ---
  1. {indicator}  ({count} hits)
  2. {indicator}  ({count} hits)
  ...

--- Review Status ---
  Unreviewed:  {count}
  Confirmed:   {count}
  Dismissed:   {count}
  False positive rate: {rate}%

--- Audit vs Enforce ---
  Audit mode entries:   {count}
  Enforce mode entries: {count}

--- Rate Limiting ---
  Active blocks:     {count}
  Total sources:     {count}
  Highest backoff:   level {n}
  Total violations:  {count}

--- Log Files ---
  Primary:  {filename}  ({size})
  Rotated:  {count} files ({total_size})
```

8. **Highlight actionable items** — after the dashboard, add notes if any of these conditions are true:
   - If there are unreviewed entries, suggest: "Run /review-threats to triage {N} unreviewed detections."
   - If false positive rate is above 20%, suggest: "High false positive rate ({rate}%). Consider tuning patterns with /test-pattern."
   - If there are active rate limit blocks, list the blocked sources and their `blocked_until` times.
   - If the primary log file size exceeds 5MB, suggest: "Log file is large. Rotation will occur automatically at {LOG_MAX_SIZE}."

## Important rules

- Do NOT dump raw log entries. This is a summary dashboard only.
- When calculating time breakdowns, use the `timestamp` field from each entry and compare to the current time. Use ISO 8601 format for parsing.
- If any file read fails (permissions, corruption), report the error for that section and continue with the remaining sections. Do not abort the entire dashboard.
- Keep the output compact. Use fixed-width alignment for the dashboard numbers.
- Round percentages to one decimal place.
- If the total scan count is 0 (empty log files), display the dashboard structure but with all zeros and a note: "No detections recorded. Guard is active and monitoring."
