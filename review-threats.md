You are reviewing the claude-quarantine threat detection log. Your job is to present flagged entries to the user for triage: they confirm real threats or dismiss false positives.

## File locations

Check project-level first, then fall back to user-level:

- **Log file (JSONL)**: `.claude/hooks/injection-guard.log` (project) or `~/.claude/hooks/injection-guard.log` (user)
- **Confirmed threats store**: `.claude/hooks/confirmed-threats.json` (project) or `~/.claude/hooks/confirmed-threats.json` (user)

To determine which to use: check if `.claude/hooks/injection-guard.log` exists. If so, use the `.claude/hooks/` paths. Otherwise, use `~/.claude/hooks/` paths.

## Procedure

1. **Read** the log file (project-level first, then user-level). Each line is a JSON object with fields: `id`, `timestamp`, `tool`, `severity`, `categories`, `indicators`, `snippet`, `status`. Optionally includes `layer2` object with `executed`, `severity`, `reasoning`, `confidence` fields. Filter for entries where `status` is `"unreviewed"`.

2. **Count** unreviewed entries. If there are none, tell the user "No unreviewed threats in the log." and stop.

3. **Paginate**: Show entries **5 at a time**. For each entry, display a compact summary:

```
[{id}] {severity} | {timestamp} | tool: {tool}
  Categories: {categories joined}
  Indicators: {indicators joined}
  Snippet: {snippet, truncated to ~200 chars}
  Layer 2: {if layer2.executed: "severity={layer2.severity} confidence={layer2.confidence} — {layer2.reasoning}"}
```

4. **Ask the user** to review the batch using AskUserQuestion. For each entry in the current batch, ask whether it is a **real threat** or a **false positive**. Use multiSelect so the user can select which entries are real threats (unselected = false positive).

5. **Process responses**:
   - **Confirmed threats**: Read the current confirmed threats file (create as `[]` if missing). Append a new entry for each confirmed threat:
     ```json
     {
       "id": "<original log entry id>",
       "confirmed_at": "<current ISO timestamp>",
       "severity": "<original severity>",
       "categories": ["<original categories>"],
       "indicators": ["<original indicators>"],
       "snippet": "<original snippet>"
     }
     ```
     Write the updated array back to the file.
   - **False positives**: Simply mark as dismissed (no storage needed).
   - **Update the log**: Rewrite the log file with the status of each processed entry changed to `"confirmed"` or `"dismissed"`. This removes them from future reviews.

6. **Repeat** for the next batch of 5 until all unreviewed entries are processed.

7. **Summary**: At the end, report:
   - Total reviewed: N
   - Confirmed threats: N (added to confirmed-threats.json)
   - Dismissed (false positives): N (removed from log)
   - Remaining unreviewed: N

## Important rules

- Do NOT dump the entire log into your response. Only show the current batch of up to 5 entries.
- Keep snippet display short (~200 chars max) to minimize context usage.
- When rewriting the log file, preserve ALL entries (confirmed, dismissed, and any remaining unreviewed). Only change the `status` field.
- The confirmed-threats.json file is an array at the top level. Read-modify-write it atomically.
- If the log file doesn't exist in either location, tell the user no detections have been recorded yet.
