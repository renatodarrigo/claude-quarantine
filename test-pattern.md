You are interactively testing a new detection pattern for claude-guard. Your job is to help the user craft a pattern, validate it against existing test fixtures, check for false positives, and optionally add it to the pattern configuration.

## File locations

Check project-level first, then fall back to user-level:

- **Pattern file**: `.claude/hooks/injection-patterns.conf` (project) or `~/.claude/hooks/injection-patterns.conf` (user)
- **Payload fixtures**: `tests/fixtures/payloads/*.json` in the claude-guard repo
- **Benign fixtures**: `tests/fixtures/benign/*.json` in the claude-guard repo

To locate fixtures: first check if the current directory is inside the claude-guard repo by looking for `tests/fixtures/` relative to the repo root. If running from an installed location, check `~/.claude/hooks/` for the pattern file and look for fixtures at the source repo path. If fixtures cannot be found, skip fixture testing and note this to the user.

## Procedure

1. **Gather pattern details** — ask the user for the following information. Use AskUserQuestion for structured input:

   a. **Regex pattern**: Ask the user to provide the regex pattern (Extended Regular Expression syntax, applied case-insensitively). Example: `ignore (all )?(previous|prior) instructions`

   b. **Category name**: Use AskUserQuestion to ask for the category. Suggest existing categories from the current pattern file (read it first to extract unique category names). Allow the user to type a custom category. Examples of existing categories: `system_impersonation`, `role_injection`, `instruction_override`, `tool_manipulation`, `credential_exfil`, `unicode_obfuscation`, `encoded_payload`, `social_engineering`.

   c. **Severity**: Use AskUserQuestion with options `HIGH`, `MED`, `LOW`. Provide guidance:
      - HIGH: Direct injection attempts, credential exfiltration, system impersonation
      - MED: Indirect manipulation, social engineering, encoded payloads
      - LOW: Suspicious but likely benign, informational

   d. **Sample text** (optional): Ask if the user wants to provide sample text to test the pattern against immediately.

2. **Validate regex syntax** — attempt to compile the regex. If it has syntax errors, report the error clearly and ask the user to fix it. Do not proceed until the regex is valid. To validate, use a bash command: `echo "test" | grep -iE '{pattern}' > /dev/null 2>&1; echo $?` — exit code 0 or 1 means valid syntax, exit code 2 means invalid regex.

3. **Test against sample text** — if the user provided sample text:
   - Run the regex against the sample text
   - Report: MATCH or NO MATCH
   - If NO MATCH, ask the user if they want to adjust the pattern
   - Show what part of the text matched (if possible, show the matched substring)

4. **Test against payload fixtures** — scan all files in `tests/fixtures/payloads/`:
   - Each fixture is a JSON file representing a tool call input (has a `tool_input` or `content` field with the text to scan)
   - For each fixture file, read the JSON content, extract the scannable text fields, and test the regex against them
   - Count: matched N out of M payload fixtures
   - List which payload fixtures matched (by filename)
   - A higher match count here is better (true positives)

5. **Test against benign fixtures** — scan all files in `tests/fixtures/benign/`:
   - Same format as payload fixtures
   - For each fixture file, test the regex against the scannable text
   - Count: matched N out of M benign fixtures (these are FALSE POSITIVES)
   - List which benign fixtures matched (by filename) — these are problematic
   - A match count of 0 here is ideal

6. **Report results** — display a formatted summary:

```
===== Pattern Test Results =====

Pattern:  {category}:{severity}:{pattern}

--- Sample Text ---
Result: {MATCH / NO MATCH / not provided}

--- Payload Fixtures (True Positives) ---
Matched: {N}/{M} payloads
  [list matched filenames]

--- Benign Fixtures (False Positives) ---
Matched: {N}/{M} benign  {show WARNING if N > 0}
  [list matched filenames if any]

--- Assessment ---
{verdict}
```

   For the verdict:
   - If 0 false positives and at least 1 true positive: "Pattern looks good. Ready to add."
   - If 0 false positives and 0 true positives: "Pattern has no false positives but also matched no known payloads. Consider testing with sample text."
   - If any false positives: "WARNING: Pattern matches {N} benign fixture(s). Review and narrow the pattern before adding."

7. **Offer to add pattern** — only if the false positive count is 0:
   - Format the pattern line: `{category}:{severity}:{pattern}`
   - Show the user exactly what will be appended to the pattern file
   - Show where it will be added (which pattern file, at the end of the file)
   - Use AskUserQuestion to confirm: "Add this pattern to {pattern_file}?" with options "Add", "Edit first", "Cancel"
   - If "Add": append the line to the pattern file (add a blank line before if the file doesn't end with one)
   - If "Edit first": ask the user for the modified pattern line and repeat from step 2
   - If "Cancel": stop

   If false positives exist, do NOT offer to add. Instead suggest the user refine the pattern and run `/test-pattern` again.

8. **Duplicate check** — before appending, read the current pattern file and check if an identical or very similar pattern already exists (same category and same regex). If a duplicate is found, warn the user and ask if they still want to add it.

## Important rules

- Always apply regex patterns case-insensitively (this matches how claude-guard applies them at runtime).
- When reading fixture files, handle both possible JSON structures: `{"tool_input": {"content": "..."}}` and `{"content": "..."}` and any nested string fields. Extract all string values and test the pattern against each.
- If the `tests/fixtures/` directory does not exist or contains no files, skip fixture testing entirely and note: "No test fixtures found. Pattern was tested against sample text only."
- Do NOT modify the pattern file without explicit user confirmation via AskUserQuestion.
- When appending to the pattern file, add a comment line above the new pattern: `# Added via /test-pattern on {current date}`
- Keep the regex in ERE (Extended Regular Expression) format. Do not convert to PCRE or other flavors.
- If the user provides a pattern that is too broad (e.g., matches common English words), warn them even if fixtures pass, based on your judgment.
