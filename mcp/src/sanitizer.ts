import { scanContent, type ScanResult, type Severity } from "./scanner.js";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import { resolve, dirname } from "path";

export type SanitizeStrategy = "redact" | "annotate" | "quarantine" | "passthrough";

export interface SanitizeResult {
  content: string;
  scan: ScanResult;
  modified: boolean;
  quarantineFile?: string;
}

// Load config values
function getGuardMode(): string {
  return process.env.GUARD_MODE || "enforce";
}

function getSanitizeStrategy(severity: Severity): SanitizeStrategy {
  if (severity === "HIGH") {
    return (process.env.SANITIZE_HIGH || "redact") as SanitizeStrategy;
  }
  if (severity === "MED") {
    return (process.env.SANITIZE_MED || "annotate") as SanitizeStrategy;
  }
  return "passthrough";
}

function getQuarantineDir(): string {
  const dir = process.env.QUARANTINE_DIR || resolve(process.env.HOME || "~", ".claude/hooks/quarantine");
  return dir.replace(/^~/, process.env.HOME || "~");
}

function getCategoryAction(category: string): string | undefined {
  return process.env[`ACTION_${category}`];
}

// Determine effective strategy based on category overrides
function getEffectiveStrategy(scan: ScanResult): SanitizeStrategy {
  const mode = getGuardMode();

  // In audit mode, annotate (never redact)
  if (mode === "audit") {
    if (scan.severity === "HIGH" || scan.severity === "MED") {
      return "annotate";
    }
    return "passthrough";
  }

  // Check per-category action overrides
  let mostRestrictive: SanitizeStrategy = "passthrough";
  let hasCategoryOverride = false;

  for (const cat of scan.categories) {
    const action = getCategoryAction(cat);
    if (action) {
      hasCategoryOverride = true;
      if (action === "block") {
        mostRestrictive = "redact"; // block → redact in MCP context
      } else if (action === "warn" && mostRestrictive !== "redact") {
        mostRestrictive = "annotate";
      }
      // silent → passthrough (no change needed)
    }
  }

  if (hasCategoryOverride) {
    return mostRestrictive;
  }

  // Fall back to severity-based strategy
  return getSanitizeStrategy(scan.severity);
}

/**
 * Sanitize content based on scan results.
 * Strategy dispatched per config: redact | annotate | quarantine | passthrough
 */
export function sanitizeContent(
  content: string,
  patternsFile?: string
): SanitizeResult {
  const scan = scanContent(content, patternsFile);

  if (scan.severity === "NONE" || scan.severity === "LOW") {
    return { content, scan, modified: false };
  }

  const strategy = getEffectiveStrategy(scan);

  switch (strategy) {
    case "redact":
      return sanitizeRedact(content, scan);
    case "annotate":
      return sanitizeAnnotate(content, scan);
    case "quarantine":
      return sanitizeQuarantine(content, scan);
    case "passthrough":
      return { content, scan, modified: false };
    default:
      // Fallback to severity-based default
      if (scan.severity === "HIGH") return sanitizeRedact(content, scan);
      return sanitizeAnnotate(content, scan);
  }
}

function sanitizeRedact(content: string, scan: ScanResult): SanitizeResult {
  // For HIGH threats, we identify and redact the suspicious portions.
  // Strategy: Split content into lines, redact lines that contain matches.
  const lines = content.split("\n");
  const redactedLines: string[] = [];
  let redactedCount = 0;

  // Build a combined regex from HIGH-severity indicators
  const highMatches = scan.matches
    .filter((m) => m.severity === "HIGH")
    .map((m) => escapeRegex(m.match));

  // Also include MED matches since the overall severity is HIGH
  const medMatches = scan.matches
    .filter((m) => m.severity === "MED")
    .map((m) => escapeRegex(m.match));

  const allMatchPatterns = [...highMatches, ...medMatches].filter(Boolean);

  if (allMatchPatterns.length === 0) {
    // Fallback: redact entire content
    const summary = scan.categories.join(", ");
    return {
      content: `[REDACTED — potential prompt injection detected. ${content.length} characters removed. Threat indicators: ${summary}]`,
      scan,
      modified: true,
    };
  }

  const matchRegex = new RegExp(
    allMatchPatterns.map((p) => `(?:${p})`).join("|"),
    "i"
  );

  for (const line of lines) {
    if (matchRegex.test(line)) {
      redactedCount += line.length;
      redactedLines.push(
        `[REDACTED — line removed, potential prompt injection]`
      );
    } else {
      redactedLines.push(line);
    }
  }

  const sanitized = redactedLines.join("\n");
  const summary = scan.categories.join(", ");

  // Prepend a warning header
  const header = `[SECURITY NOTICE: ${redactedCount} characters redacted from ${scan.matches.length} suspicious sections. Categories: ${summary}]\n\n`;

  return {
    content: header + sanitized,
    scan,
    modified: true,
  };
}

function sanitizeAnnotate(content: string, scan: ScanResult): SanitizeResult {
  // For MED threats (or audit mode), annotate suspicious lines but don't remove them
  const lines = content.split("\n");
  const annotatedLines: string[] = [];

  const allMatches = scan.matches.map((m) => escapeRegex(m.match)).filter(Boolean);

  if (allMatches.length === 0) {
    return { content, scan, modified: false };
  }

  const matchRegex = new RegExp(
    allMatches.map((p) => `(?:${p})`).join("|"),
    "i"
  );

  let inWarningBlock = false;
  for (const line of lines) {
    if (matchRegex.test(line)) {
      if (!inWarningBlock) {
        annotatedLines.push(
          "[SEC-WARNING: the following content contains suspicious directives]"
        );
        inWarningBlock = true;
      }
      annotatedLines.push(line);
    } else {
      if (inWarningBlock) {
        annotatedLines.push("[/SEC-WARNING]");
        inWarningBlock = false;
      }
      annotatedLines.push(line);
    }
  }

  if (inWarningBlock) {
    annotatedLines.push("[/SEC-WARNING]");
  }

  return {
    content: annotatedLines.join("\n"),
    scan,
    modified: true,
  };
}

function sanitizeQuarantine(content: string, scan: ScanResult): SanitizeResult {
  const quarantineDir = getQuarantineDir();

  // Ensure quarantine directory exists
  try {
    if (!existsSync(quarantineDir)) {
      mkdirSync(quarantineDir, { recursive: true });
    }
  } catch (err) {
    console.error(`[guard] Failed to create quarantine dir: ${quarantineDir}`, err);
    // Fall back to redact
    return sanitizeRedact(content, scan);
  }

  // Generate quarantine filename
  const timestamp = new Date().toISOString().replace(/[:.]/g, "-");
  const hash = Math.random().toString(36).slice(2, 10);
  const quarantineFile = resolve(quarantineDir, `${timestamp}-${hash}.txt`);

  // Write quarantined content with metadata header
  const metadata = [
    `# Quarantined by claude-guard`,
    `# Timestamp: ${new Date().toISOString()}`,
    `# Severity: ${scan.severity}`,
    `# Categories: ${scan.categories.join(", ")}`,
    `# Indicators: ${scan.indicators.join(", ")}`,
    `---`,
    content,
  ].join("\n");

  try {
    writeFileSync(quarantineFile, metadata, "utf-8");
  } catch (err) {
    console.error(`[guard] Failed to write quarantine file: ${quarantineFile}`, err);
    return sanitizeRedact(content, scan);
  }

  // Return redacted version with quarantine reference
  const summary = scan.categories.join(", ");
  const redactedContent = `[QUARANTINED — ${content.length} characters quarantined to ${quarantineFile}. Severity: ${scan.severity}. Categories: ${summary}. Review quarantined file before use.]`;

  return {
    content: redactedContent,
    scan,
    modified: true,
    quarantineFile,
  };
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
