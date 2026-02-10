import { scanContent, type ScanResult, type Severity } from "./scanner.js";

export interface SanitizeResult {
  content: string;
  scan: ScanResult;
  modified: boolean;
}

/**
 * Sanitize content based on scan results.
 *
 * HIGH threat: Replace suspicious sections with [REDACTED] markers
 * MED threat: Annotate suspicious sections with [SEC-WARNING] markers
 * LOW/NONE: Pass through unchanged
 */
export function sanitizeContent(
  content: string,
  patternsFile?: string
): SanitizeResult {
  const scan = scanContent(content, patternsFile);

  if (scan.severity === "NONE" || scan.severity === "LOW") {
    return { content, scan, modified: false };
  }

  if (scan.severity === "HIGH") {
    return sanitizeHigh(content, scan);
  }

  // MED
  return sanitizeMed(content, scan);
}

function sanitizeHigh(content: string, scan: ScanResult): SanitizeResult {
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

function sanitizeMed(content: string, scan: ScanResult): SanitizeResult {
  // For MED threats, annotate suspicious lines but don't remove them
  const lines = content.split("\n");
  const annotatedLines: string[] = [];

  const medMatches = scan.matches.map((m) => escapeRegex(m.match)).filter(Boolean);

  if (medMatches.length === 0) {
    return { content, scan, modified: false };
  }

  const matchRegex = new RegExp(
    medMatches.map((p) => `(?:${p})`).join("|"),
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

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
