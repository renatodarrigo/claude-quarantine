import { readFileSync } from "fs";
import { resolve } from "path";

export type Severity = "HIGH" | "MED" | "LOW" | "NONE";

export interface ScanMatch {
  category: string;
  severity: Severity;
  match: string;
}

export interface ScanResult {
  severity: Severity;
  categories: string[];
  indicators: string[];
  matches: ScanMatch[];
  confirmedMatch?: string; // ID of matched confirmed threat
}

interface PatternEntry {
  category: string;
  severity: Severity;
  regex: RegExp;
  raw: string;
}

interface ConfirmedThreat {
  id: string;
  indicators: string[];
  categories: string[];
  severity: string;
  confirmed_at: string;
  snippet: string;
}

const SEVERITY_ORDER: Record<string, number> = {
  NONE: 0,
  LOW: 1,
  MED: 2,
  HIGH: 3,
};

let cachedPatterns: PatternEntry[] | null = null;
let cachedThreats: ConfirmedThreat[] | null = null;
let threatsModTime = 0;

function loadPatterns(patternsFile?: string): PatternEntry[] {
  if (cachedPatterns) return cachedPatterns;

  const file =
    patternsFile ||
    process.env.GUARD_PATTERNS ||
    resolve(process.env.HOME || "~", ".claude/hooks/injection-patterns.conf");

  let content: string;
  try {
    content = readFileSync(file, "utf-8");
  } catch {
    console.error(`[quarantine] Could not load patterns from ${file}`);
    return [];
  }

  const patterns: PatternEntry[] = [];
  for (const line of content.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) continue;

    const firstColon = trimmed.indexOf(":");
    if (firstColon === -1) continue;
    const secondColon = trimmed.indexOf(":", firstColon + 1);
    if (secondColon === -1) continue;

    const category = trimmed.slice(0, firstColon);
    const severity = trimmed.slice(firstColon + 1, secondColon) as Severity;
    const pattern = trimmed.slice(secondColon + 1);

    if (!pattern || !["HIGH", "MED", "LOW"].includes(severity)) continue;

    try {
      patterns.push({
        category,
        severity,
        regex: new RegExp(pattern, "i"),
        raw: pattern,
      });
    } catch {
      console.error(`[quarantine] Invalid regex: ${pattern}`);
    }
  }

  cachedPatterns = patterns;
  return patterns;
}

function loadConfirmedThreats(): ConfirmedThreat[] {
  const file =
    process.env.GUARD_CONFIRMED ||
    resolve(
      process.env.HOME || "~",
      ".claude/hooks/confirmed-threats.json"
    );

  try {
    const stat = require("fs").statSync(file);
    // Reload if file changed
    if (cachedThreats && stat.mtimeMs === threatsModTime) {
      return cachedThreats;
    }
    const content = readFileSync(file, "utf-8");
    const threats = JSON.parse(content);
    if (Array.isArray(threats)) {
      cachedThreats = threats;
      threatsModTime = stat.mtimeMs;
      return threats;
    }
  } catch {
    // File doesn't exist or invalid — no confirmed threats
  }
  return [];
}

function checkConfirmedThreats(content: string): string | null {
  const threats = loadConfirmedThreats();
  const lowerContent = content.toLowerCase();

  for (const threat of threats) {
    for (const indicator of threat.indicators || []) {
      if (indicator.length < 8) continue; // skip short indicators
      if (lowerContent.includes(indicator.toLowerCase())) {
        return threat.id;
      }
    }
  }
  return null;
}

export function resetPatternCache(): void {
  cachedPatterns = null;
  cachedThreats = null;
  threatsModTime = 0;
}

export function scanContent(
  content: string,
  patternsFile?: string
): ScanResult {
  // Check confirmed threats first — auto-escalate to HIGH
  const confirmedId = checkConfirmedThreats(content);
  if (confirmedId) {
    return {
      severity: "HIGH",
      categories: ["confirmed_threat"],
      indicators: [`matched confirmed threat ${confirmedId}`],
      matches: [
        {
          category: "confirmed_threat",
          severity: "HIGH",
          match: `confirmed threat ${confirmedId}`,
        },
      ],
      confirmedMatch: confirmedId,
    };
  }

  // Pattern scan
  const patterns = loadPatterns(patternsFile);
  let maxSeverity: Severity = "NONE";
  let maxSeverityNum = 0;
  const categories = new Set<string>();
  const indicators: string[] = [];
  const matches: ScanMatch[] = [];

  for (const entry of patterns) {
    const m = content.match(entry.regex);
    if (m) {
      const sevNum = SEVERITY_ORDER[entry.severity] || 0;
      if (sevNum > maxSeverityNum) {
        maxSeverityNum = sevNum;
        maxSeverity = entry.severity;
      }
      categories.add(entry.category);
      const matched = (m[0] || "").slice(0, 80);
      indicators.push(matched);
      matches.push({
        category: entry.category,
        severity: entry.severity,
        match: matched,
      });
    }
  }

  return {
    severity: maxSeverity,
    categories: [...categories],
    indicators,
    matches,
  };
}
