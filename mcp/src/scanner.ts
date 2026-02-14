import { readFileSync, statSync, existsSync, mkdirSync, writeFileSync } from "fs";
import { resolve, dirname } from "path";

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

interface ScanCacheEntry {
  severity: Severity;
  categories: string[];
  indicators: string[];
  ts: number;
}

interface PatternOverride {
  pattern: string;
  severity: Severity;
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

// In-memory scan cache (MCP server is long-running)
const scanCache = new Map<string, ScanCacheEntry>();
const SCAN_CACHE_TTL = parseInt(process.env.SCAN_CACHE_TTL || "300", 10) * 1000;

// Allowlist cache
let cachedAllowlist: string[] | null = null;

function loadPatternOverrides(): PatternOverride[] {
  const file =
    process.env.PATTERN_OVERRIDES_FILE ||
    resolve(process.env.HOME || "~", ".claude/hooks/pattern-overrides.conf");

  try {
    const content = readFileSync(file, "utf-8");
    const overrides: PatternOverride[] = [];
    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eqIdx = trimmed.indexOf("=");
      if (eqIdx === -1) continue;
      const pattern = trimmed.slice(0, eqIdx).trim();
      const severity = trimmed.slice(eqIdx + 1).trim().toUpperCase() as Severity;
      if (!pattern || !["HIGH", "MED", "LOW"].includes(severity)) continue;
      overrides.push({ pattern, severity });
    }
    return overrides;
  } catch {
    return [];
  }
}

function loadPatterns(patternsFile?: string): PatternEntry[] {
  if (cachedPatterns) return cachedPatterns;

  const fileSpec =
    patternsFile ||
    process.env.GUARD_PATTERNS ||
    resolve(process.env.HOME || "~", ".claude/hooks/injection-patterns.conf");

  // Split on : to support multiple pattern files
  const fileList = fileSpec.split(":");
  const patterns: PatternEntry[] = [];
  const seen = new Set<string>(); // For deduplication using full pattern key

  const overrides = loadPatternOverrides();

  for (let file of fileList) {
    // Expand tilde to HOME
    if (file.startsWith("~")) {
      file = resolve(process.env.HOME || "~", file.slice(2));
    }

    // Resolve relative paths from .claude/hooks directory
    if (!file.startsWith("/")) {
      file = resolve(
        process.env.HOME || "~",
        ".claude/hooks",
        file
      );
    }

    let content: string;
    try {
      content = readFileSync(file, "utf-8");
    } catch (err) {
      console.error(`[guard] Could not load patterns from ${file}:`, err);
      continue; // Skip this file but continue with others
    }

    for (const line of content.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      const firstColon = trimmed.indexOf(":");
      if (firstColon === -1) continue;
      const secondColon = trimmed.indexOf(":", firstColon + 1);
      if (secondColon === -1) continue;

      const category = trimmed.slice(0, firstColon);
      let severity = trimmed.slice(firstColon + 1, secondColon) as Severity;
      const pattern = trimmed.slice(secondColon + 1);

      if (!pattern || !["HIGH", "MED", "LOW"].includes(severity)) {
        console.error(`[guard] Invalid pattern format: ${trimmed}`);
        continue;
      }

      // Apply overrides
      for (const override of overrides) {
        if (trimmed.toLowerCase().includes(override.pattern.toLowerCase())) {
          severity = override.severity;
          break;
        }
      }

      // Deduplicate using full pattern key (category:severity:pattern)
      const patternKey = `${category}:${severity}:${pattern}`;
      if (seen.has(patternKey)) continue;
      seen.add(patternKey);

      try {
        patterns.push({
          category,
          severity,
          regex: new RegExp(pattern, "i"),
          raw: pattern,
        });
      } catch (err) {
        console.error(`[guard] Invalid regex: ${pattern}`, err);
      }
    }
  }

  if (patterns.length === 0) {
    console.warn(
      `[guard] No patterns loaded from: ${fileSpec}`
    );
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
    const stat = statSync(file);
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

function checkConfirmedThreats(
  content: string
): { id: string; indicator: string } | null {
  const threats = loadConfirmedThreats();
  const lowerContent = content.toLowerCase();

  for (const threat of threats) {
    for (const indicator of threat.indicators || []) {
      if (indicator.length < 8) continue; // skip short indicators
      if (lowerContent.includes(indicator.toLowerCase())) {
        return { id: threat.id, indicator };
      }
    }
  }
  return null;
}

export function resetPatternCache(): void {
  cachedPatterns = null;
  cachedThreats = null;
  threatsModTime = 0;
  scanCache.clear();
  cachedAllowlist = null;
}

// --- Allowlist ---

export function loadAllowlist(): string[] {
  if (cachedAllowlist) return cachedAllowlist;

  const file =
    process.env.GUARD_ALLOWLIST ||
    process.env.ALLOWLIST_FILE ||
    "";

  if (!file) {
    cachedAllowlist = [];
    return [];
  }

  let filePath = file;
  if (filePath.startsWith("~")) {
    filePath = resolve(process.env.HOME || "~", filePath.slice(2));
  }

  try {
    const content = readFileSync(filePath, "utf-8");
    const patterns: string[] = [];
    for (const line of content.split("\n")) {
      const trimmed = line.replace(/#.*$/, "").trim();
      if (!trimmed) continue;
      patterns.push(trimmed);
    }
    cachedAllowlist = patterns;
    return patterns;
  } catch {
    cachedAllowlist = [];
    return [];
  }
}

export function isAllowlisted(url: string): boolean {
  const patterns = loadAllowlist();
  if (patterns.length === 0) return false;

  // Extract host from URL
  let host = "";
  try {
    const parsed = new URL(url);
    host = parsed.host;
  } catch {
    return false;
  }

  for (const pattern of patterns) {
    // Exact URL match
    if (url === pattern) return true;

    // Wildcard domain: *.example.com
    if (pattern.startsWith("*.")) {
      const suffix = pattern.slice(1); // .example.com
      if (host.endsWith(suffix) || `.${host}`.endsWith(suffix)) return true;
    }

    // Port wildcard: localhost:*
    if (pattern.endsWith(":*")) {
      const patternHost = pattern.slice(0, -2);
      const hostOnly = host.split(":")[0];
      if (hostOnly === patternHost) return true;
    }

    // Exact host match
    if (host === pattern) return true;
  }

  return false;
}

// --- Scan Cache ---

function computeHash(content: string): string {
  // Simple hash for in-memory cache — not crypto-grade
  let hash = 0;
  for (let i = 0; i < content.length; i++) {
    const chr = content.charCodeAt(i);
    hash = ((hash << 5) - hash) + chr;
    hash |= 0;
  }
  return hash.toString(36);
}

function checkScanCache(content: string): ScanResult | null {
  const hash = computeHash(content);
  const entry = scanCache.get(hash);
  if (!entry) return null;

  if (Date.now() - entry.ts > SCAN_CACHE_TTL) {
    scanCache.delete(hash);
    return null;
  }

  return {
    severity: entry.severity,
    categories: entry.categories,
    indicators: entry.indicators,
    matches: [],
  };
}

function updateScanCache(content: string, result: ScanResult): void {
  const hash = computeHash(content);
  scanCache.set(hash, {
    severity: result.severity,
    categories: result.categories,
    indicators: result.indicators,
    ts: Date.now(),
  });

  // Prune old entries periodically (keep cache size bounded)
  if (scanCache.size > 1000) {
    const now = Date.now();
    for (const [key, entry] of scanCache) {
      if (now - entry.ts > SCAN_CACHE_TTL) {
        scanCache.delete(key);
      }
    }
  }
}

export function scanContent(
  content: string,
  patternsFile?: string
): ScanResult {
  // Check scan cache first
  const cached = checkScanCache(content);
  if (cached) return cached;

  // Check confirmed threats first — auto-escalate to HIGH
  const confirmed = checkConfirmedThreats(content);
  if (confirmed) {
    const result: ScanResult = {
      severity: "HIGH",
      categories: ["confirmed_threat"],
      indicators: [`matched confirmed threat ${confirmed.id}`],
      matches: [
        {
          category: "confirmed_threat",
          severity: "HIGH",
          match: confirmed.indicator,
        },
      ],
      confirmedMatch: confirmed.id,
    };
    updateScanCache(content, result);
    return result;
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

  const result: ScanResult = {
    severity: maxSeverity,
    categories: [...categories],
    indicators,
    matches,
  };

  updateScanCache(content, result);
  return result;
}
