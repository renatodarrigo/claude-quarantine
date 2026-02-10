import { execFile } from "child_process";
import { promisify } from "util";
import { sanitizeContent } from "../sanitizer.js";

const execFileAsync = promisify(execFile);

export interface ShellParams {
  command: string;
  args?: string[];
  timeout?: number;
}

export interface ShellResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  sanitized: boolean;
  scanSummary?: {
    severity: string;
    categories: string[];
  };
}

/**
 * Execute a shell command and sanitize its output.
 * Only allows specific commands (gh, curl) for security.
 */
export async function secureShell(params: ShellParams): Promise<ShellResult> {
  const { command, args = [], timeout = 30000 } = params;

  // Allowlist of commands
  const allowed = ["gh", "curl"];
  if (!allowed.includes(command)) {
    return {
      stdout: "",
      stderr: `Command "${command}" is not in the allowlist. Allowed: ${allowed.join(", ")}`,
      exitCode: 1,
      sanitized: false,
    };
  }

  let stdout: string;
  let stderr: string;
  let exitCode: number;

  try {
    const result = await execFileAsync(command, args, {
      timeout,
      maxBuffer: 10 * 1024 * 1024, // 10MB
      env: { ...process.env },
    });
    stdout = result.stdout;
    stderr = result.stderr;
    exitCode = 0;
  } catch (err: unknown) {
    const execErr = err as {
      stdout?: string;
      stderr?: string;
      code?: number;
    };
    stdout = execErr.stdout || "";
    stderr = execErr.stderr || String(err);
    exitCode = execErr.code || 1;
  }

  // Sanitize stdout (where content payloads live)
  const { content: sanitizedStdout, scan, modified } = sanitizeContent(stdout);

  return {
    stdout: sanitizedStdout,
    stderr,
    exitCode,
    sanitized: modified,
    ...(modified
      ? {
          scanSummary: {
            severity: scan.severity,
            categories: scan.categories,
          },
        }
      : {}),
  };
}
