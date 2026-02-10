import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { secureFetch } from "./tools/secure-fetch.js";
import { secureShell } from "./tools/secure-shell.js";

const server = new McpServer({
  name: "claude-quarantine",
  version: "1.0.0",
});

// --- secure_fetch tool ---
server.tool(
  "secure_fetch",
  "Fetch a URL with prompt injection scanning and sanitization. Use this instead of WebFetch for security.",
  {
    url: z.string().url().describe("The URL to fetch"),
    method: z
      .enum(["GET", "POST", "PUT", "DELETE"])
      .optional()
      .default("GET")
      .describe("HTTP method"),
    headers: z
      .record(z.string(), z.string())
      .optional()
      .describe("HTTP headers as key-value pairs"),
    body: z.string().optional().describe("Request body (for POST/PUT)"),
  },
  async (params) => {
    try {
      const result = await secureFetch({
        url: params.url,
        method: params.method,
        headers: params.headers as Record<string, string> | undefined,
        body: params.body,
      });
      const lines = [`Status: ${result.status}`];
      if (result.sanitized && result.scanSummary) {
        lines.push(
          `Security: Content was sanitized (${result.scanSummary.severity} threat detected in categories: ${result.scanSummary.categories.join(", ")})`
        );
      }
      lines.push("", result.content);

      return {
        content: [{ type: "text" as const, text: lines.join("\n") }],
      };
    } catch (err) {
      return {
        content: [
          {
            type: "text" as const,
            text: `Fetch error: ${err instanceof Error ? err.message : String(err)}`,
          },
        ],
        isError: true,
      };
    }
  }
);

// --- secure_gh tool ---
server.tool(
  "secure_gh",
  "Run a GitHub CLI (gh) command with prompt injection scanning and sanitization. Use this instead of `gh` via Bash.",
  {
    args: z
      .array(z.string())
      .describe(
        'Arguments to pass to the gh command (e.g., ["issue", "view", "123"])'
      ),
    timeout: z
      .number()
      .optional()
      .default(30000)
      .describe("Timeout in milliseconds"),
  },
  async (params) => {
    const result = await secureShell({
      command: "gh",
      args: params.args,
      timeout: params.timeout,
    });

    const lines: string[] = [];
    if (result.sanitized && result.scanSummary) {
      lines.push(
        `Security: Output was sanitized (${result.scanSummary.severity} threat detected in categories: ${result.scanSummary.categories.join(", ")})`
      );
      lines.push("");
    }

    if (result.stdout) lines.push(result.stdout);
    if (result.stderr && result.exitCode !== 0) {
      lines.push(`\nstderr: ${result.stderr}`);
    }

    return {
      content: [{ type: "text" as const, text: lines.join("\n") || "(no output)" }],
      ...(result.exitCode !== 0 ? { isError: true } : {}),
    };
  }
);

// --- secure_curl tool ---
server.tool(
  "secure_curl",
  "Run a curl command with prompt injection scanning and sanitization. Use this instead of `curl` via Bash.",
  {
    args: z
      .array(z.string())
      .describe(
        'Arguments to pass to curl (e.g., ["-s", "https://example.com"])'
      ),
    timeout: z
      .number()
      .optional()
      .default(30000)
      .describe("Timeout in milliseconds"),
  },
  async (params) => {
    const result = await secureShell({
      command: "curl",
      args: params.args,
      timeout: params.timeout,
    });

    const lines: string[] = [];
    if (result.sanitized && result.scanSummary) {
      lines.push(
        `Security: Output was sanitized (${result.scanSummary.severity} threat detected in categories: ${result.scanSummary.categories.join(", ")})`
      );
      lines.push("");
    }

    if (result.stdout) lines.push(result.stdout);
    if (result.stderr && result.exitCode !== 0) {
      lines.push(`\nstderr: ${result.stderr}`);
    }

    return {
      content: [{ type: "text" as const, text: lines.join("\n") || "(no output)" }],
      ...(result.exitCode !== 0 ? { isError: true } : {}),
    };
  }
);

// --- Start server ---
async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
}

main().catch((err) => {
  console.error("Fatal:", err);
  process.exit(1);
});
