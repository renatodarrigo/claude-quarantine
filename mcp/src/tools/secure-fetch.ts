import { sanitizeContent } from "../sanitizer.js";

export interface FetchParams {
  url: string;
  method?: string;
  headers?: Record<string, string>;
  body?: string;
}

export interface FetchResult {
  status: number;
  content: string;
  contentType: string;
  sanitized: boolean;
  scanSummary?: {
    severity: string;
    categories: string[];
  };
}

export async function secureFetch(params: FetchParams): Promise<FetchResult> {
  const { url, method = "GET", headers = {}, body } = params;

  const response = await fetch(url, {
    method,
    headers,
    body: method !== "GET" ? body : undefined,
    signal: AbortSignal.timeout(30000),
  });

  const contentType = response.headers.get("content-type") || "text/plain";
  const rawContent = await response.text();

  const { content, scan, modified } = sanitizeContent(rawContent);

  return {
    status: response.status,
    content,
    contentType,
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
