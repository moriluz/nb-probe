import { userAgent } from "./version.js";
import { errorMessage } from "./util.js";

export interface HttpRequest {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  allowRedirects?: boolean;
  maxBytes?: number;
}

export interface HttpResponse {
  status: number;
  url: string;
  headers: Headers;
  text: string;
  truncated: boolean;
}

export class HttpError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "HttpError";
  }
}

export class HttpClient {
  constructor(private readonly timeoutMs: number) {}

  async request(target: string, init: HttpRequest = {}): Promise<HttpResponse> {
    const allowRedirects = init.allowRedirects ?? true;
    const maxBytes = init.maxBytes ?? 2_000_000;
    const method = (init.method ?? "GET").toUpperCase();
    let current: URL;
    try {
      current = new URL(target);
    } catch {
      throw new HttpError(`Invalid URL ${target}`);
    }
    const originalOrigin = current.origin;

    for (let hop = 0; hop < 5; hop++) {
      let response: Response;
      try {
        response = await fetch(current, {
          method,
          headers: {
            "user-agent": userAgent(),
            ...init.headers,
          },
          body: method === "GET" || method === "HEAD" ? undefined : init.body,
          redirect: "manual",
          signal: AbortSignal.timeout(this.timeoutMs),
        });
      } catch (err) {
        const name = err instanceof Error ? err.name : "";
        if (name === "TimeoutError" || name === "AbortError") {
          throw new HttpError(`Timed out after ${this.timeoutMs}ms calling ${current.origin}`);
        }
        throw new HttpError(`Request failed for ${current.origin}: ${errorMessage(err)}`);
      }

      const location = response.headers.get("location");
      if (response.status >= 300 && response.status < 400 && location) {
        await response.body?.cancel().catch(() => undefined);
        if (!allowRedirects || method !== "GET") {
          return { status: response.status, url: current.toString(), headers: response.headers, text: "", truncated: false };
        }
        let next: URL;
        try {
          next = new URL(location, current);
        } catch {
          throw new HttpError(`Invalid redirect from ${current.origin}`);
        }
        if (next.origin !== originalOrigin) {
          throw new HttpError(`Refused redirect from ${originalOrigin} to ${next.origin}`);
        }
        current = next;
        continue;
      }

      const buf = Buffer.from(await response.arrayBuffer());
      const truncated = buf.length > maxBytes;
      const text = (truncated ? buf.subarray(0, maxBytes) : buf).toString("utf8");
      return {
        status: response.status,
        url: current.toString(),
        headers: response.headers,
        text,
        truncated,
      };
    }

    throw new HttpError(`Too many redirects for ${originalOrigin}`);
  }
}
