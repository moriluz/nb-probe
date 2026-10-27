import crypto from "node:crypto";

import type { ApiResult } from "./types.js";

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "UsageError";
  }
}

export function errorMessage(err: unknown): string {
  if (err instanceof Error) return err.message;
  return String(err);
}

export function snippet(text: string, max = 240): string {
  const oneLine = text.replace(/\s+/g, " ").trim();
  if (oneLine.length <= max) return oneLine;
  return `${oneLine.slice(0, max)}...`;
}

export function shellQuote(value: string): string {
  return `'${value.replace(/'/g, `'\\''`)}'`;
}

export function toCurl(req: {
  method?: string;
  url: string;
  headers?: Record<string, string>;
  body?: string;
}): string {
  const parts = ["curl", "-sS"];
  const method = (req.method ?? "GET").toUpperCase();
  if (method !== "GET") parts.push("-X", method);
  parts.push(shellQuote(req.url));
  for (const [key, value] of Object.entries(req.headers ?? {})) {
    parts.push("-H", shellQuote(`${key}: ${value}`));
  }
  if (req.body !== undefined) parts.push("--data-raw", shellQuote(req.body));
  return parts.join(" ");
}

export function curlOf(result: ApiResult): string {
  return toCurl({
    method: result.method,
    url: result.url,
    headers: result.requestHeaders,
    body: result.body,
  });
}

export function tokensMatch(expected: string, actual: string): boolean {
  const a = crypto.createHash("sha256").update(expected, "utf8").digest();
  const b = crypto.createHash("sha256").update(actual, "utf8").digest();
  return crypto.timingSafeEqual(a, b);
}

export function parseOwnershipBody(body: string): string | null {
  const trimmed = body.trim();
  if (!trimmed || trimmed.length > 512) return null;
  if (trimmed.startsWith("{")) {
    try {
      const parsed: unknown = JSON.parse(trimmed);
      if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
      const token = (parsed as { token?: unknown }).token;
      if (typeof token !== "string") return null;
      const value = token.trim();
      if (!value || value.length > 200) return null;
      return value;
    } catch {
      return null;
    }
  }
  if (trimmed.includes("\n") || trimmed.includes("<")) return null;
  return trimmed;
}

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const body = parts[1];
  if (!body) return null;
  try {
    const json = Buffer.from(body, "base64url").toString("utf8");
    const value: unknown = JSON.parse(json);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

export function jwtRole(token: string): string | null {
  const payload = decodeJwtPayload(token);
  const role = payload?.role;
  return typeof role === "string" ? role : null;
}

export function jwtSub(token: string): string | null {
  const payload = decodeJwtPayload(token);
  const sub = payload?.sub;
  return typeof sub === "string" && sub.length > 0 ? sub : null;
}

export function assertNotServiceRole(bearer: string): void {
  if (jwtRole(bearer) === "service_role" || bearer.startsWith("sb_secret_")) {
    throw new Error("Refusing to send a service-role or secret key to the Data API.");
  }
}

export function previewSecret(value: string): string {
  if (value.length <= 12) return `${value.slice(0, 4)}...`;
  return `${value.slice(0, 8)}...${value.slice(-4)}`;
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

export function assertIdent(name: string, label: string): void {
  if (!IDENT.test(name)) throw new Error(`Refusing ${label} ${name}`);
}

export function safePath(input: string, flag: string): string {
  if (!input.startsWith("/") || input.startsWith("//")) {
    throw new UsageError(`${flag} must be a path starting with /`);
  }
  if (input.includes("://") || input.includes("\\") || input.includes("..")) {
    throw new UsageError(`${flag} must stay on the app origin`);
  }
  if (input.includes("?") || input.includes("#") || input.length > 200) {
    throw new UsageError(`${flag} must be a plain path`);
  }
  return input;
}

export function sameOriginUrl(origin: string, ref: string): string | null {
  if (!ref || ref.startsWith("javascript:") || ref.startsWith("data:")) return null;
  if (ref.includes("\\") || ref.includes("..")) return null;
  let resolved: URL;
  try {
    resolved = new URL(ref, origin.endsWith("/") ? origin : `${origin}/`);
  } catch {
    return null;
  }
  if (resolved.origin !== origin) return null;
  if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return null;
  return resolved.toString();
}

export function splitList(value: string | string[] | undefined): string[] | undefined {
  if (value === undefined) return undefined;
  const raw = Array.isArray(value) ? value : value.split(",");
  const items = raw.map((item) => item.trim()).filter(Boolean);
  return items.length ? items : undefined;
}

export function eqFilter(column: string, value: string): string {
  assertIdent(column, "column");
  if (!/^[A-Za-z0-9._~:-]+$/.test(value)) {
    throw new Error("Refusing a filter value with unexpected characters.");
  }
  return `${column}=eq.${value}`;
}

const SEVERITY_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 } as const;

export function severityRank(severity: keyof typeof SEVERITY_RANK): number {
  return SEVERITY_RANK[severity];
}

export function randomId(bytes = 6): string {
  return crypto.randomBytes(bytes).toString("hex");
}
