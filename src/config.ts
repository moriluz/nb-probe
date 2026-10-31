import { CHECK_IDS } from "./checks/ids.js";
import type { ScanConfig } from "./types.js";
import { jwtRole, safePath, splitList, UsageError } from "./util.js";

export interface ResolvedConfig {
  url: string;
  token: string;
  supabaseUrl?: string;
  anonKey?: string;
  serviceRole?: string;
  tables?: string[];
  userA?: string;
  userB?: string;
  userACredentials?: { email: string; password: string };
  userBCredentials?: { email: string; password: string };
  signupPath?: string;
  closedSignup: boolean;
  webhookPaths: string[];
  webhookExplicit: boolean;
  llmPaths: string[];
  llmExplicit: boolean;
  only?: string[];
  timeoutMs: number;
  cleanup: boolean;
}

export const DEFAULT_WEBHOOK_PATHS = ["/api/webhooks/stripe", "/api/stripe/webhook", "/api/webhook"];
export const DEFAULT_LLM_PATHS = ["/api/chat", "/api/llm", "/api/ai"];

const TOKEN_RE = /^[A-Za-z0-9._~-]{8,200}$/;

function originOnly(input: string, flag: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UsageError(`${flag} is not a URL: ${input}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new UsageError(`${flag} must be http or https`);
  }
  if (url.username || url.password) throw new UsageError(`${flag} must not include credentials`);
  if ((url.pathname && url.pathname !== "/") || url.search || url.hash) {
    throw new UsageError(`${flag} must be an origin, without a path`);
  }
  return url.origin;
}

export function normalizeSupabaseUrl(input: string): string {
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new UsageError(`--supabase-url is not a URL: ${input}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new UsageError("--supabase-url must be http or https");
  }
  if (url.username || url.password) throw new UsageError("--supabase-url must not include credentials");
  let path = url.pathname.replace(/\/+$/, "");
  if (path.endsWith("/rest/v1")) path = path.slice(0, -"/rest/v1".length);
  if (path && path !== "/") throw new UsageError("--supabase-url must be the project origin");
  return url.origin;
}

function requireKey(value: string, flag: string): string {
  if (value.length < 8 || value.length > 4096 || /\s/.test(value)) {
    throw new UsageError(`${flag} does not look like a key`);
  }
  return value;
}

function rejectSecretAnon(anonKey: string): void {
  if (anonKey.startsWith("sb_secret_")) {
    throw new UsageError("--anon-key looks like a secret key. Pass the anon or publishable key.");
  }
  const role = jwtRole(anonKey);
  if (role === "service_role") {
    throw new UsageError(
      "--anon-key is a service_role key. Pass the anon key. Put the service role in --service-role if you want probe users created and deleted.",
    );
  }
  if (role === "authenticated") {
    throw new UsageError("--anon-key is a user JWT. Pass the project's anon key.");
  }
}

function credentials(
  email: string | undefined,
  password: string | undefined,
  side: "a" | "b",
): { email: string; password: string } | undefined {
  const trimmed = email?.trim();
  if (!trimmed && !password) return undefined;
  if (!trimmed) throw new UsageError(`--user-${side}-password needs --user-${side}-email`);
  if (!password) throw new UsageError(`--user-${side}-email needs --user-${side}-password`);
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed)) throw new UsageError(`--user-${side}-email is not an email address`);
  return { email: trimmed, password };
}

export function resolveConfig(input: ScanConfig): ResolvedConfig {
  if (!input.url) throw new UsageError("--url is required");
  if (!input.token) throw new UsageError("--token is required");
  const url = originOnly(input.url, "--url");
  const token = input.token.trim();
  if (!TOKEN_RE.test(token)) {
    throw new UsageError("--token must be 8 to 200 characters of letters, digits, or . _ ~ -");
  }

  const supabaseUrl = input.supabaseUrl ? normalizeSupabaseUrl(input.supabaseUrl) : undefined;
  const anonKey = input.anonKey ? requireKey(input.anonKey.trim(), "--anon-key") : undefined;
  const serviceRole = input.serviceRole ? requireKey(input.serviceRole.trim(), "--service-role") : undefined;
  if (supabaseUrl && !anonKey) throw new UsageError("--anon-key is required with --supabase-url");
  if (!supabaseUrl && anonKey) throw new UsageError("--supabase-url is required with --anon-key");
  if (anonKey) rejectSecretAnon(anonKey);
  if (serviceRole && jwtRole(serviceRole) === "anon") {
    throw new UsageError("--service-role is an anon key. That key cannot create or delete users.");
  }
  if (anonKey && serviceRole && anonKey === serviceRole) {
    throw new UsageError("--anon-key and --service-role are the same value");
  }

  const userA = input.userA?.trim();
  const userB = input.userB?.trim();
  if ((userA && !userB) || (!userA && userB)) {
    throw new UsageError("Pass both --user-a and --user-b, or neither");
  }
  if (userA && userA.split(".").length !== 3) throw new UsageError("--user-a must be a JWT");
  if (userB && userB.split(".").length !== 3) throw new UsageError("--user-b must be a JWT");
  if (userA && serviceRole && (userA === serviceRole || userB === serviceRole)) {
    throw new UsageError("Probe user JWTs must not be the service role key");
  }

  const credsA = credentials(input.userAEmail, input.userAPassword, "a");
  const credsB = credentials(input.userBEmail, input.userBPassword, "b");
  if ((credsA && !credsB) || (!credsA && credsB)) {
    throw new UsageError("Pass sign-in details for both test users (--user-a-email/--user-a-password and --user-b-email/--user-b-password), or neither");
  }
  if (credsA && userA) {
    throw new UsageError("Pass the test users either as JWTs (--user-a/--user-b) or as email and password, not both");
  }
  if (credsA && credsB && credsA.email.toLowerCase() === credsB.email.toLowerCase()) {
    throw new UsageError("Test users A and B must be two different accounts");
  }
  if (credsA && !supabaseUrl) throw new UsageError("Test user sign-in needs --supabase-url and --anon-key");

  const tables = splitList(input.tables)?.map((name) => name.replace(/^public\./, ""));
  if (tables) {
    const bad = tables.filter((name) => !/^[A-Za-z_][A-Za-z0-9_]*$/.test(name));
    if (bad.length) throw new UsageError(`--tables takes plain table names in the public schema: ${bad.join(", ")}`);
  }
  if (input.tables !== undefined && !tables) throw new UsageError("--tables is empty");
  const only = splitList(input.only);
  if (input.only !== undefined && !only) throw new UsageError("--only is empty");
  if (only) {
    const known = new Set<string>(CHECK_IDS);
    const unknown = only.filter((id) => !known.has(id));
    if (unknown.length) {
      throw new UsageError(`Unknown check in --only: ${unknown.join(", ")}. Known checks: ${CHECK_IDS.join(", ")}`);
    }
  }

  const timeoutMs = input.timeoutMs ?? 10_000;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1000 || timeoutMs > 120_000) {
    throw new UsageError("--timeout must be an integer number of milliseconds from 1000 to 120000");
  }

  const webhookPaths = input.webhookPath
    ? [safePath(input.webhookPath, "--webhook-path")]
    : [...DEFAULT_WEBHOOK_PATHS];
  const llmPaths = input.llmPath ? [safePath(input.llmPath, "--llm-path")] : [...DEFAULT_LLM_PATHS];

  const resolved: ResolvedConfig = {
    url,
    token,
    closedSignup: input.closedSignup ?? false,
    webhookPaths,
    webhookExplicit: Boolean(input.webhookPath),
    llmPaths,
    llmExplicit: Boolean(input.llmPath),
    timeoutMs,
    cleanup: input.cleanup ?? true,
  };
  if (supabaseUrl) resolved.supabaseUrl = supabaseUrl;
  if (anonKey) resolved.anonKey = anonKey;
  if (serviceRole) resolved.serviceRole = serviceRole;
  if (tables) resolved.tables = tables;
  if (userA) resolved.userA = userA;
  if (userB) resolved.userB = userB;
  if (credsA) resolved.userACredentials = credsA;
  if (credsB) resolved.userBCredentials = credsB;
  if (input.signupPath) resolved.signupPath = safePath(input.signupPath, "--signup-path");
  if (only) resolved.only = only;
  return resolved;
}
