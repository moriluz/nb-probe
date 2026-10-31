import { CHECK_LIST } from "./checks/index.js";
import type { ResolvedConfig } from "./config.js";
import { resolveConfig } from "./config.js";
import type { ScanContext } from "./context.js";
import { cleanupSupabase, prepareSupabase } from "./harness.js";
import { HttpClient } from "./http.js";
import { checkOwnership } from "./ownership.js";
import { buildReport } from "./report.js";
import { SupabaseClient } from "./supabase.js";
import type { CheckResult, ScanConfig, ScanReport } from "./types.js";
import { errorMessage } from "./util.js";

export async function scan(input: ScanConfig): Promise<ScanReport> {
  const startedAt = new Date().toISOString();
  const config = resolveConfig(input);
  const http = new HttpClient(config.timeoutMs);
  const ownership = await checkOwnership(http, config.target, config.token);
  if (!ownership.ok) {
    return buildReport({
      target: config.url,
      supabaseUrl: config.supabaseUrl,
      ownership: "refused",
      message: ownership.message,
      startedAt,
      results: [],
      notes: [],
    });
  }

  const ctx = createContext(config, http);
  let results: CheckResult[] = [];
  try {
    if (ctx.supabase) await prepareSupabase(ctx);
    results = await runChecks(ctx);
  } finally {
    try {
      await cleanupSupabase(ctx);
    } catch (err) {
      ctx.notes.push(`Cleanup failed: ${errorMessage(err)}`);
    }
  }

  return buildReport({
    target: config.url,
    supabaseUrl: config.supabaseUrl,
    ownership: "verified",
    ownershipFile: ownership.url,
    startedAt,
    results,
    notes: ctx.notes,
    discovery: ctx.supabase?.discovery,
  });
}

function createContext(config: ResolvedConfig, http: HttpClient): ScanContext {
  const ctx: ScanContext = {
    config,
    http,
    origin: config.target.origin,
    notes: [],
    ephemeralUserIds: [],
  };
  if (config.supabaseUrl && config.anonKey) {
    ctx.supabase = {
      rest: new SupabaseClient(http, config.supabaseUrl, config.anonKey),
      schema: [],
      selected: [],
      usersCreatedByUs: false,
      canaries: [],
      insertErrors: [],
    };
  }
  return ctx;
}

async function runChecks(ctx: ScanContext): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  for (const check of CHECK_LIST) {
    if (ctx.config.only && !ctx.config.only.includes(check.id)) continue;
    try {
      results.push(...(await check.run(ctx)));
    } catch (err) {
      results.push({
        id: check.id,
        title: check.title,
        status: "error",
        severity: "info",
        summary: errorMessage(err),
      });
    }
  }
  return results;
}
