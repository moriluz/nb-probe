import type { ScanContext } from "../context.js";
import type { Canary, CheckResult, Severity } from "../types.js";
import { eqFilter } from "../util.js";

export interface Check {
  id: string;
  title: string;
  run(ctx: ScanContext): Promise<CheckResult[]>;
}

export function skipped(id: string, title: string, summary: string): CheckResult {
  return { id, title, status: "skip", severity: "info", summary };
}

export function errored(id: string, title: string, summary: string, repro?: string): CheckResult {
  const result: CheckResult = { id, title, status: "error", severity: "info", summary };
  if (repro) result.repro = repro;
  return result;
}

export function conclude(args: {
  id: string;
  title: string;
  status: "pass" | "fail" | "error";
  severity: Severity;
  summary: string;
  fix?: string;
  repro?: string;
  evidence?: Record<string, unknown>;
}): CheckResult {
  if (args.status === "fail" && !args.repro) {
    throw new Error(`${args.id} failed without a repro command`);
  }
  const result: CheckResult = {
    id: args.id,
    title: args.title,
    status: args.status,
    severity: args.status === "fail" ? args.severity : "info",
    summary: args.summary,
  };
  if (args.fix && args.status === "fail") result.fix = args.fix;
  if (args.repro && args.status !== "pass") result.repro = args.repro;
  if (args.evidence && Object.keys(args.evidence).length > 0) result.evidence = args.evidence;
  return result;
}

export function userGate(ctx: ScanContext, id: string, title: string): CheckResult | null {
  const state = ctx.supabase;
  if (!state) return skipped(id, title, "Pass --supabase-url and --anon-key to run this check.");
  if (!state.userA || !state.userB) {
    if (!state.provisionError && state.selected.length === 0) {
      const named = ctx.config.tables?.length
        ? "None of the requested tables could be probed."
        : "No user-scoped tables in the published schema. Pass --tables to name private tables.";
      return skipped(id, title, state.provisionError ?? named);
    }
    return errored(id, title, state.provisionError ?? "Could not prepare two probe users.");
  }
  return null;
}

export function pairs(canaries: Canary[]): { table: string; a: Canary; b: Canary }[] {
  const grouped = new Map<string, { a?: Canary; b?: Canary }>();
  for (const canary of canaries) {
    const slot = grouped.get(canary.table) ?? {};
    slot[canary.side] = canary;
    grouped.set(canary.table, slot);
  }
  const ready: { table: string; a: Canary; b: Canary }[] = [];
  for (const [table, slot] of grouped) {
    if (slot.a && slot.b) ready.push({ table, a: slot.a, b: slot.b });
  }
  return ready.sort((left, right) => left.table.localeCompare(right.table));
}

export function onePerTable(canaries: Canary[]): Canary[] {
  const byTable = new Map<string, Canary>();
  for (const canary of canaries) {
    if (!byTable.has(canary.table)) byTable.set(canary.table, canary);
  }
  return [...byTable.values()].sort((left, right) => left.table.localeCompare(right.table));
}

export function idQuery(canary: Canary): string {
  return `${eqFilter(canary.idColumn, canary.id)}&select=*`;
}

export function listTables(names: string[]): string {
  return [...new Set(names)].sort().join(", ");
}
