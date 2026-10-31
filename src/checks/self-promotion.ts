import type { ColumnSchema } from "../types.js";
import type { Severity } from "../types.js";
import { curlOf, eqFilter, severityRank } from "../util.js";
import { rowsFromBody, valueStuck } from "../rows.js";
import type { Check } from "./common.js";
import { conclude, errored, listTables, reproAll, skipped, userGate } from "./common.js";

const BENIGN: Record<string, unknown> = {
  role: "user",
  is_admin: false,
  is_superadmin: false,
  admin: false,
  plan: "free",
  tier: "free",
  credits: 0,
  credit_balance: 0,
  balance: 0,
};

const VALUES: Record<string, unknown[]> = {
  role: ["admin", "owner", "superuser"],
  is_admin: [true],
  is_superadmin: [true],
  admin: [true],
  plan: ["enterprise", "pro", "premium"],
  tier: ["enterprise", "pro"],
  credits: [999999],
  credit_balance: [999999],
  balance: [999999],
};

const FIX =
  "Revoke UPDATE on role, is_admin, plan, and credits from authenticated and anon. RLS that only checks auth.uid() = user_id still lets a user promote their own row. Use a column grant, a security definer function, or a before-update trigger that rejects changes to those columns.";

export function promotionSeverity(column: string): Severity {
  if (column === "role" || column === "is_admin" || column === "is_superadmin" || column === "admin") {
    return "critical";
  }
  return "high";
}

export const selfPromotion: Check = {
  id: "self-promotion",
  title: "Column self-promotion",
  async run(ctx) {
    const gate = userGate(ctx, this.id, this.title);
    if (gate) return [gate];
    const state = ctx.supabase;
    if (!state?.userA) return [errored(this.id, this.title, "Probe users are missing.")];
    const mine = state.canaries.filter((canary) => canary.side === "a" && canary.sensitiveColumns.length > 0);
    if (state.canaries.length === 0) {
      return [errored(this.id, this.title, state.provisionError ?? "Could not insert a probe row.")];
    }
    if (mine.length === 0) {
      return [
        skipped(
          this.id,
          this.title,
          "None of the probed tables publish role, is_admin, plan, or credits columns.",
        ),
      ];
    }

    const promoted: { table: string; column: string; value: unknown; repro: string; severity: Severity }[] = [];
    const tested = new Set<string>();
    const errors: string[] = [];

    for (const canary of mine) {
      const table = state.schema.find((item) => item.name === canary.table);
      for (const column of canary.sensitiveColumns) {
        tested.add(column);
        const schemaColumn = table?.columns.find((item) => item.name === column);
        const values = valuesFor(column, schemaColumn);
        try {
          const hit = await attemptColumn(state, canary.table, canary.idColumn, canary.id, column, values, state.userA.accessToken);
          if (hit.promoted) promoted.push({ table: canary.table, column, value: hit.value, repro: hit.repro, severity: promotionSeverity(column) });
          if (hit.error) errors.push(`${canary.table}.${column}: ${hit.error}`);
        } catch (err) {
          errors.push(`${canary.table}.${column}: ${err instanceof Error ? err.message : String(err)}`);
        }
      }
    }

    if (promoted.length) {
      promoted.sort((left, right) => severityRank(right.severity) - severityRank(left.severity));
      const columns = [...new Set(promoted.map((item) => item.column))].join(", ");
      const tables = listTables(promoted.map((item) => item.table));
      const first = promoted[0];
      return [
        conclude({
          id: this.id,
          title: this.title,
          status: "fail",
          severity: first?.severity ?? "high",
          summary: `Probe user changed ${columns} on their own row in ${tables}.`,
          fix: FIX,
          repro: reproAll(promoted.map((item) => ({ label: `${item.table}.${item.column}`, repro: item.repro }))),
          evidence: { promoted: promoted.map(({ table, column, value, repro }) => ({ table, column, value, repro })) },
        }),
      ];
    }
    if (errors.length) return [errored(this.id, this.title, errors.join(" "))];
    return [
      conclude({
        id: this.id,
        title: this.title,
        status: "pass",
        severity: "info",
        summary: `Probe user could not change ${[...tested].sort().join(", ")} on their own row.`,
        evidence: { columns: [...tested].sort() },
      }),
    ];
  },
};

function valuesFor(column: string, schemaColumn: ColumnSchema | undefined): unknown[] {
  const known = VALUES[column];
  if (known && known.length > 0) return known;
  if (schemaColumn?.type === "boolean") return [true];
  if (schemaColumn?.type === "number") return [999999];
  return ["admin"];
}

async function attemptColumn(
  state: NonNullable<import("../context.js").ScanContext["supabase"]>,
  table: string,
  idColumn: string,
  id: string,
  column: string,
  values: unknown[],
  bearer: string,
): Promise<{ promoted: boolean; value?: unknown; repro: string; error?: string }> {
  let lastRepro = "";
  for (const value of values) {
    const response = await state.rest.update(table, eqFilter(idColumn, id), { [column]: value }, bearer);
    lastRepro = curlOf(response);
    if (response.status === 401 || response.status === 403) return { promoted: false, repro: lastRepro };
    if (response.status >= 500) return { promoted: false, repro: lastRepro, error: `HTTP ${response.status}` };
    const missing =
      response.status === 400 &&
      (/could not find the .*column/i.test(response.text) || response.text.includes("PGRST204"));
    if (missing) return { promoted: false, repro: lastRepro };
    if (response.status >= 400) continue;
    const represented = rowsFromBody(response.text).rows.some((row) => valueStuck(row[column], value));
    const readback = await state.rest.select(table, `${eqFilter(idColumn, id)}&select=*`, bearer);
    const stuck = represented || rowsFromBody(readback.text).rows.some((row) => valueStuck(row[column], value));
    if (!stuck) continue;
    if (column in BENIGN) {
      try {
        await state.rest.update(table, eqFilter(idColumn, id), { [column]: BENIGN[column] }, bearer);
      } catch {
        // The row is deleted during cleanup.
      }
    }
    return { promoted: true, value, repro: lastRepro };
  }
  return { promoted: false, repro: lastRepro };
}
