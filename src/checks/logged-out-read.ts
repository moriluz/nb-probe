import { curlOf } from "../util.js";
import { rowId, rowsFromBody } from "../rows.js";
import type { Check } from "./common.js";
import { conclude, errored, idQuery, listTables, onePerTable, userGate } from "./common.js";

const FIX =
  "Turn on RLS for the table. Add a select policy for authenticated with auth.uid() = user_id (or your owner column). Do not add a select policy for anon.";

export const loggedOutRead: Check = {
  id: "logged-out-read",
  title: "Logged-out read of protected tables",
  async run(ctx) {
    const gate = userGate(ctx, this.id, this.title);
    if (gate) return [gate];
    const state = ctx.supabase;
    const anonKey = ctx.config.anonKey;
    if (!state?.userA || !anonKey) return [errored(this.id, this.title, "Probe users are missing.")];
    const targets = onePerTable(state.canaries);
    if (targets.length === 0) {
      return [errored(this.id, this.title, state.provisionError ?? "Could not insert a probe row.")];
    }

    const leaks: { table: string; id: string; marker: string; repro: string }[] = [];
    const errors: string[] = [];
    for (const canary of targets) {
      try {
        const response = await state.rest.select(canary.table, idQuery(canary), anonKey);
        const parsed = rowsFromBody(response.text);
        const visible = parsed.rows.some((row) => rowId(row, canary.idColumn) === canary.id);
        if ((response.status === 401 || response.status === 403) && !visible) continue;
        if (response.status >= 200 && response.status < 300 && !visible) continue;
        if (response.status >= 200 && response.status < 300 && visible) {
          leaks.push({
            table: canary.table,
            id: canary.id,
            marker: canary.marker,
            repro: curlOf(response),
          });
          continue;
        }
        errors.push(`${canary.table}: HTTP ${response.status} ${parsed.error ?? ""}`.trim());
      } catch (err) {
        errors.push(`${canary.table}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    const tables = listTables(targets.map((canary) => canary.table));
    if (leaks.length) {
      return [
        conclude({
          id: this.id,
          title: this.title,
          status: "fail",
          severity: "high",
          summary: `The anon key read probe rows in ${listTables(leaks.map((leak) => leak.table))}.`,
          fix: FIX,
          repro: leaks[0]?.repro,
          evidence: { leaks },
        }),
      ];
    }
    if (errors.length) {
      return [errored(this.id, this.title, errors.join(" "))];
    }
    return [
      conclude({
        id: this.id,
        title: this.title,
        status: "pass",
        severity: "info",
        summary: `The anon key could not read probe rows in ${tables}.`,
        evidence: { tables: targets.map((canary) => canary.table).sort() },
      }),
    ];
  },
};
