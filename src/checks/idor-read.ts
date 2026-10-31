import { curlOf } from "../util.js";
import { rowId, rowsFromBody } from "../rows.js";
import type { Check } from "./common.js";
import { conclude, errored, idQuery, listTables, pairs, reproAll, userGate } from "./common.js";

const FIX =
  "Add a select policy so a user can read only their own rows: auth.uid() = user_id. Drop any policy whose expression is true.";

export const idorRead: Check = {
  id: "idor-read",
  title: "Cross-user read",
  async run(ctx) {
    const gate = userGate(ctx, this.id, this.title);
    if (gate) return [gate];
    const state = ctx.supabase;
    if (!state?.userA) return [errored(this.id, this.title, "Probe users are missing.")];
    const ready = pairs(state.canaries);
    if (ready.length === 0) {
      return [errored(this.id, this.title, "Could not insert probe rows for both users in the same table.")];
    }

    const leaks: { table: string; id: string; marker: string; repro: string }[] = [];
    const errors: string[] = [];
    for (const pair of ready) {
      try {
        const response = await state.rest.select(pair.table, idQuery(pair.b), state.userA.accessToken);
        const parsed = rowsFromBody(response.text);
        const visible = parsed.rows.some((row) => rowId(row, pair.b.idColumn) === pair.b.id);
        if ((response.status === 401 || response.status === 403) && !visible) continue;
        if (response.status >= 200 && response.status < 300 && !visible) continue;
        if (visible) {
          leaks.push({
            table: pair.table,
            id: pair.b.id,
            marker: pair.b.marker,
            repro: curlOf(response),
          });
          continue;
        }
        errors.push(`${pair.table}: HTTP ${response.status} ${parsed.error ?? ""}`.trim());
      } catch (err) {
        errors.push(`${pair.table}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (leaks.length) {
      return [
        conclude({
          id: this.id,
          title: this.title,
          status: "fail",
          severity: "high",
          summary: `User A read User B's probe rows in ${listTables(leaks.map((leak) => leak.table))}.`,
          fix: FIX,
          repro: reproAll(leaks.map((leak) => ({ label: leak.table, repro: leak.repro }))),
          evidence: { leaks },
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
        summary: `User A could not read User B's probe rows in ${listTables(ready.map((pair) => pair.table))}.`,
        evidence: { tables: ready.map((pair) => pair.table) },
      }),
    ];
  },
};
