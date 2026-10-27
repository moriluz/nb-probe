import { randomId, curlOf, eqFilter } from "../util.js";
import { rowId, rowsFromBody, valueStuck } from "../rows.js";
import type { ApiResult } from "../types.js";
import type { Canary } from "../types.js";
import type { Check } from "./common.js";
import { conclude, errored, idQuery, listTables, pairs, userGate } from "./common.js";

const FIX =
  "Add update and delete policies with both USING and WITH CHECK set to auth.uid() = user_id. USING alone can still allow an owner change on some setups, so set WITH CHECK as well.";

export const idorWrite: Check = {
  id: "idor-write",
  title: "Cross-user write",
  async run(ctx) {
    const gate = userGate(ctx, this.id, this.title);
    if (gate) return [gate];
    const state = ctx.supabase;
    if (!state?.userA || !state.userB) return [errored(this.id, this.title, "Probe users are missing.")];
    const ready = pairs(state.canaries);
    if (ready.length === 0) {
      return [errored(this.id, this.title, "Could not insert probe rows for both users in the same table.")];
    }

    const writes: { table: string; id: string; via: "patch" | "delete"; repro: string }[] = [];
    const errors: string[] = [];

    for (const pair of ready) {
      try {
        const before = await state.rest.select(pair.table, idQuery(pair.b), state.userB.accessToken);
        const beforeRows = rowsFromBody(before.text).rows;
        const ownerCanSee = beforeRows.some((row) => rowId(row, pair.b.idColumn) === pair.b.id);
        if (!ownerCanSee) {
          errors.push(`${pair.table}: the owning user could not read the probe row, so a write could not be confirmed.`);
          continue;
        }

        if (pair.b.markerColumn) {
          const tampered = `nb-probe-tamper-${randomId()}`;
          const patched = await state.rest.update(
            pair.table,
            eqFilter(pair.b.idColumn, pair.b.id),
            { [pair.b.markerColumn]: tampered },
            state.userA.accessToken,
          );
          const patchHit = rowsFromBody(patched.text).rows.some((row) =>
            valueStuck(row[pair.b.markerColumn ?? ""], tampered),
          );
          const after = await state.rest.select(pair.table, idQuery(pair.b), state.userB.accessToken);
          const readHit = rowsFromBody(after.text).rows.some((row) =>
            valueStuck(row[pair.b.markerColumn ?? ""], tampered),
          );
          if (patchHit || readHit) {
            writes.push({ table: pair.table, id: pair.b.id, via: "patch", repro: curlOf(patched) });
            continue;
          }
          if (patched.status >= 500) {
            errors.push(`${pair.table}: update returned HTTP ${patched.status}.`);
            continue;
          }
          const removed = await tryDelete(state, pair.table, pair.b, state.userA.accessToken, state.userB.accessToken);
          if (removed.gone) {
            writes.push({ table: pair.table, id: pair.b.id, via: "delete", repro: curlOf(removed.response) });
            continue;
          }
          if (removed.error) errors.push(`${pair.table}: ${removed.error}`);
          continue;
        }

        const removed = await tryDelete(state, pair.table, pair.b, state.userA.accessToken, state.userB.accessToken);
        if (removed.gone) {
          writes.push({ table: pair.table, id: pair.b.id, via: "delete", repro: curlOf(removed.response) });
        } else if (removed.error) {
          errors.push(`${pair.table}: ${removed.error}`);
        }
      } catch (err) {
        errors.push(`${pair.table}: ${err instanceof Error ? err.message : String(err)}`);
      }
    }

    if (writes.length) {
      return [
        conclude({
          id: this.id,
          title: this.title,
          status: "fail",
          severity: "critical",
          summary: `User A wrote User B's probe rows in ${listTables(writes.map((write) => write.table))}.`,
          fix: FIX,
          repro: writes[0]?.repro,
          evidence: { writes },
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
        summary: `User A could not update or delete User B's probe rows in ${listTables(ready.map((pair) => pair.table))}.`,
        evidence: { tables: ready.map((pair) => pair.table) },
      }),
    ];
  },
};

async function tryDelete(
  state: NonNullable<import("../context.js").ScanContext["supabase"]>,
  table: string,
  canary: Canary,
  attacker: string,
  owner: string,
): Promise<{ gone: boolean; response: ApiResult; error?: string }> {
  const response = await state.rest.remove(table, eqFilter(canary.idColumn, canary.id), attacker);
  if (response.status >= 500) {
    return { gone: false, response, error: `delete returned HTTP ${response.status}` };
  }
  const after = await state.rest.select(table, idQuery(canary), owner);
  if (after.status >= 500) {
    return { gone: false, response, error: `read-back after delete returned HTTP ${after.status}` };
  }
  const gone = !rowsFromBody(after.text).rows.some((row) => rowId(row, canary.idColumn) === canary.id);
  return { gone, response };
}
