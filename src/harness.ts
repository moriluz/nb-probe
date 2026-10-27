import crypto from "node:crypto";

import type { ScanContext } from "./context.js";
import { parseOpenApi, selectTables } from "./openapi.js";
import { rowId, rowsFromBody } from "./rows.js";
import { parseSession } from "./supabase.js";
import type { ColumnSchema, SessionUser, TableSchema } from "./types.js";
import { eqFilter, errorMessage, jwtSub, randomId, snippet } from "./util.js";

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

export function buildInsertBody(
  table: TableSchema,
  userId: string,
  email: string,
  marker: string,
  includePk: boolean,
): Record<string, unknown> {
  const body: Record<string, unknown> = {};
  if (includePk && table.primaryKey) {
    const pk = table.columns.find((column) => column.name === table.primaryKey);
    if (pk?.type === "string") body[pk.name] = crypto.randomUUID();
  }
  if (table.ownerColumn) body[table.ownerColumn] = userId;
  if (table.markerColumn) body[table.markerColumn] = marker;
  for (const column of table.columns) {
    if (column.name in body || column.primary) continue;
    if (!column.required || column.hasDefault) continue;
    body[column.name] = valueFor(column, email, marker);
  }
  return body;
}

function valueFor(column: ColumnSchema, email: string, marker: string): unknown {
  if (column.name in BENIGN) return BENIGN[column.name];
  if (column.format === "email" || column.name.toLowerCase().includes("email")) return email;
  if (column.type === "number") return 0;
  if (column.type === "boolean") return false;
  if (column.format === "uuid") return crypto.randomUUID();
  return marker;
}

export async function prepareSupabase(ctx: ScanContext): Promise<void> {
  const { config } = ctx;
  if (!config.supabaseUrl || !config.anonKey || !ctx.supabase) return;
  const state = ctx.supabase;

  let document;
  try {
    document = await state.rest.openApi();
  } catch (err) {
    state.provisionError = `Could not read the API schema at /rest/v1/: ${errorMessage(err)}`;
    return;
  }
  if (document.status !== 200 || document.text.length === 0) {
    state.provisionError = `Schema request returned HTTP ${document.status}. ${snippet(document.text)}`;
    return;
  }

  try {
    state.schema = parseOpenApi(document.text);
  } catch (err) {
    state.provisionError = errorMessage(err);
    return;
  }

  const selected = selectTables(state.schema, config.tables);
  state.selected = selected.tables;
  if (selected.missing.length && selected.tables.length === 0) {
    state.provisionError = `None of the requested tables are in the schema: ${selected.missing.join(", ")}.`;
    return;
  }
  if (selected.missing.length) {
    ctx.notes.push(`Not in the schema, skipped: ${selected.missing.join(", ")}.`);
  }
  if (selected.truncatedFrom) {
    ctx.notes.push(
      `Probed 20 of ${selected.truncatedFrom} user-scoped tables. Pass --tables to choose.`,
    );
  }
  if (selected.tables.length === 0) return;

  const provisioned = await provisionUsers(ctx);
  if (!provisioned) return;
  await insertCanaries(ctx, provisioned.userA, provisioned.userB);
}

async function provisionUsers(
  ctx: ScanContext,
): Promise<{ userA: SessionUser; userB: SessionUser } | null> {
  const state = ctx.supabase;
  const { config } = ctx;
  if (!state) return null;

  if (config.userA && config.userB) {
    const idA = jwtSub(config.userA);
    const idB = jwtSub(config.userB);
    if (!idA || !idB) {
      state.provisionError = "--user-a or --user-b is not a JWT with a sub claim.";
      return null;
    }
    if (idA === idB) {
      state.provisionError = "--user-a and --user-b are the same subject.";
      return null;
    }
    const userA = { id: idA, email: "", accessToken: config.userA };
    const userB = { id: idB, email: "", accessToken: config.userB };
    state.userA = userA;
    state.userB = userB;
    state.usersCreatedByUs = false;
    return { userA, userB };
  }

  const stamp = randomId();
  const emailA = `nb-probe-a-${stamp}@example.com`;
  const emailB = `nb-probe-b-${stamp}@example.com`;
  const passwordA = crypto.randomBytes(18).toString("base64url");
  const passwordB = crypto.randomBytes(18).toString("base64url");

  try {
    if (config.serviceRole) {
      const userA = await adminSession(ctx, emailA, passwordA);
      const userB = await adminSession(ctx, emailB, passwordB);
      state.userA = userA;
      state.userB = userB;
      state.usersCreatedByUs = true;
      return { userA, userB };
    }
    const userA = await publicSession(ctx, emailA, passwordA);
    const userB = await publicSession(ctx, emailB, passwordB);
    state.userA = userA;
    state.userB = userB;
    state.usersCreatedByUs = true;
    return { userA, userB };
  } catch (err) {
    state.provisionError = errorMessage(err);
    return null;
  }
}

async function adminSession(ctx: ScanContext, email: string, password: string): Promise<SessionUser> {
  const state = ctx.supabase;
  const serviceRole = ctx.config.serviceRole;
  if (!state || !serviceRole) throw new Error("service role missing");
  const created = await state.rest.admin("POST", "/auth/v1/admin/users", serviceRole, {
    email,
    password,
    email_confirm: true,
  });
  const user = parseSession(created.text);
  if (created.status >= 300 || !user) {
    throw new Error(`Creating a probe user failed: HTTP ${created.status}. ${snippet(created.text)}`);
  }
  const session = await state.rest.passwordGrant(email, password);
  const parsed = parseSession(session.text);
  if (session.status >= 300 || !parsed?.accessToken) {
    throw new Error(
      `Probe user ${email} was created but password login failed: HTTP ${session.status}. ${snippet(session.text)}`,
    );
  }
  return { id: parsed.id || user.id, email, accessToken: parsed.accessToken };
}

async function publicSession(ctx: ScanContext, email: string, password: string): Promise<SessionUser> {
  const state = ctx.supabase;
  if (!state) throw new Error("supabase client missing");
  const signed = await state.rest.signUp(email, password);
  const parsed = parseSession(signed.text);
  if (signed.status >= 300 || !parsed) {
    throw new Error(
      `Public signup did not return a session (HTTP ${signed.status}). Pass --service-role to create probe users, or pass --user-a and --user-b. ${snippet(signed.text)}`,
    );
  }
  if (parsed.accessToken) return { id: parsed.id, email: parsed.email || email, accessToken: parsed.accessToken };
  const session = await state.rest.passwordGrant(email, password);
  const granted = parseSession(session.text);
  if (!granted?.accessToken) {
    throw new Error(
      "Signup created a user but did not return an access token. Turn off email confirmation for the probe project, or pass existing JWTs.",
    );
  }
  return { id: granted.id || parsed.id, email, accessToken: granted.accessToken };
}

async function insertCanaries(ctx: ScanContext, userA: SessionUser, userB: SessionUser): Promise<void> {
  const state = ctx.supabase;
  if (!state) return;
  for (const table of state.selected) {
    for (const side of ["a", "b"] as const) {
      const user = side === "a" ? userA : userB;
      const marker = `nb-probe-${side}-${randomId()}`;
      try {
        const canaryId = await insertOne(ctx, table, user, marker);
        state.canaries.push({
          table: table.name,
          idColumn: table.primaryKey ?? "id",
          id: canaryId,
          markerColumn: table.markerColumn,
          marker,
          side,
          sensitiveColumns: table.sensitiveColumns,
        });
      } catch (err) {
        state.insertErrors.push(`${table.name} (${side}): ${errorMessage(err)}`);
      }
    }
  }
  if (state.insertErrors.length) {
    ctx.notes.push(`Some probe rows were not inserted: ${state.insertErrors.join(" | ")}`);
  }
  if (state.canaries.length === 0) {
    state.provisionError = `Could not insert a probe row. ${state.insertErrors.join(" | ")}`;
  }
}

async function insertOne(
  ctx: ScanContext,
  table: TableSchema,
  user: SessionUser,
  marker: string,
): Promise<string> {
  const state = ctx.supabase;
  if (!state) throw new Error("supabase client missing");
  let body = buildInsertBody(table, user.id, user.email, marker, false);
  let response = await state.rest.insert(table.name, body, user.accessToken);
  if (response.status === 400 && table.primaryKey && !(table.primaryKey in body)) {
    body = buildInsertBody(table, user.id, user.email, marker, true);
    response = await state.rest.insert(table.name, body, user.accessToken);
  }
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`HTTP ${response.status} ${snippet(response.text)}`);
  }
  const { rows, error } = rowsFromBody(response.text);
  const first = rows[0];
  const id = first ? rowId(first, table.primaryKey ?? "id") : null;
  if (id) return id;
  if (table.markerColumn) {
    const found = await state.rest.select(
      table.name,
      `${eqFilter(table.markerColumn, marker)}&select=*`,
      user.accessToken,
    );
    const located = rowsFromBody(found.text).rows[0];
    const locatedId = located ? rowId(located, table.primaryKey ?? "id") : null;
    if (locatedId) return locatedId;
  }
  throw new Error(error ?? "insert response had no id");
}

export async function cleanupSupabase(ctx: ScanContext): Promise<void> {
  const state = ctx.supabase;
  const createdUsers =
    (state?.usersCreatedByUs && (state.userA || state.userB)) || ctx.ephemeralUserIds.length > 0;
  const createdRows = (state?.canaries.length ?? 0) > 0;
  if (!ctx.config.cleanup) {
    if (createdUsers || createdRows) {
      ctx.notes.push("Cleanup skipped (--no-cleanup). Probe users and rows were left in place.");
    }
    return;
  }
  if (!state) return;

  for (const canary of state.canaries) {
    const actor = canary.side === "a" ? state.userA : state.userB;
    if (!actor) continue;
    try {
      const filter = eqFilter(canary.idColumn, canary.id);
      await state.rest.remove(canary.table, filter, actor.accessToken);
      const still = await state.rest.select(canary.table, `${filter}&select=*`, actor.accessToken);
      const left = rowsFromBody(still.text).rows.some((row) => rowId(row, canary.idColumn) === canary.id);
      if (left) {
        ctx.notes.push(`Probe row ${canary.table} ${canary.id} is still there. Delete it by id if you do not want it left behind.`);
      }
    } catch (err) {
      ctx.notes.push(`Cleanup for ${canary.table} ${canary.id} failed: ${errorMessage(err)}`);
    }
  }

  const ids = new Set<string>();
  if (state.usersCreatedByUs && state.userA) ids.add(state.userA.id);
  if (state.usersCreatedByUs && state.userB) ids.add(state.userB.id);
  for (const id of ctx.ephemeralUserIds) ids.add(id);
  if (ids.size === 0) return;
  if (!ctx.config.serviceRole) {
    ctx.notes.push(
      "Probe auth users were not deleted (no --service-role). Remove nb-probe-*@example.com in Authentication if this was not a throwaway project.",
    );
    return;
  }
  for (const id of ids) {
    try {
      const removed = await state.rest.admin(
        "DELETE",
        `/auth/v1/admin/users/${encodeURIComponent(id)}`,
        ctx.config.serviceRole,
      );
      if (removed.status >= 300 && removed.status !== 404) {
        ctx.notes.push(`Could not delete probe user ${id}: HTTP ${removed.status}.`);
      }
    } catch (err) {
      ctx.notes.push(`Could not delete probe user ${id}: ${errorMessage(err)}`);
    }
  }
}
