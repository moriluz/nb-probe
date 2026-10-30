import crypto from "node:crypto";

import type { ScanContext } from "./context.js";
import { loadBundle } from "./bundle.js";
import { extractUsage, confirmCandidates, guessColumn, parsePostgrestError } from "./discovery.js";
import { deriveTable, OWNER_COLUMNS, parseOpenApi, selectTables } from "./openapi.js";
import { rowId, rowsFromBody } from "./rows.js";
import { parseSession } from "./supabase.js";
import type { ColumnSchema, DiscoveredTable, DiscoveryReport, SessionUser, TableSchema } from "./types.js";
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
  if (column.format === "date-time") return new Date().toISOString();
  if (column.format === "json") return {};
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

  const found = await loadSchema(ctx, config.anonKey);
  if (!found) return;

  const discovery = state.discovery;
  // --tables chooses what gets probed in both modes, so a public table with a user_id column can
  // still be left out. Discovered tables outside --tables are listed in the report, not probed.
  const selected = selectTables(state.schema, config.tables);
  state.selected = selected.tables;
  if (discovery) {
    markSelection(discovery.tables, state.schema, selected.tables, config.tables);
  }
  if (selected.missing.length) {
    const where = discovery?.schema === "openapi" ? "Not in the schema" : "Not found by PostgREST";
    ctx.notes.push(`${where}, skipped: ${selected.missing.join(", ")}.`);
  }
  if (selected.truncatedFrom) {
    ctx.notes.push(
      `Probed 20 of ${selected.truncatedFrom} user-scoped tables. Pass --tables to choose.`,
    );
  }
  if (selected.tables.length === 0) {
    state.skipReason = noTablesReason(state.schema, config.tables, selected.missing, discovery);
    return;
  }

  const provisioned = await provisionUsers(ctx);
  if (!provisioned) return;
  await insertCanaries(ctx, provisioned.userA, provisioned.userB);
}

// Reads the OpenAPI schema when the key is allowed to. Hosted Supabase refuses it to anon and
// publishable keys (HTTP 403 since 2026-04-08), so the fallback finds tables from the app bundle
// and confirms them with read-only PostgREST requests. Returns false only on a hard error.
async function loadSchema(ctx: ScanContext, anonKey: string): Promise<boolean> {
  const state = ctx.supabase;
  if (!state) return false;
  const discovery: DiscoveryReport = {
    schema: "openapi",
    openApi: { status: null },
    files: { pages: 0, scripts: 0, sourceMaps: 0, errors: [] },
    tables: [],
    rpcs: [],
    buckets: [],
    projects: [],
    requests: 1,
  };
  state.discovery = discovery;

  let refusal: string;
  try {
    const document = await state.rest.openApi();
    discovery.openApi.status = document.status;
    if (document.status === 200 && document.text.length > 0) {
      try {
        state.schema = parseOpenApi(document.text);
        const requested = new Set(ctx.config.tables ?? []);
        discovery.tables = state.schema.map((table) => ({
          name: table.name,
          sources: requested.has(table.name) ? ["openapi", "--tables"] : ["openapi"],
          status: "found",
          ownerColumn: table.ownerColumn,
          markerColumn: table.markerColumn,
          columns: table.columns.map((column) => column.name),
        }));
        return true;
      } catch (err) {
        refusal = `The schema at /rest/v1/ could not be parsed: ${errorMessage(err)}`;
      }
    } else {
      const error = parsePostgrestError(document.text);
      refusal = `The schema at /rest/v1/ returned HTTP ${document.status}${error?.message ? ` (${error.message})` : ""}`;
    }
  } catch (err) {
    refusal = `The schema at /rest/v1/ could not be read: ${errorMessage(err)}`;
  }
  discovery.schema = "discovery";
  discovery.openApi.message = refusal;

  const bundle = await loadBundle(ctx);
  discovery.files = {
    pages: bundle.files.filter((file) => file.kind === "page").length,
    scripts: bundle.files.filter((file) => file.kind === "script").length,
    sourceMaps: new Set(
      bundle.files.filter((file) => file.kind === "source-map").map((file) => file.url.split("#")[0]),
    ).size,
    errors: bundle.pageError ? [`entry page: ${bundle.pageError}`, ...bundle.errors] : bundle.errors,
  };
  const usage = extractUsage(bundle.files);
  discovery.rpcs = [...usage.rpcs].sort();
  discovery.buckets = [...usage.buckets].sort();
  discovery.projects = [...usage.projects].sort();
  const project = projectHost(ctx.config.supabaseUrl);
  if (project && discovery.projects.length && !discovery.projects.includes(project)) {
    ctx.notes.push(
      `The app bundle names ${discovery.projects.join(", ")}, not ${project}. Check --supabase-url points at the app's project.`,
    );
  }

  let found;
  try {
    found = await confirmCandidates(state.rest, anonKey, usage, ctx.config.tables);
  } catch (err) {
    state.provisionError = `${refusal}. Table discovery failed: ${errorMessage(err)}`;
    return false;
  }
  discovery.requests += found.requests;
  discovery.tables = found.tables;
  state.schema = found.schema;
  ctx.notes.push(
    `${refusal}. Tables were found from the app bundle and PostgREST instead (${describeSources(found.tables)}).`,
  );
  return true;
}

function projectHost(supabaseUrl: string | undefined): string | null {
  if (!supabaseUrl) return null;
  try {
    const host = new URL(supabaseUrl).hostname;
    return /\.supabase\.(co|in)$/.test(host) ? host.replace(/\.supabase\.in$/, ".supabase.co") : null;
  } catch {
    return null;
  }
}

function describeSources(tables: DiscoveredTable[]): string {
  const live = tables.filter((table) => table.status !== "not-found" && table.status !== "error");
  if (live.length === 0) return "none confirmed";
  return live.map((table) => `${table.name}: ${table.sources.join("+")}`).join(", ");
}

function markSelection(
  entries: DiscoveredTable[],
  schema: TableSchema[],
  selected: TableSchema[],
  requested: string[] | undefined,
): void {
  const chosen = new Set(selected.map((table) => table.name));
  const known = new Set(schema.map((table) => table.name));
  for (const entry of entries) {
    if (chosen.has(entry.name)) {
      entry.status = "probed";
      continue;
    }
    if (entry.status !== "found" || !known.has(entry.name)) continue;
    if (requested?.length) entry.note ??= "Exists, not in --tables, not probed.";
    else if (!entry.ownerColumn) entry.note ??= `Exists, no owner column (${OWNER_COLUMNS.join(", ")}). Name it in --tables to probe it.`;
    else entry.note ??= "Exists, over the 20-table limit. Pass --tables to choose.";
  }
}

function noTablesReason(
  schema: TableSchema[],
  requested: string[] | undefined,
  missing: string[],
  discovery: DiscoveryReport | undefined,
): string {
  if (requested?.length) {
    const hints = (discovery?.tables ?? [])
      .filter((entry) => missing.includes(entry.name) && entry.note?.startsWith("PostgREST suggested"))
      .map((entry) => `${entry.name}: ${entry.note}`);
    return `skipped: none of the tables in --tables exist (${missing.join(", ")})${hints.length ? `. ${hints.join("; ")}` : ""}`;
  }
  if (schema.length === 0) return "skipped: no tables discovered, pass --tables";
  return `skipped: no user-scoped tables discovered (found ${schema.map((table) => table.name).join(", ")}, none has ${OWNER_COLUMNS.join(", ")}), pass --tables`;
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

  if (config.userACredentials && config.userBCredentials) {
    try {
      const userA = await signIn(ctx, "A", config.userACredentials);
      const userB = await signIn(ctx, "B", config.userBCredentials);
      if (userA.id === userB.id) {
        state.provisionError = "Test users A and B signed in as the same account.";
        return null;
      }
      state.userA = userA;
      state.userB = userB;
      state.usersCreatedByUs = false;
      return { userA, userB };
    } catch (err) {
      state.provisionError = errorMessage(err);
      return null;
    }
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

// The buyer's own test accounts. They are never created or deleted by nb-probe.
async function signIn(
  ctx: ScanContext,
  label: "A" | "B",
  credentials: { email: string; password: string },
): Promise<SessionUser> {
  const state = ctx.supabase;
  if (!state) throw new Error("supabase client missing");
  const session = await state.rest.passwordGrant(credentials.email, credentials.password);
  const parsed = parseSession(session.text);
  if (session.status >= 300 || !parsed?.accessToken) {
    const error = authError(session.text);
    const advice = /confirm/i.test(error)
      ? " Confirm the account's email first, or turn off email confirmation for the test project."
      : /invalid/i.test(error)
        ? " Check the email and password."
        : "";
    throw new Error(
      `Could not sign in test user ${label} (${credentials.email}): HTTP ${session.status}${error ? ` ${error}` : ""}.${advice}`,
    );
  }
  return { id: parsed.id, email: parsed.email || credentials.email, accessToken: parsed.accessToken };
}

function authError(text: string): string {
  try {
    const json = JSON.parse(text) as Record<string, unknown>;
    for (const key of ["msg", "error_description", "message", "error", "error_code"]) {
      const value = json[key];
      if (typeof value === "string" && value) return value;
    }
  } catch {
    // fall through
  }
  return snippet(text, 120);
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
  let includePk = false;
  let body = buildInsertBody(table, user.id, user.email, marker, includePk);
  let response = await state.rest.insert(table.name, body, user.accessToken);
  // Without the schema nb-probe does not know which columns are NOT NULL or how they are typed.
  // Postgres says so in the error, and a failed insert writes nothing, so adjust and retry a few times.
  for (let attempt = 0; attempt < 6 && response.status >= 400 && response.status < 500; attempt++) {
    const fixed = adjustForError(table, body, response.text);
    if (fixed === "pk") {
      if (includePk || !table.primaryKey) break;
      includePk = true;
    } else if (!fixed) {
      if (response.status !== 400 || includePk || !table.primaryKey || table.primaryKey in body) break;
      includePk = true;
    }
    body = buildInsertBody(table, user.id, user.email, marker, includePk);
    response = await state.rest.insert(table.name, body, user.accessToken);
  }
  if (response.status < 200 || response.status >= 300) {
    throw new Error(`HTTP ${response.status} ${snippet(response.text)}`);
  }
  const { rows, error } = rowsFromBody(response.text);
  const first = rows[0];
  if (first) learnColumns(table, first);
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

const PG_TYPES: [RegExp, Partial<ColumnSchema>][] = [
  [/^uuid$/, { type: "string", format: "uuid" }],
  [/^(smallint|integer|bigint|numeric|real|double precision|decimal)$/, { type: "number" }],
  [/^boolean$/, { type: "boolean" }],
  [/^jsonb?$/, { type: "unknown", format: "json" }],
  [/^(date|time|timestamp|timestamp with(out)? time zone|timestamptz)$/, { type: "string", format: "date-time" }],
];

// Returns true when the table was changed and the insert is worth retrying, "pk" when the
// primary key itself is NOT NULL without a default, and false otherwise.
function adjustForError(table: TableSchema, body: Record<string, unknown>, text: string): boolean | "pk" {
  const error = parsePostgrestError(text);
  if (!error) return false;
  if (error.code === "23502") {
    const name = /null value in column "([A-Za-z_][A-Za-z0-9_]*)"/.exec(error.message)?.[1];
    if (!name || name in body) return false;
    if (name === table.primaryKey) return "pk";
    const column = table.columns.find((item) => item.name === name);
    if (column) {
      if (column.required && !column.hasDefault) return false;
      column.required = true;
      column.hasDefault = false;
    } else {
      table.columns.push({ ...guessColumn(name), required: true, hasDefault: false, primary: false });
    }
    return true;
  }
  if (error.code === "22P02" || error.code === "22007" || error.code === "22008") {
    const match = /invalid input syntax for type ([a-z ]+): "(.*)"/.exec(error.message);
    if (!match?.[1]) return false;
    const pgType = match[1].trim();
    const sent = match[2] ?? "";
    // The marker goes in more than one column, so skip the owner and marker columns when matching.
    const name = Object.keys(body).find(
      (key) => String(body[key]) === sent && key !== table.ownerColumn && key !== table.markerColumn,
    );
    const column = name ? table.columns.find((item) => item.name === name) : undefined;
    const patch = PG_TYPES.find(([re]) => re.test(pgType))?.[1];
    if (!column || !patch) return false;
    if (column.type === patch.type && column.format === patch.format) return false;
    column.type = patch.type ?? column.type;
    if (patch.format) column.format = patch.format;
    else delete column.format;
    return true;
  }
  if (error.code === "PGRST204") {
    const name = /Could not find the '([A-Za-z_][A-Za-z0-9_]*)' column/.exec(error.message)?.[1];
    if (!name || !(name in body) || name === table.ownerColumn || name === table.markerColumn) return false;
    table.columns = table.columns.filter((item) => item.name !== name);
    return true;
  }
  return false;
}

// The inserted row lists every column the user can read. Columns the discovery pass did not
// guess (role, plan, ...) show up here, so the self-promotion check can still find them.
function learnColumns(table: TableSchema, row: Record<string, unknown>): void {
  let added = false;
  for (const [name, value] of Object.entries(row)) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || table.columns.some((column) => column.name === name)) continue;
    const column = guessColumn(name);
    if (typeof value === "number") column.type = "number";
    else if (typeof value === "boolean") column.type = "boolean";
    else if (typeof value === "string") column.type = "string";
    else if (value !== null) column.type = "unknown";
    column.hasDefault = true;
    table.columns.push(column);
    added = true;
  }
  if (!added) return;
  const derived = deriveTable(table.name, table.columns);
  table.sensitiveColumns = derived.sensitiveColumns;
  table.primaryKey ??= derived.primaryKey;
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
