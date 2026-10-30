import type { BundleFile } from "./bundle.js";
import { deriveTable, MARKER_COLUMNS, OWNER_COLUMNS, SENSITIVE_COLUMNS } from "./openapi.js";
import type { SupabaseClient } from "./supabase.js";
import type { ColumnSchema, DiscoveredTable, TableSchema, TableSource } from "./types.js";

// ---------------------------------------------------------------------------------------------
// Static pass: read supabase-js calls out of scripts and source map sources.
// ---------------------------------------------------------------------------------------------

export interface BundleUsage {
  tables: Map<string, { sources: Set<TableSource>; columns: Set<string> }>;
  rpcs: Set<string>;
  buckets: Set<string>;
  projects: Set<string>;
}

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;
const FROM_RE = /\.from\(\s*(["'`])([A-Za-z_][A-Za-z0-9_]*)\1\s*\)/g;
const RPC_RE = /\.rpc\(\s*(["'`])([A-Za-z_][A-Za-z0-9_]*)\1/g;
const PROJECT_RE = /\b([a-z0-9]{20})\.supabase\.(?:co|in)\b/g;
// Globals whose .from() takes a string and has nothing to do with Supabase.
const NOT_A_CLIENT = new Set([
  "Array", "Buffer", "Uint8Array", "Int8Array", "Uint16Array", "Int16Array", "Uint32Array", "Int32Array",
  "Float32Array", "Float64Array", "BigInt64Array", "BigUint64Array", "Uint8ClampedArray", "Set", "Map",
  "Object", "String", "Promise", "Readable", "Observable", "Iterator", "Blob", "storage",
]);
const STORAGE_METHODS = new Set([
  "upload", "download", "list", "getPublicUrl", "createSignedUrl", "createSignedUrls", "createSignedUploadUrl",
  "uploadToSignedUrl", "move", "copy", "exists", "info",
]);
const DATA_METHODS = new Set([
  "select", "insert", "upsert", "update", "delete", "eq", "neq", "gt", "gte", "lt", "lte", "like", "ilike",
  "is", "in", "contains", "containedBy", "match", "order", "range", "limit", "single", "maybeSingle", "filter",
  "or", "not", "textSearch", "returns", "csv", "throwOnError", "abortSignal", "likeAnyOf", "ilikeAnyOf",
  "overlaps", "rangeGt", "rangeGte", "rangeLt", "rangeLte", "rangeAdjacent",
]);
const COLUMN_ARG_METHODS = new Set([
  "eq", "neq", "gt", "gte", "lt", "lte", "like", "ilike", "is", "in", "contains", "containedBy", "order",
  "textSearch", "filter", "likeAnyOf", "ilikeAnyOf", "overlaps",
]);
const OBJECT_ARG_METHODS = new Set(["insert", "upsert", "update", "match"]);

export function emptyUsage(): BundleUsage {
  return { tables: new Map(), rpcs: new Set(), buckets: new Set(), projects: new Set() };
}

export function extractUsage(files: BundleFile[], usage: BundleUsage = emptyUsage()): BundleUsage {
  for (const file of files) {
    if (file.kind === "page" && !/<script/i.test(file.text)) continue;
    const source: TableSource = file.kind === "source-map" ? "source-map" : "bundle";
    scanText(file.text, source, usage);
  }
  return usage;
}

function scanText(text: string, source: TableSource, usage: BundleUsage): void {
  for (const match of text.matchAll(PROJECT_RE)) if (match[1]) usage.projects.add(`${match[1]}.supabase.co`);
  for (const match of text.matchAll(RPC_RE)) if (match[2]) usage.rpcs.add(match[2]);

  for (const match of text.matchAll(FROM_RE)) {
    const name = match[2];
    const index = match.index ?? 0;
    if (!name) continue;
    const receiver = text.slice(Math.max(0, index - 40), index).match(/([A-Za-z_$][\w$]*)\s*(?:\?)?$/)?.[1] ?? "";
    const chain = readChain(text, index + match[0].length);
    const first = chain[0]?.method;
    if (receiver === "storage" || (first && STORAGE_METHODS.has(first))) {
      usage.buckets.add(name);
      continue;
    }
    if (NOT_A_CLIENT.has(receiver)) continue;
    if (!first && /^[A-Z]/.test(receiver)) continue;
    if (first && !DATA_METHODS.has(first)) continue;
    const entry = tableEntry(usage, name);
    entry.sources.add(source);
    for (const call of chain) collectColumns(call, entry.columns, usage, source);
  }
}

function tableEntry(usage: BundleUsage, name: string): { sources: Set<TableSource>; columns: Set<string> } {
  let entry = usage.tables.get(name);
  if (!entry) {
    entry = { sources: new Set(), columns: new Set() };
    usage.tables.set(name, entry);
  }
  return entry;
}

function collectColumns(
  call: { method: string; args: string },
  columns: Set<string>,
  usage: BundleUsage,
  source: TableSource,
): void {
  const args = splitTopLevel(call.args, ",");
  const first = args[0]?.trim() ?? "";
  if (call.method === "select") {
    const literal = stringLiteral(first);
    if (literal !== null) parseSelect(literal, columns, usage, source);
    return;
  }
  if (COLUMN_ARG_METHODS.has(call.method)) {
    const literal = stringLiteral(first);
    if (literal !== null) {
      const column = literal.split(/->>?/)[0]?.trim() ?? "";
      if (IDENT.test(column)) columns.add(column);
    }
    return;
  }
  if (OBJECT_ARG_METHODS.has(call.method)) {
    let body = first;
    if (body.startsWith("[")) body = splitTopLevel(body.slice(1, -1), ",")[0]?.trim() ?? "";
    if (body.startsWith("{")) for (const key of objectKeys(body)) columns.add(key);
  }
}

// "id, title, owner:profiles!user_id(name), tags(*)" -> id, title. Embedded resources become table candidates.
export function parseSelect(select: string, columns: Set<string>, usage?: BundleUsage, source: TableSource = "bundle"): void {
  for (const raw of splitTopLevel(select, ",")) {
    let item = raw.trim();
    if (!item || item === "*") continue;
    // An alias is "name:" but a cast is "::", so only a single colon starts an alias.
    const alias = /^[A-Za-z_][A-Za-z0-9_]*:(?!:)/.exec(item);
    if (alias) item = item.slice(alias[0].length).trim();
    const aggregate = /^([A-Za-z_][A-Za-z0-9_]*)(?:::[a-z]+)?\.(sum|avg|min|max|count)\(\)/.exec(item);
    if (aggregate?.[1]) {
      columns.add(aggregate[1]);
      continue;
    }
    if (/^count\(\)/.test(item)) continue;
    const paren = item.indexOf("(");
    if (paren !== -1) {
      if (!usage) continue;
      let relation = item.slice(0, paren);
      relation = relation.replace(/^\.\.\./, "").split("!")[0]?.trim() ?? "";
      if (!IDENT.test(relation) || relation === "count") continue;
      const nested = tableEntry(usage, relation);
      nested.sources.add(source);
      parseSelect(item.slice(paren + 1, item.lastIndexOf(")")), nested.columns, usage, source);
      continue;
    }
    item = item.split("::")[0]?.split(/->>?/)[0]?.trim() ?? "";
    if (IDENT.test(item)) columns.add(item);
  }
}

function readChain(text: string, start: number): { method: string; args: string }[] {
  const calls: { method: string; args: string }[] = [];
  let pos = start;
  while (calls.length < 25) {
    const head = /^\s*\??\.\s*([A-Za-z_$][\w$]*)\s*\(/.exec(text.slice(pos, pos + 80));
    if (!head?.[1]) break;
    const open = pos + head[0].length - 1;
    const close = matchClose(text, open);
    if (close === -1) break;
    calls.push({ method: head[1], args: text.slice(open + 1, close) });
    pos = close + 1;
  }
  return calls;
}

// Index of the bracket that closes the one at `open`, skipping strings. -1 if not found within 4000 chars.
function matchClose(text: string, open: number): number {
  const pairs: Record<string, string> = { "(": ")", "[": "]", "{": "}" };
  const stack: string[] = [];
  const end = Math.min(text.length, open + 4000);
  for (let i = open; i < end; i++) {
    const ch = text[i] ?? "";
    if (ch === '"' || ch === "'" || ch === "`") {
      i = skipString(text, i, end);
      continue;
    }
    if (ch in pairs) stack.push(pairs[ch] ?? "");
    else if (ch === ")" || ch === "]" || ch === "}") {
      if (stack.pop() !== ch) return -1;
      if (stack.length === 0) return i;
    }
  }
  return -1;
}

function skipString(text: string, start: number, end: number): number {
  const quote = text[start];
  for (let i = start + 1; i < end; i++) {
    const ch = text[i];
    if (ch === "\\") {
      i++;
      continue;
    }
    if (ch === quote) return i;
  }
  return end;
}

export function splitTopLevel(text: string, separator: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let current = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i] ?? "";
    if (ch === '"' || ch === "'" || ch === "`") {
      const close = skipString(text, i, text.length);
      current += text.slice(i, close + 1);
      i = close;
      continue;
    }
    if (ch === "(" || ch === "[" || ch === "{") depth++;
    if (ch === ")" || ch === "]" || ch === "}") depth--;
    if (ch === separator && depth === 0) {
      parts.push(current);
      current = "";
      continue;
    }
    current += ch;
  }
  if (current.trim()) parts.push(current);
  return parts;
}

function stringLiteral(text: string): string | null {
  const match = /^(["'`])([\s\S]*)\1$/.exec(text.trim());
  if (!match) return null;
  if (match[1] === "`" && match[2]?.includes("${")) return null;
  return match[2] ?? "";
}

function objectKeys(objectText: string): string[] {
  const keys: string[] = [];
  for (const entry of splitTopLevel(objectText.trim().slice(1, -1), ",")) {
    const item = entry.trim();
    if (!item || item.startsWith("...")) continue;
    const keyed = /^(?:(["'])([A-Za-z_][A-Za-z0-9_]*)\1|([A-Za-z_][A-Za-z0-9_]*))\s*:/.exec(item);
    const key = keyed?.[2] ?? keyed?.[3] ?? (IDENT.test(item) ? item : null);
    if (key) keys.push(key);
  }
  return keys;
}

// ---------------------------------------------------------------------------------------------
// Live pass: confirm candidates with read-only PostgREST requests (GET ... limit=0).
// ---------------------------------------------------------------------------------------------

export const COMMON_TABLES = [
  "profiles", "users", "accounts", "todos", "tasks", "notes", "posts", "comments", "messages", "chats",
  "conversations", "documents", "files", "projects", "teams", "organizations", "workspaces", "members",
  "orders", "invoices", "payments", "subscriptions", "customers", "products", "items", "bookings",
  "settings", "api_keys", "credits", "transactions", "notifications", "leads", "contacts", "reviews",
];

const TABLE_HINT_RE = /Perhaps you meant the table '(?:([A-Za-z_][A-Za-z0-9_]*)\.)?([A-Za-z_][A-Za-z0-9_]*)'/;
const COLUMN_MISSING_RE = /column\s+(?:"?[A-Za-z_][A-Za-z0-9_]*"?\.)*"?([A-Za-z_][A-Za-z0-9_]*)"?\s+does not exist/;
const COLUMN_HINT_RE = /Perhaps you meant to reference the column "(?:[A-Za-z_][A-Za-z0-9_]*\.)?([A-Za-z_][A-Za-z0-9_]*)"/;
const SCHEMA_COLUMN_RE = /Could not find the '([A-Za-z_][A-Za-z0-9_]*)' column/;

export interface PostgrestError {
  code: string;
  message: string;
  details: string;
  hint: string;
}

export function parsePostgrestError(text: string): PostgrestError | null {
  try {
    const json: unknown = JSON.parse(text);
    if (!json || typeof json !== "object" || Array.isArray(json)) return null;
    const record = json as Record<string, unknown>;
    const str = (value: unknown) => (typeof value === "string" ? value : "");
    return { code: str(record.code), message: str(record.message), details: str(record.details), hint: str(record.hint) };
  } catch {
    return null;
  }
}

// PostgREST puts the suggestion in details on some versions and in hint on others. Read both.
export function tableSuggestion(error: PostgrestError): string | null {
  const match = TABLE_HINT_RE.exec(`${error.hint}\n${error.details}`);
  if (!match?.[2]) return null;
  if (match[1] && match[1] !== "public") return null;
  return match[2];
}

export function missingColumn(error: PostgrestError): string | null {
  return COLUMN_MISSING_RE.exec(error.message)?.[1] ?? SCHEMA_COLUMN_RE.exec(error.message)?.[1] ?? null;
}

export function columnSuggestion(error: PostgrestError): string | null {
  return COLUMN_HINT_RE.exec(`${error.hint}\n${error.details}`)?.[1] ?? null;
}

type Probe = "exists" | "missing" | "error";

export interface Discovered {
  schema: TableSchema[];
  tables: DiscoveredTable[];
  requests: number;
}

interface Candidate {
  name: string;
  sources: Set<TableSource>;
  columns: Set<string>;
  suggestedFor?: string;
}

const MAX_CANDIDATES = 80;
const MAX_TABLES = 40;
const MAX_COLUMN_REQUESTS = 40;

// Confirms table and column candidates with GET /rest/v1/<table>?select=<cols>&limit=0 as anon.
// limit=0 returns no rows, and a 401/403 permission error still proves the table and columns exist,
// because Postgres resolves names before it checks grants.
export async function confirmCandidates(
  rest: SupabaseClient,
  anonKey: string,
  usage: BundleUsage,
  requested: string[] | undefined,
): Promise<Discovered> {
  let requests = 0;
  const candidates = new Map<string, Candidate>();
  const order: string[] = [];
  const add = (name: string, source: TableSource, columns?: Iterable<string>, suggestedFor?: string) => {
    if (!IDENT.test(name)) return;
    let candidate = candidates.get(name);
    if (!candidate) {
      if (candidates.size >= MAX_CANDIDATES && source !== "--tables") return;
      candidate = { name, sources: new Set(), columns: new Set() };
      if (suggestedFor) candidate.suggestedFor = suggestedFor;
      candidates.set(name, candidate);
      order.push(name);
    }
    candidate.sources.add(source);
    for (const column of columns ?? []) candidate.columns.add(column);
  };
  for (const name of requested ?? []) add(name, "--tables");
  for (const [name, entry] of usage.tables) for (const source of entry.sources) add(name, source, entry.columns);
  for (const name of COMMON_TABLES) add(name, "guess");

  const report = new Map<string, DiscoveredTable>();
  const schema: TableSchema[] = [];
  for (let index = 0; index < order.length; index++) {
    const name = order[index];
    const candidate = name ? candidates.get(name) : undefined;
    if (!name || !candidate) continue;
    const entry: DiscoveredTable = { name, sources: [...candidate.sources], status: "found" };
    if (candidate.suggestedFor) entry.suggestedFor = candidate.suggestedFor;
    report.set(name, entry);
    if (schema.length >= MAX_TABLES) {
      entry.status = "error";
      entry.note = `Not checked: more than ${MAX_TABLES} tables. Pass --tables to choose.`;
      continue;
    }

    requests++;
    const response = await rest.select(name, "select=*&limit=0", anonKey);
    const verdict = classify(response.status, response.text);
    if (verdict.probe === "missing") {
      entry.status = "not-found";
      const suggestion = verdict.error ? tableSuggestion(verdict.error) : null;
      if (suggestion && suggestion !== name) {
        entry.note = `PostgREST suggested ${suggestion}`;
        // A guess that PostgREST corrects to a table already on the list adds nothing worth showing.
        const guessOnly = candidate.sources.size === 1 && candidate.sources.has("guess");
        if (guessOnly && candidates.has(suggestion)) continue;
        add(suggestion, "postgrest-hint", undefined, name);
        const target = candidates.get(suggestion);
        if (target && !target.suggestedFor) target.suggestedFor = name;
        const later = report.get(suggestion);
        if (later && !later.sources.includes("postgrest-hint")) later.sources.push("postgrest-hint");
        if (later && !later.suggestedFor) later.suggestedFor = name;
      }
      continue;
    }
    if (verdict.probe === "error") {
      entry.status = "error";
      entry.note = `HTTP ${response.status} ${verdict.error?.message ?? ""}`.trim();
      continue;
    }

    const columns = new Map<string, ColumnSchema>();
    const probed = await confirmColumns(rest, anonKey, name, [
      "id",
      ...OWNER_COLUMNS,
      ...candidate.columns,
    ]);
    requests += probed.requests;
    for (const column of probed.columns) columns.set(column, guessColumn(column));
    const owned = OWNER_COLUMNS.some((column) => columns.has(column));
    if (owned || candidate.sources.has("--tables")) {
      const more = await confirmColumns(
        rest,
        anonKey,
        name,
        [...MARKER_COLUMNS, ...SENSITIVE_COLUMNS].filter((column) => !columns.has(column) && !probed.missing.has(column)),
      );
      requests += more.requests;
      for (const column of more.columns) columns.set(column, guessColumn(column));
    }
    const table = deriveTable(name, [...columns.values()]);
    schema.push(table);
    entry.ownerColumn = table.ownerColumn;
    entry.markerColumn = table.markerColumn;
    entry.columns = [...columns.keys()];
  }

  // Tables that only came from the guess list and do not exist are noise in the report.
  const tables = [...report.values()].filter(
    (entry) => !(entry.status === "not-found" && entry.sources.length === 1 && entry.sources[0] === "guess"),
  );
  schema.sort((a, b) => a.name.localeCompare(b.name));
  return { schema, tables, requests };
}

function classify(status: number, text: string): { probe: Probe; error: PostgrestError | null } {
  const error = status >= 300 ? parsePostgrestError(text) : null;
  if (status >= 200 && status < 300) return { probe: "exists", error };
  if ((status === 401 || status === 403) && error?.code === "42501") return { probe: "exists", error };
  if (status === 404 && (error?.code === "PGRST205" || error?.code === "42P01")) return { probe: "missing", error };
  return { probe: "error", error };
}

async function confirmColumns(
  rest: SupabaseClient,
  anonKey: string,
  table: string,
  candidates: string[],
): Promise<{ columns: string[]; missing: Set<string>; requests: number }> {
  const remaining = [...new Set(candidates.filter((column) => IDENT.test(column)))];
  const missing = new Set<string>();
  let requests = 0;
  while (remaining.length && requests < MAX_COLUMN_REQUESTS) {
    requests++;
    const response = await rest.select(table, `select=${remaining.join(",")}&limit=0`, anonKey);
    const verdict = classify(response.status, response.text);
    if (verdict.probe === "exists") return { columns: remaining, missing, requests };
    const error = verdict.error;
    const gone = error ? missingColumn(error) : null;
    if (!gone || !remaining.includes(gone)) break;
    remaining.splice(remaining.indexOf(gone), 1);
    missing.add(gone);
    const suggestion = error ? columnSuggestion(error) : null;
    if (suggestion && !remaining.includes(suggestion) && !missing.has(suggestion)) remaining.push(suggestion);
  }
  return { columns: [], missing, requests };
}

const NUMERIC = /(^|_)(count|credits|balance|amount|price|quantity|total|score|priority|position|rank)$/;

// Without the schema, types come from the name. The insert path corrects them from Postgres errors.
export function guessColumn(name: string): ColumnSchema {
  const column: ColumnSchema = { name, type: "string", required: false, primary: name === "id", hasDefault: name === "id" };
  if (name === "id" || name.endsWith("_id") || name === "uuid") column.format = "uuid";
  else if (/^(is|has|can)_/.test(name) || name === "admin" || name === "enabled" || name === "active") column.type = "boolean";
  else if (NUMERIC.test(name)) column.type = "number";
  else if (/_at$/.test(name)) {
    column.format = "date-time";
    column.hasDefault = true;
  }
  return column;
}
