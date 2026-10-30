import type { ColumnSchema, TableSchema } from "./types.js";

export const OWNER_COLUMNS = ["user_id", "owner_id", "created_by", "author_id"];
export const MARKER_COLUMNS = [
  "note",
  "notes",
  "body",
  "content",
  "title",
  "name",
  "display_name",
  "description",
  "bio",
  "message",
  "text",
  "comment",
];
export const SENSITIVE_COLUMNS = [
  "role",
  "is_admin",
  "is_superadmin",
  "admin",
  "plan",
  "tier",
  "credits",
  "credit_balance",
  "balance",
];

const IDENT = /^[A-Za-z_][A-Za-z0-9_]*$/;

function mapType(type: unknown): ColumnSchema["type"] {
  if (type === "integer" || type === "number") return "number";
  if (type === "boolean") return "boolean";
  if (type === "string") return "string";
  if (Array.isArray(type)) {
    const first = type.find((item) => item !== "null");
    return mapType(first);
  }
  return "unknown";
}

function schemaMaps(doc: Record<string, unknown>): Record<string, unknown> {
  const merged: Record<string, unknown> = {};
  const definitions = doc.definitions;
  if (definitions && typeof definitions === "object") Object.assign(merged, definitions);
  const components = doc.components;
  if (components && typeof components === "object") {
    const schemas = (components as { schemas?: unknown }).schemas;
    if (schemas && typeof schemas === "object") Object.assign(merged, schemas);
  }
  return merged;
}

function tableNames(doc: Record<string, unknown>): string[] {
  const paths = doc.paths;
  if (!paths || typeof paths !== "object") return [];
  const names: string[] = [];
  for (const key of Object.keys(paths)) {
    if (!key.startsWith("/")) continue;
    const rest = key.slice(1);
    if (!rest || rest.includes("/") || rest.includes("{") || !IDENT.test(rest)) continue;
    names.push(rest);
  }
  return names;
}

function parseTable(name: string, definition: unknown): TableSchema {
  const empty: TableSchema = {
    name,
    columns: [],
    primaryKey: null,
    ownerColumn: null,
    markerColumn: null,
    sensitiveColumns: [],
  };
  if (!definition || typeof definition !== "object") return empty;
  const def = definition as { properties?: unknown; required?: unknown };
  const properties = def.properties;
  if (!properties || typeof properties !== "object") return empty;
  const required = new Set(
    Array.isArray(def.required) ? def.required.filter((item): item is string => typeof item === "string") : [],
  );
  const columns: ColumnSchema[] = [];
  for (const [columnName, prop] of Object.entries(properties)) {
    if (!IDENT.test(columnName) || !prop || typeof prop !== "object") continue;
    const value = prop as Record<string, unknown>;
    const description = typeof value.description === "string" ? value.description : "";
    const primary = description.includes("<pk/>") || value["x-primary-key"] === true;
    const column: ColumnSchema = {
      name: columnName,
      type: mapType(value.type),
      required: required.has(columnName),
      primary,
      hasDefault: "default" in value || primary || value.readOnly === true,
    };
    if (typeof value.format === "string") column.format = value.format;
    columns.push(column);
  }

  return deriveTable(name, columns);
}

// Picks the primary key, owner, marker, and privileged columns from a column list. Shared by the
// OpenAPI parser and by bundle discovery, so both paths choose the same columns.
export function deriveTable(name: string, columns: ColumnSchema[]): TableSchema {
  const primaryKey = columns.find((column) => column.primary)?.name ?? columns.find((column) => column.name === "id")?.name ?? null;
  const sensitive = new Set(SENSITIVE_COLUMNS);
  const ownerColumn = OWNER_COLUMNS.find((candidate) => columns.some((column) => column.name === candidate)) ?? null;
  const markerColumn =
    MARKER_COLUMNS.find((candidate) => {
      const column = columns.find((item) => item.name === candidate);
      if (!column) return false;
      if (column.name === ownerColumn || column.name === primaryKey) return false;
      if (sensitive.has(column.name)) return false;
      return column.type === "string" || column.type === "unknown";
    }) ?? null;

  return {
    name,
    columns,
    primaryKey,
    ownerColumn,
    markerColumn,
    sensitiveColumns: columns.map((column) => column.name).filter((columnName) => sensitive.has(columnName)),
  };
}

export function parseOpenApi(text: string): TableSchema[] {
  let doc: unknown;
  try {
    doc = JSON.parse(text);
  } catch {
    throw new Error("OpenAPI document was not JSON.");
  }
  if (!doc || typeof doc !== "object" || Array.isArray(doc)) {
    throw new Error("OpenAPI document was not an object.");
  }
  const record = doc as Record<string, unknown>;
  const schemas = schemaMaps(record);
  const tables = tableNames(record).map((name) => parseTable(name, schemas[name]));
  tables.sort((a, b) => a.name.localeCompare(b.name));
  return tables;
}

export function selectTables(
  schema: TableSchema[],
  requested?: string[],
): { tables: TableSchema[]; missing: string[]; truncatedFrom: number } {
  if (requested && requested.length) {
    const byName = new Map(schema.map((table) => [table.name, table]));
    const tables: TableSchema[] = [];
    const missing: string[] = [];
    for (const name of requested) {
      const table = byName.get(name);
      if (table) tables.push(table);
      else missing.push(name);
    }
    return { tables, missing, truncatedFrom: 0 };
  }
  const owned = schema.filter((table) => table.ownerColumn).sort((a, b) => a.name.localeCompare(b.name));
  if (owned.length > 20) {
    return { tables: owned.slice(0, 20), missing: [], truncatedFrom: owned.length };
  }
  return { tables: owned, missing: [], truncatedFrom: 0 };
}
