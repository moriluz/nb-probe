export function rowsFromBody(text: string): {
  rows: Record<string, unknown>[];
  error?: string;
} {
  if (!text.trim()) return { rows: [] };
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return { rows: [], error: "response was not JSON" };
  }
  if (Array.isArray(json)) {
    const rows = json.filter(
      (row): row is Record<string, unknown> =>
        !!row && typeof row === "object" && !Array.isArray(row),
    );
    return { rows };
  }
  if (json && typeof json === "object") {
    const obj = json as Record<string, unknown>;
    if (typeof obj.message === "string" || typeof obj.msg === "string" || typeof obj.error === "string") {
      const message =
        (typeof obj.message === "string" && obj.message) ||
        (typeof obj.msg === "string" && obj.msg) ||
        (typeof obj.error === "string" && obj.error) ||
        "request failed";
      if (!("id" in obj)) return { rows: [], error: message };
    }
    return { rows: [obj] };
  }
  return { rows: [], error: "unexpected JSON" };
}

export function rowId(row: Record<string, unknown>, idColumn: string): string | null {
  const value = row[idColumn] ?? row.id;
  if (typeof value === "string" && value) return value;
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

export function valueStuck(actual: unknown, expected: unknown): boolean {
  if (actual === expected) return true;
  if (typeof expected === "number" && (actual === expected || actual === String(expected))) return true;
  if (typeof expected === "boolean" && (actual === expected || actual === String(expected))) return true;
  return false;
}
