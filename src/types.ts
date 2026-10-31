export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type CheckStatus = "pass" | "fail" | "skip" | "error";

export interface CheckResult {
  id: string;
  title: string;
  status: CheckStatus;
  severity: Severity;
  summary: string;
  fix?: string;
  repro?: string;
  evidence?: Record<string, unknown>;
}

export interface ScanReport {
  tool: "nb-probe";
  version: string;
  schemaVersion: 1;
  target: string;
  supabaseUrl?: string;
  ownership: "verified" | "refused";
  // The URL that served the matching ownership token.
  ownershipFile?: string;
  message?: string;
  startedAt: string;
  finishedAt: string;
  results: CheckResult[];
  summary: {
    pass: number;
    fail: number;
    skip: number;
    error: number;
  };
  notes: string[];
  // Where the probed tables came from. Absent when no Supabase project was given.
  discovery?: DiscoveryReport;
}

// openapi: the /rest/v1/ schema. --tables: named by the user. bundle: a supabase-js call in a
// same-origin script. source-map: the same, inside a published source map. postgrest-hint: a
// "Perhaps you meant" suggestion in a PostgREST error. guess: a common table name.
export type TableSource = "openapi" | "--tables" | "bundle" | "source-map" | "postgrest-hint" | "guess";

export interface DiscoveredTable {
  name: string;
  sources: TableSource[];
  // probed: canary rows were attempted. found: the table exists but was not probed (see note).
  status: "probed" | "found" | "not-found" | "error";
  note?: string;
  // The name PostgREST corrected to this one, for postgrest-hint tables.
  suggestedFor?: string;
  ownerColumn?: string | null;
  markerColumn?: string | null;
  columns?: string[];
}

export interface DiscoveryReport {
  schema: "openapi" | "discovery";
  openApi: { status: number | null; message?: string };
  files: { pages: number; scripts: number; sourceMaps: number; errors: string[] };
  tables: DiscoveredTable[];
  // Seen in the bundle and listed for the report. nb-probe never calls an RPC.
  rpcs: string[];
  buckets: string[];
  // Supabase project hosts named in the bundle, to catch a scan pointed at the wrong project.
  projects: string[];
  requests: number;
}

export interface ScanConfig {
  url?: string;
  token?: string;
  supabaseUrl?: string;
  anonKey?: string;
  serviceRole?: string;
  tables?: string[] | string;
  userA?: string;
  userB?: string;
  userAEmail?: string;
  userAPassword?: string;
  userBEmail?: string;
  userBPassword?: string;
  signupPath?: string;
  closedSignup?: boolean;
  webhookPath?: string;
  llmPath?: string;
  only?: string[] | string;
  timeoutMs?: number;
  cleanup?: boolean;
}

export interface ColumnSchema {
  name: string;
  type: "string" | "number" | "boolean" | "unknown";
  format?: string;
  required: boolean;
  primary: boolean;
  hasDefault: boolean;
}

export interface TableSchema {
  name: string;
  columns: ColumnSchema[];
  primaryKey: string | null;
  ownerColumn: string | null;
  markerColumn: string | null;
  sensitiveColumns: string[];
}

export interface SessionUser {
  id: string;
  email: string;
  accessToken: string;
}

export interface Canary {
  table: string;
  idColumn: string;
  id: string;
  markerColumn: string | null;
  marker: string;
  side: "a" | "b";
  sensitiveColumns: string[];
}

export interface ApiResult {
  status: number;
  text: string;
  url: string;
  method: string;
  requestHeaders: Record<string, string>;
  body?: string;
}
