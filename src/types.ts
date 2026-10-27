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
