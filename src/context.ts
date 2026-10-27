import type { ResolvedConfig } from "./config.js";
import type { HttpClient } from "./http.js";
import type { SupabaseClient } from "./supabase.js";
import type { Canary, SessionUser, TableSchema } from "./types.js";

export interface SupabaseState {
  rest: SupabaseClient;
  schema: TableSchema[];
  selected: TableSchema[];
  userA?: SessionUser;
  userB?: SessionUser;
  usersCreatedByUs: boolean;
  canaries: Canary[];
  insertErrors: string[];
  provisionError?: string;
}

export interface ScanContext {
  config: ResolvedConfig;
  http: HttpClient;
  origin: string;
  notes: string[];
  ephemeralUserIds: string[];
  supabase?: SupabaseState;
}
