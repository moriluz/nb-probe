import type { Bundle } from "./bundle.js";
import type { ResolvedConfig } from "./config.js";
import type { HttpClient } from "./http.js";
import type { SupabaseClient } from "./supabase.js";
import type { Canary, DiscoveryReport, SessionUser, TableSchema } from "./types.js";

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
  // Set when no table could be probed for a reason that is not an error, for example nothing was discovered.
  skipReason?: string;
  discovery?: DiscoveryReport;
}

export interface ScanContext {
  config: ResolvedConfig;
  http: HttpClient;
  // The app origin. App routes are built with appUrl(config.target, path), which keeps a sub-path.
  origin: string;
  notes: string[];
  ephemeralUserIds: string[];
  supabase?: SupabaseState;
  bundle?: Promise<Bundle>;
}
