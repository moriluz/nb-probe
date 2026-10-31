import type { HttpClient } from "./http.js";
import type { ApiResult } from "./types.js";
import { assertIdent, assertNotServiceRole, isJwt } from "./util.js";

export class SupabaseClient {
  constructor(
    private readonly http: HttpClient,
    private readonly base: string,
    private readonly anonKey: string,
  ) {}

  openApi(): Promise<ApiResult> {
    return this.call("GET", "/rest/v1/", this.anonKey, undefined, {
      accept: "application/openapi+json",
    });
  }

  signUp(email: string, password: string): Promise<ApiResult> {
    return this.auth("/auth/v1/signup", { email, password });
  }

  passwordGrant(email: string, password: string): Promise<ApiResult> {
    return this.auth("/auth/v1/token?grant_type=password", { email, password });
  }

  select(table: string, query: string, bearer: string): Promise<ApiResult> {
    assertIdent(table, "table");
    const path = query ? `/rest/v1/${table}?${query}` : `/rest/v1/${table}`;
    return this.call("GET", path, bearer);
  }

  insert(table: string, row: Record<string, unknown>, bearer: string): Promise<ApiResult> {
    assertIdent(table, "table");
    return this.call("POST", `/rest/v1/${table}`, bearer, row, { prefer: "return=representation" });
  }

  update(table: string, filter: string, patch: Record<string, unknown>, bearer: string): Promise<ApiResult> {
    assertIdent(table, "table");
    if (!filter.includes("=eq.")) throw new Error("Refusing an unfiltered update.");
    return this.call("PATCH", `/rest/v1/${table}?${filter}`, bearer, patch, {
      prefer: "return=representation",
    });
  }

  remove(table: string, filter: string, bearer: string): Promise<ApiResult> {
    assertIdent(table, "table");
    if (!filter.includes("=eq.")) throw new Error("Refusing an unfiltered delete.");
    return this.call("DELETE", `/rest/v1/${table}?${filter}`, bearer, undefined, {
      prefer: "return=representation",
    });
  }

  async admin(method: string, path: string, serviceKey: string, body?: unknown): Promise<ApiResult> {
    if (!path.startsWith("/auth/v1/admin/")) {
      throw new Error("Service role calls are limited to /auth/v1/admin/.");
    }
    const headers: Record<string, string> = { apikey: serviceKey, accept: "application/json" };
    // sb_secret_ keys are not JWTs. The hosted gateway reads them from apikey only.
    if (isJwt(serviceKey)) headers.authorization = `Bearer ${serviceKey}`;
    let payload: string | undefined;
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    }
    return this.send(method, path, headers, payload);
  }

  private auth(path: string, body: Record<string, unknown>): Promise<ApiResult> {
    return this.call("POST", path, this.anonKey, body);
  }

  private call(
    method: string,
    path: string,
    bearer: string,
    body?: unknown,
    extra?: Record<string, string>,
  ): Promise<ApiResult> {
    if (path.startsWith("/rest/v1")) assertNotServiceRole(bearer);
    const headers: Record<string, string> = { apikey: this.anonKey, accept: "application/json" };
    // Authorization carries a JWT only. An sb_publishable_ key there gets PGRST301 ("Expected 3 parts
    // in JWT"), so anonymous calls with a publishable key send apikey alone and the gateway maps it to anon.
    if (isJwt(bearer)) headers.authorization = `Bearer ${bearer}`;
    Object.assign(headers, extra);
    let payload: string | undefined;
    if (body !== undefined) {
      headers["content-type"] = "application/json";
      payload = JSON.stringify(body);
    }
    return this.send(method, path, headers, payload);
  }

  private async send(
    method: string,
    path: string,
    headers: Record<string, string>,
    body?: string,
  ): Promise<ApiResult> {
    const response = await this.http.request(`${this.base}${path}`, { method, headers, body });
    const result: ApiResult = {
      status: response.status,
      text: response.text,
      url: response.url,
      method,
      requestHeaders: headers,
    };
    if (body !== undefined) result.body = body;
    return result;
  }
}

export function parseSession(text: string): { id: string; email: string; accessToken: string } | null {
  try {
    const json: unknown = JSON.parse(text);
    if (!json || typeof json !== "object") return null;
    const record = json as Record<string, unknown>;
    const accessToken = typeof record.access_token === "string" ? record.access_token : "";
    const user =
      record.user && typeof record.user === "object" ? (record.user as Record<string, unknown>) : record;
    const id = typeof user.id === "string" ? user.id : "";
    const email = typeof user.email === "string" ? user.email : "";
    if (!id) return null;
    return { id, email, accessToken };
  } catch {
    return null;
  }
}
