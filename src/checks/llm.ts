import type { HttpClient } from "../http.js";
import type { ApiResult } from "../types.js";
import { errorMessage, toCurl } from "../util.js";
import type { Check } from "./common.js";
import { conclude, errored, skipped } from "./common.js";

const BODY = JSON.stringify({
  messages: [{ role: "user", content: "nb-probe ping" }],
  model: "nb-probe-override-model",
  max_tokens: 999999,
});

const FIX =
  "Require a session before the handler calls a model. Choose model and max_tokens on the server, and ignore those fields if the client sends them.";

export const llmEndpoint: Check = {
  id: "llm-endpoint",
  title: "LLM endpoint auth and client overrides",
  async run(ctx) {
    let found: { path: string; unauth: ApiResult } | undefined;
    const missing: string[] = [];
    for (const path of ctx.config.llmPaths) {
      try {
        const unauth = await post(ctx.http, `${ctx.origin}${path}`, undefined);
        if (unauth.status === 404) {
          missing.push(path);
          continue;
        }
        found = { path, unauth };
        break;
      } catch (err) {
        return [errored(this.id, this.title, `POST ${path} failed: ${errorMessage(err)}`)];
      }
    }
    if (!found) {
      const where = ctx.config.llmExplicit ? missing.join(", ") : "the default paths";
      return [
        skipped(
          this.id,
          this.title,
          `No LLM endpoint at ${where} (HTTP 404). Pass --llm-path if it lives somewhere else.`,
        ),
      ];
    }

    const unauthRejected = authRejected(found.unauth.status, found.unauth.text);
    const unauthOverride = honorsOverride(found.unauth.text);
    const unauthOpen = found.unauth.status >= 200 && found.unauth.status < 300 && !unauthRejected;

    let auth: ApiResult | undefined;
    const bearer = ctx.supabase?.userA?.accessToken;
    if (!unauthOpen && bearer) {
      try {
        auth = await post(ctx.http, `${ctx.origin}${found.path}`, bearer);
      } catch (err) {
        return [errored(this.id, this.title, `Authenticated POST ${found.path} failed: ${errorMessage(err)}`)];
      }
    }
    const authOverride = auth ? honorsOverride(auth.text) : { model: false, maxTokens: false };
    const override = unauthOverride.model || unauthOverride.maxTokens || authOverride.model || authOverride.maxTokens;

    if (unauthOpen) {
      const extra = override ? " The response honored a client model or max_tokens override." : "";
      return [
        conclude({
          id: this.id,
          title: this.title,
          status: "fail",
          severity: "high",
          summary: `POST ${found.path} answered without a session (HTTP ${found.unauth.status}).${extra}`,
          fix: FIX,
          repro: curlOf(found.unauth),
          evidence: evidence(found.path, found.unauth.status, auth?.status, override),
        }),
      ];
    }

    if (!unauthRejected && found.unauth.status >= 500) {
      return [
        errored(
          this.id,
          this.title,
          `POST ${found.path} returned HTTP ${found.unauth.status} instead of an auth decision.`,
          curlOf(found.unauth),
        ),
      ];
    }
    if (!unauthRejected) {
      return [
        errored(
          this.id,
          this.title,
          `POST ${found.path} returned HTTP ${found.unauth.status}, which is not a clear rejection or a model response.`,
          curlOf(found.unauth),
        ),
      ];
    }

    if (auth && auth.status >= 200 && auth.status < 300 && override) {
      return [
        conclude({
          id: this.id,
          title: this.title,
          status: "fail",
          severity: "medium",
          summary: `POST ${found.path} rejected an anonymous caller (HTTP ${found.unauth.status}), then honored a client model or max_tokens override for a signed-in probe user.`,
          fix: FIX,
          repro: curlOf(auth),
          evidence: evidence(found.path, found.unauth.status, auth.status, true),
        }),
      ];
    }

    const authNote = authNoteFor(auth, Boolean(bearer));
    return [
      conclude({
        id: this.id,
        title: this.title,
        status: "pass",
        severity: "info",
        summary: `POST ${found.path} rejected an anonymous caller (HTTP ${found.unauth.status}). ${authNote}`,
        evidence: evidence(found.path, found.unauth.status, auth?.status, false),
      }),
    ];
  },
};

function authNoteFor(auth: ApiResult | undefined, hadBearer: boolean): string {
  if (!hadBearer) return "No probe session was available to test model or max_tokens overrides.";
  if (!auth) return "No authenticated response was captured.";
  if (auth.status >= 200 && auth.status < 300) return "The authenticated response ignored client model and max_tokens.";
  if (authRejected(auth.status, auth.text)) {
    return "The probe bearer token was not accepted, so a client override could not be confirmed. Cookie sessions are not sent.";
  }
  return `The authenticated call returned HTTP ${auth.status}.`;
}

function evidence(path: string, unauthStatus: number, authStatus: number | undefined, override: boolean): Record<string, unknown> {
  const value: Record<string, unknown> = { path, unauthStatus, clientOverride: override };
  if (authStatus !== undefined) value.authStatus = authStatus;
  return value;
}

function honorsOverride(text: string): { model: boolean; maxTokens: boolean } {
  try {
    const json: unknown = JSON.parse(text);
    return { model: readField(json, ["model"], "nb-probe-override-model"), maxTokens: readNumber(json) };
  } catch {
    return { model: false, maxTokens: false };
  }
}

function readField(value: unknown, keys: string[], expected: unknown, depth = 0): boolean {
  if (!value || typeof value !== "object" || depth > 2) return false;
  const record = value as Record<string, unknown>;
  if (keys.some((key) => record[key] === expected)) return true;
  for (const nested of ["data", "result", "response"]) {
    if (readField(record[nested], keys, expected, depth + 1)) return true;
  }
  return false;
}

function readNumber(value: unknown, depth = 0): boolean {
  if (!value || typeof value !== "object" || depth > 2) return false;
  const record = value as Record<string, unknown>;
  if (record.max_tokens === 999999 || record.maxTokens === 999999) return true;
  for (const nested of ["data", "result", "response"]) {
    if (readNumber(record[nested], depth + 1)) return true;
  }
  return false;
}

function authRejected(status: number, text: string): boolean {
  if (status === 401 || status === 403) return true;
  if (status === 400 || status === 422) {
    return /unauthor|forbidden|not authenticated|sign in|login required|missing session|no session/i.test(text);
  }
  return false;
}

async function post(http: HttpClient, url: string, bearer: string | undefined): Promise<ApiResult> {
  const headers: Record<string, string> = {
    "content-type": "application/json",
    accept: "application/json",
  };
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  const response = await http.request(url, { method: "POST", headers, body: BODY });
  return {
    status: response.status,
    text: response.text,
    url: response.url,
    method: "POST",
    requestHeaders: headers,
    body: BODY,
  };
}

function curlOf(result: ApiResult): string {
  return toCurl({
    method: result.method,
    url: result.url,
    headers: result.requestHeaders,
    body: result.body,
  });
}
