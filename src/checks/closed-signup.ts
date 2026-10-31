import { appUrl } from "../target.js";
import type { HttpClient } from "../http.js";
import { parseSession } from "../supabase.js";
import type { ApiResult } from "../types.js";
import { curlOf, randomId } from "../util.js";
import type { Check } from "./common.js";
import { conclude, errored, skipped } from "./common.js";

const SIGNUP_PASSWORD = "nb-probe-signup-check";

const FIX =
  "Turn off public signups in the Supabase Auth settings, or reject them in a before-user-created hook. An invite check in the client, or only on your own signup route, leaves GoTrue open.";

export const closedSignup: Check = {
  id: "closed-signup",
  title: "Closed signup bypass",
  async run(ctx) {
    if (!ctx.config.closedSignup) {
      return [
        skipped(
          this.id,
          this.title,
          "Not requested. Pass --closed-signup when public registration should be refused.",
        ),
      ];
    }
    if (!ctx.supabase && !ctx.config.signupPath) {
      return [errored(this.id, this.title, "Pass --supabase-url or --signup-path so there is a signup request to make.")];
    }

    const attempts: { name: string; status: number; opened: boolean; repro: string; ambiguous: boolean }[] = [];
    try {
      if (ctx.supabase) {
        const email = `nb-probe-closed-${randomId()}@example.com`;
        const response = await ctx.supabase.rest.signUp(email, SIGNUP_PASSWORD);
        attempts.push(interpret("GoTrue", response, ctx));
      }
      if (ctx.config.signupPath) {
        const email = `nb-probe-closed-${randomId()}@example.com`;
        const response = await postSignup(ctx.http, appUrl(ctx.config.target, ctx.config.signupPath), email);
        attempts.push(interpret("app signup", response, ctx));
      }
    } catch (err) {
      return [errored(this.id, this.title, err instanceof Error ? err.message : String(err))];
    }

    const opened = attempts.filter((attempt) => attempt.opened);
    if (opened.length) {
      const names = opened.map((attempt) => `${attempt.name} HTTP ${attempt.status}`).join(", ");
      return [
        conclude({
          id: this.id,
          title: this.title,
          status: "fail",
          severity: "medium",
          summary: `Signup created a user without an invite (${names}).`,
          fix: FIX,
          repro: opened[0]?.repro,
          evidence: { attempts: attempts.map(({ name, status, opened: didOpen }) => ({ name, status, opened: didOpen })) },
        }),
      ];
    }
    if (attempts.some((attempt) => attempt.ambiguous)) {
      return [
        errored(
          this.id,
          this.title,
          "Signup returned success without a user id, so it is not clear whether an account was created.",
          attempts[0]?.repro,
        ),
      ];
    }
    const detail = attempts.map((attempt) => `${attempt.name} HTTP ${attempt.status}`).join(", ");
    return [
      conclude({
        id: this.id,
        title: this.title,
        status: "pass",
        severity: "info",
        summary: `Public signup was refused (${detail}).`,
        evidence: { attempts: attempts.map(({ name, status }) => ({ name, status })) },
      }),
    ];
  },
};

function interpret(name: string, response: ApiResult, ctx: { ephemeralUserIds: string[] }): {
  name: string;
  status: number;
  opened: boolean;
  repro: string;
  ambiguous: boolean;
} {
  const session = parseSession(response.text);
  const opened = response.status >= 200 && response.status < 300 && Boolean(session?.id);
  if (opened && session?.id) ctx.ephemeralUserIds.push(session.id);
  const ambiguous = response.status >= 200 && response.status < 300 && !session?.id;
  return { name, status: response.status, opened, repro: curlOf(response), ambiguous };
}

async function postSignup(http: HttpClient, url: string, email: string): Promise<ApiResult> {
  const headers = { "content-type": "application/json", accept: "application/json" };
  const body = JSON.stringify({ email, password: SIGNUP_PASSWORD });
  const response = await http.request(url, { method: "POST", headers, body });
  return {
    status: response.status,
    text: response.text,
    url: response.url,
    method: "POST",
    requestHeaders: headers,
    body,
  };
}
