import { appUrl } from "../target.js";
import type { HttpClient } from "../http.js";
import type { ApiResult } from "../types.js";
import { errorMessage, toCurl } from "../util.js";
import type { Check } from "./common.js";
import { conclude, errored, NO_ROUTE, skipped } from "./common.js";

const STRIPE_FIX =
  "Verify Stripe-Signature against the raw body and the endpoint secret before parsing the event. Return 400 when the header is missing or invalid.";

const GENERIC_FIX =
  "Reject this POST unless it carries a signature you verify. Return 400 when the signature is missing.";

const PAYLOAD = JSON.stringify({
  id: "evt_nb_probe_canary",
  object: "event",
  type: "checkout.session.completed",
  data: {
    object: {
      id: "cs_nb_probe_canary",
      object: "checkout.session",
      metadata: { nb_probe: "canary" },
    },
  },
});

export const webhookSignature: Check = {
  id: "webhook-signature",
  title: "Unsigned webhook",
  async run(ctx) {
    const tried: string[] = [];
    for (const path of ctx.config.webhookPaths) {
      tried.push(path);
      let response;
      try {
        response = await post(ctx.http, appUrl(ctx.config.target, path));
      } catch (err) {
        return [errored(this.id, this.title, `POST ${path} failed: ${errorMessage(err)}`)];
      }
      if (NO_ROUTE.has(response.status)) continue;
      const repro = toCurl({
        method: "POST",
        url: response.url,
        headers: response.requestHeaders,
        body: response.body,
      });
      const stripe = path.toLowerCase().includes("stripe");
      const fix = stripe ? STRIPE_FIX : GENERIC_FIX;
      if (response.status >= 200 && response.status < 300) {
        return [
          conclude({
            id: this.id,
            title: this.title,
            status: "fail",
            severity: "high",
            summary: `Unsigned POST to ${path} was accepted (HTTP ${response.status}).`,
            fix,
            repro,
            evidence: { path, status: response.status },
          }),
        ];
      }
      if (response.status >= 500) {
        return [
          conclude({
            id: this.id,
            title: this.title,
            status: "fail",
            severity: "medium",
            summary: `Unsigned POST to ${path} was not rejected cleanly (HTTP ${response.status}). A signature check should return 400 before the handler runs.`,
            fix,
            repro,
            evidence: { path, status: response.status },
          }),
        ];
      }
      if ([400, 401, 403, 415, 422].includes(response.status)) {
        return [
          conclude({
            id: this.id,
            title: this.title,
            status: "pass",
            severity: "info",
            summary: `Unsigned POST to ${path} was rejected (HTTP ${response.status}).`,
            evidence: { path, status: response.status },
          }),
        ];
      }
      return [
        errored(
          this.id,
          this.title,
          `Unsigned POST to ${path} returned HTTP ${response.status}, which is neither acceptance nor a clear rejection.`,
          repro,
        ),
      ];
    }
    const where = ctx.config.webhookExplicit ? tried.join(", ") : "the default paths";
    return [
      skipped(
        this.id,
        this.title,
        `No webhook endpoint at ${where} (HTTP 404, 405, or 501). Pass --webhook-path if it lives somewhere else.`,
      ),
    ];
  },
};

async function post(http: HttpClient, url: string): Promise<ApiResult> {
  const headers = { "content-type": "application/json", accept: "application/json" };
  const response = await http.request(url, { method: "POST", headers, body: PAYLOAD });
  return {
    status: response.status,
    text: response.text,
    url: response.url,
    method: "POST",
    requestHeaders: headers,
    body: PAYLOAD,
  };
}
