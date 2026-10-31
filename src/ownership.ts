import type { HttpClient } from "./http.js";
import type { AppTarget } from "./target.js";
import { errorMessage, parseOwnershipBody, tokensMatch } from "./util.js";

export const OWNERSHIP_FILE = ".well-known/neural-breach";

export type OwnershipResult = { ok: true; url: string } | { ok: false; message: string };

// Where the ownership file may live, in the order it is checked. A root app: only
// <origin>/.well-known/neural-breach. A sub-path app (https://host/sub/): first
// <origin>/sub/.well-known/neural-breach, then <origin>/.well-known/neural-breach, because whoever
// controls the origin root controls every path on it.
export function ownershipUrls(target: AppTarget): string[] {
  const root = `${target.origin}/${OWNERSHIP_FILE}`;
  if (target.basePath === "/") return [root];
  return [`${target.base}${OWNERSHIP_FILE}`, root];
}

type Attempt =
  | { kind: "match" }
  | { kind: "mismatch"; message: string }
  | { kind: "absent"; message: string };

// The first location that serves a matching token wins. A location that serves a different token
// stops the scan right there; it does not fall through to the next location. Anything else
// (404, a redirect, an HTML fallback page, a network error) moves on to the next location.
export async function checkOwnership(http: HttpClient, target: AppTarget, token: string): Promise<OwnershipResult> {
  const urls = ownershipUrls(target);
  const problems: string[] = [];
  for (const url of urls) {
    const attempt = await tryLocation(http, url, token);
    if (attempt.kind === "match") return { ok: true, url };
    if (attempt.kind === "mismatch") return { ok: false, message: attempt.message };
    problems.push(attempt.message);
  }
  const intro =
    urls.length > 1
      ? `No ownership file with your token at ${urls.map(pathOf).join(" or ")}. The scan did not run.`
      : "The scan stops until the ownership file answers 200 with your token.";
  return { ok: false, message: `${intro} ${problems.join(" ")}`.trim() };
}

async function tryLocation(http: HttpClient, url: string, token: string): Promise<Attempt> {
  const path = pathOf(url);
  try {
    const response = await http.request(url, {
      allowRedirects: false,
      maxBytes: 4096,
      headers: { accept: "text/plain, application/json" },
    });
    if (response.status >= 300 && response.status < 400) {
      return { kind: "absent", message: `GET ${path} redirected. Serve the ownership file directly with HTTP 200.` };
    }
    if (response.status !== 200) {
      return { kind: "absent", message: `GET ${path} returned HTTP ${response.status}.` };
    }
    if (response.truncated) {
      return { kind: "absent", message: `GET ${path} was too large. The ownership file should be the token and nothing else.` };
    }
    const presented = parseOwnershipBody(response.text);
    if (!presented) {
      return {
        kind: "absent",
        message: `GET ${path} was not a token. Serve the raw token as text/plain, or {"token":"<value>"} as JSON.`,
      };
    }
    if (!tokensMatch(token, presented)) {
      return { kind: "mismatch", message: `The ownership file at ${path} did not match --token. The scan did not run.` };
    }
    return { kind: "match" };
  } catch (err) {
    return { kind: "absent", message: `Could not fetch ${path}: ${errorMessage(err)}` };
  }
}

function pathOf(url: string): string {
  try {
    return new URL(url).pathname;
  } catch {
    return url;
  }
}
