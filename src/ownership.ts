import type { HttpClient } from "./http.js";
import { errorMessage, parseOwnershipBody, tokensMatch } from "./util.js";

export async function checkOwnership(
  http: HttpClient,
  origin: string,
  token: string,
): Promise<{ ok: true } | { ok: false; message: string }> {
  const url = `${origin}/.well-known/neural-breach`;
  try {
    const response = await http.request(url, {
      allowRedirects: false,
      maxBytes: 4096,
      headers: { accept: "text/plain, application/json" },
    });
    if (response.status >= 300 && response.status < 400) {
      return {
        ok: false,
        message: "The ownership file redirected. Serve it directly from the origin with HTTP 200.",
      };
    }
    if (response.status !== 200) {
      return {
        ok: false,
        message: `GET /.well-known/neural-breach returned HTTP ${response.status}. The scan stops until that path answers 200 with your token.`,
      };
    }
    if (response.truncated) {
      return { ok: false, message: "The ownership file is too large. It should be the token and nothing else." };
    }
    const presented = parseOwnershipBody(response.text);
    if (!presented) {
      return {
        ok: false,
        message: 'The ownership file was not a token. Serve the raw token as text/plain, or {"token":"<value>"} as JSON.',
      };
    }
    if (!tokensMatch(token, presented)) {
      return { ok: false, message: "The ownership file did not match --token. The scan did not run." };
    }
    return { ok: true };
  } catch (err) {
    return { ok: false, message: `Could not fetch /.well-known/neural-breach: ${errorMessage(err)}` };
  }
}
