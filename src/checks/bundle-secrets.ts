import { findSecrets, type SecretHit } from "../secrets.js";
import { errorMessage, sameOriginUrl, shellQuote } from "../util.js";
import type { Check } from "./common.js";
import { conclude, errored } from "./common.js";

const SECRET_FIX =
  "Rotate the leaked key, then remove it from the client bundle. The anon key is public. A service role key, an sb_secret key, and a Stripe secret key are not. NEXT_PUBLIC_ and Vite env values are shipped to the browser.";

const MAP_FIX =
  "Remove sourceMappingURL from public JavaScript, or do not serve the .map files from the origin. Send source maps to your error tracker if you need them.";

const SEVERITY_SCORE = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };

export const bundleSecrets: Check = {
  id: "bundle-secrets",
  title: "Secrets in the client bundle",
  async run(ctx) {
    let page;
    try {
      page = await ctx.http.request(`${ctx.origin}/`, {
        maxBytes: 1_500_000,
        headers: { accept: "text/html" },
      });
    } catch (err) {
      return [errored(this.id, this.title, `Could not fetch the entry page: ${errorMessage(err)}`)];
    }
    if (page.status !== 200) {
      return [errored(this.id, this.title, `Entry page returned HTTP ${page.status}.`)];
    }

    const files: { file: string; text: string }[] = [{ file: page.url, text: page.text }];
    const scripts = extractScriptSrcs(page.text, ctx.origin).slice(0, 15);
    const downloadErrors: string[] = [];
    for (const scriptUrl of scripts) {
      try {
        const script = await ctx.http.request(scriptUrl, { maxBytes: 1_500_000 });
        if (script.status === 200) files.push({ file: script.url, text: script.text });
        else downloadErrors.push(`${pathOf(scriptUrl)} HTTP ${script.status}`);
      } catch (err) {
        downloadErrors.push(`${pathOf(scriptUrl)} ${errorMessage(err)}`);
      }
    }

    const hits = findSecrets(files, [ctx.config.anonKey ?? ""].filter(Boolean));
    if (hits.length === 0 && scripts.length > 0 && files.length === 1 && downloadErrors.length > 0) {
      return [errored(this.id, this.title, `Could not download same-origin scripts. ${downloadErrors.join("; ")}`)];
    }
    if (hits.length === 0) {
      return [
        conclude({
          id: this.id,
          title: this.title,
          status: "pass",
          severity: "info",
          summary:
            "No service-role key, sb_secret key, Stripe secret, or source map in the entry page or its same-origin scripts.",
          evidence: { scripts: scripts.map(pathOf) },
        }),
      ];
    }

    const primary = [...hits].sort((left, right) => SEVERITY_SCORE[right.severity] - SEVERITY_SCORE[left.severity])[0];
    if (!primary) return [errored(this.id, this.title, "Secret scan produced an empty hit.")];
    return [
      conclude({
        id: this.id,
        title: this.title,
        status: "fail",
        severity: primary.severity,
        summary: `Client bundle exposes ${describe(hits)}.`,
        fix: hits.every((hit) => hit.kind === "source_map") ? MAP_FIX : SECRET_FIX,
        repro: reproFor(primary),
        evidence: {
          hits: hits.map((hit) => ({ kind: hit.kind, file: pathOf(hit.file), preview: hit.preview })),
        },
      }),
    ];
  },
};

function describe(hits: SecretHit[]): string {
  const parts: string[] = [];
  if (hits.some((hit) => hit.kind === "service_role")) parts.push("a service_role JWT");
  if (hits.some((hit) => hit.kind === "sb_secret")) parts.push("an sb_secret key");
  if (hits.some((hit) => hit.kind === "stripe_secret")) parts.push("a Stripe secret key");
  if (hits.some((hit) => hit.kind === "source_map")) parts.push("a source map reference");
  if (parts.length <= 1) return parts[0] ?? "a secret";
  const last = parts[parts.length - 1] ?? "a secret";
  return `${parts.slice(0, -1).join(", ")} and ${last}`;
}

function reproFor(hit: SecretHit): string {
  if (hit.kind === "source_map") return `curl -sS ${shellQuote(hit.file)} | grep -n sourceMappingURL`;
  if (hit.kind === "service_role") {
    // The token is base64, so a grep for the word service_role will not see it.
    const script =
      'let s="";process.stdin.on("data",d=>s+=d);process.stdin.on("end",()=>{const re=/eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}/g;for (const m of s.matchAll(re)){const token=m[0];if(!token)continue;try{const body=token.split(".")[1];if(!body)continue;const payload=JSON.parse(Buffer.from(body,"base64url").toString());if(payload.role==="service_role")console.log(token)}catch{}}})';
    return `curl -sS ${shellQuote(hit.file)} | node -e ${shellQuote(script)}`;
  }
  return `curl -sS ${shellQuote(hit.file)} | grep -E ${shellQuote("sb_secret_|sk_live_|sk_test_|rk_live_|rk_test_")}`;
}

function pathOf(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}`;
  } catch {
    return url;
  }
}

export function extractScriptSrcs(html: string, origin: string): string[] {
  const urls: string[] = [];
  for (const match of html.matchAll(/<script\b([^>]*)>/gi)) {
    const attrs = match[1] ?? "";
    const quoted = attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
    const bare = attrs.match(/\bsrc\s*=\s*([^\s>]+)/i);
    const ref = quoted?.[1] ?? bare?.[1];
    if (!ref) continue;
    const absolute = sameOriginUrl(origin, ref);
    if (absolute) urls.push(absolute);
  }
  return [...new Set(urls)];
}
