import type { HttpClient } from "./http.js";
import { type AppTarget, parseTarget, withinBase } from "./target.js";
import { errorMessage } from "./util.js";

export interface BundleFile {
  url: string;
  kind: "page" | "script" | "source-map";
  text: string;
}

export interface Bundle {
  pageStatus: number | null;
  pageError?: string;
  // Scripts named in the entry page, in page order.
  entryScripts: string[];
  files: BundleFile[];
  errors: string[];
}

const MAX_SCRIPTS = 40;
const MAX_SOURCE_MAPS = 12;
const SCRIPT_BYTES = 1_500_000;
const MAP_BYTES = 8_000_000;
// Lazily loaded chunks are named in the code as string literals: Vite "./Dashboard-x1.js" or
// "assets/Dashboard-x1.js", Next "static/chunks/app/page-x1.js".
const CHUNK_RE = /["'`]((?:\.{0,2}\/)?[A-Za-z0-9_@~.\-/]*[A-Za-z0-9_\-]\.m?js)["'`]/g;
const MAP_RE = /\/\/[#@]\s*sourceMappingURL\s*=\s*(\S+)\s*$/gm;

// Downloads the entry page, its same-origin scripts, the chunks those scripts name, and any
// same-origin source maps. GET only, never leaves the app origin. The only page fetched is the
// entry page inside the target path; scripts, chunks and maps it references may sit anywhere on the
// same origin (an app at /sub/ can load /assets/x.js), but no other page is crawled.
export async function fetchBundle(http: HttpClient, target: AppTarget | string): Promise<Bundle> {
  const app = typeof target === "string" ? parseTarget(target) : target;
  const origin = app.origin;
  const bundle: Bundle = { pageStatus: null, entryScripts: [], files: [], errors: [] };
  let page;
  try {
    page = await http.request(app.entry, { maxBytes: SCRIPT_BYTES, headers: { accept: "text/html" } });
  } catch (err) {
    bundle.pageError = errorMessage(err);
    return bundle;
  }
  if (!withinBase(app, page.url)) {
    bundle.pageError = `The entry page redirected to ${pathOf(page.url)}, outside ${app.basePath}. Pass the URL the app is served from.`;
    return bundle;
  }
  bundle.pageStatus = page.status;
  if (page.status !== 200) return bundle;
  bundle.files.push({ url: page.url, kind: "page", text: page.text });

  // Relative references in the page resolve against <base href> when it is set, otherwise the page URL.
  const docBase = documentBase(page.text, page.url, origin);
  bundle.entryScripts = extractScriptSrcs(page.text, docBase).slice(0, 15);
  const queue = [...bundle.entryScripts, ...extractPreloads(page.text, docBase)];
  const seen = new Set<string>();
  const maps: string[] = [];
  let scripts = 0;
  while (queue.length && scripts < MAX_SCRIPTS) {
    const next = queue.shift();
    if (!next || seen.has(next)) continue;
    seen.add(next);
    scripts++;
    let script;
    try {
      script = await http.request(next, { maxBytes: SCRIPT_BYTES });
    } catch (err) {
      bundle.errors.push(`${pathOf(next)} ${errorMessage(err)}`);
      continue;
    }
    if (script.status !== 200) {
      bundle.errors.push(`${pathOf(next)} HTTP ${script.status}`);
      continue;
    }
    if (looksLikeHtml(script.text)) continue; // SPA fallback served index.html for a missing chunk.
    bundle.files.push({ url: script.url, kind: "script", text: script.text });
    for (const ref of chunkRefs(script.text, script.url, app)) {
      if (!seen.has(ref)) queue.push(ref);
    }
    for (const ref of sourceMapRefs(script.text, script.url, origin)) {
      if (ref.inline !== undefined) bundle.files.push(...mapSources(ref.inline, `${script.url}#inline-map`));
      else if (ref.url && !maps.includes(ref.url)) maps.push(ref.url);
    }
  }

  for (const mapUrl of maps.slice(0, MAX_SOURCE_MAPS)) {
    try {
      const response = await http.request(mapUrl, { maxBytes: MAP_BYTES });
      if (response.status !== 200 || response.truncated) {
        if (response.status !== 200) bundle.errors.push(`${pathOf(mapUrl)} HTTP ${response.status}`);
        else bundle.errors.push(`${pathOf(mapUrl)} larger than ${MAP_BYTES} bytes, skipped`);
        continue;
      }
      bundle.files.push(...mapSources(response.text, mapUrl));
    } catch (err) {
      bundle.errors.push(`${pathOf(mapUrl)} ${errorMessage(err)}`);
    }
  }
  return bundle;
}

// One pseudo file per original source in the map. Vendor code is skipped.
export function mapSources(text: string, mapUrl: string): BundleFile[] {
  let json: unknown;
  try {
    json = JSON.parse(text);
  } catch {
    return [];
  }
  if (!json || typeof json !== "object") return [];
  const record = json as { sources?: unknown; sourcesContent?: unknown };
  const sources = Array.isArray(record.sources) ? record.sources : [];
  const contents = Array.isArray(record.sourcesContent) ? record.sourcesContent : [];
  const files: BundleFile[] = [];
  contents.forEach((content, index) => {
    if (typeof content !== "string" || !content) return;
    const source = typeof sources[index] === "string" ? (sources[index] as string) : String(index);
    if (source.includes("node_modules/")) return;
    files.push({ url: `${mapUrl}#${source}`, kind: "source-map", text: content });
  });
  return files;
}

// The URL relative references in the page resolve against: <base href> if it is same-origin, else the page.
export function documentBase(html: string, pageUrl: string, origin: string): string {
  const tag = html.match(/<base\b([^>]*)>/i)?.[1];
  const href = tag?.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1] ?? tag?.match(/\bhref\s*=\s*([^\s>]+)/i)?.[1];
  if (!href) return pageUrl;
  const resolved = resolveSameOrigin(href, pageUrl, origin);
  return resolved ?? pageUrl;
}

// Resolves ref against baseUrl. Returns null unless the result is http(s) on the same origin.
export function resolveSameOrigin(ref: string, baseUrl: string, origin?: string): string | null {
  const trimmed = ref.trim();
  if (!trimmed || /^(?:javascript|data|blob|about):/i.test(trimmed) || trimmed.includes("\\")) return null;
  let resolved: URL;
  let expected: string;
  try {
    expected = origin ?? new URL(baseUrl).origin;
    resolved = new URL(trimmed, baseUrl);
  } catch {
    return null;
  }
  if (resolved.origin !== expected) return null;
  if (resolved.protocol !== "http:" && resolved.protocol !== "https:") return null;
  resolved.hash = "";
  return resolved.toString();
}

// docBase is the URL the page's relative references resolve against: the page URL, or <base href>.
export function extractScriptSrcs(html: string, docBase: string): string[] {
  const urls: string[] = [];
  for (const match of html.matchAll(/<script\b([^>]*)>/gi)) {
    const attrs = match[1] ?? "";
    const quoted = attrs.match(/\bsrc\s*=\s*["']([^"']+)["']/i);
    const bare = attrs.match(/\bsrc\s*=\s*([^\s>]+)/i);
    const ref = quoted?.[1] ?? bare?.[1];
    if (!ref) continue;
    const absolute = resolveSameOrigin(ref, docBase);
    if (absolute) urls.push(absolute);
  }
  return [...new Set(urls)];
}

function extractPreloads(html: string, docBase: string): string[] {
  const urls: string[] = [];
  for (const match of html.matchAll(/<link\b([^>]*)>/gi)) {
    const attrs = match[1] ?? "";
    if (!/\brel\s*=\s*["']?(?:modulepreload|preload)\b/i.test(attrs)) continue;
    const href = attrs.match(/\bhref\s*=\s*["']([^"']+)["']/i)?.[1];
    if (!href || !/\.m?js(?:$|\?)/.test(href)) continue;
    const absolute = resolveSameOrigin(href, docBase);
    if (absolute) urls.push(absolute);
  }
  return urls;
}

// target: the app (or its origin as a string). Bare "assets/x.js" and Next "static/chunks/x.js"
// references are relative to the app's base path, which is the origin root for a root app.
export function chunkRefs(text: string, scriptUrl: string, target: AppTarget | string): string[] {
  const app = typeof target === "string" ? parseTarget(target) : target;
  const out = new Set<string>();
  for (const match of text.matchAll(CHUNK_RE)) {
    const ref = match[1];
    if (!ref || ref.includes("//") || ref.length > 200) continue;
    // Bundlers name chunks with a path ("./Dashboard-x1.js", "assets/x.js", "static/chunks/x.js").
    // A bare "Node.js" or "Next.js" is prose in a library string, not a file.
    if (!ref.includes("/")) continue;
    const resolved = resolveRef(ref, scriptUrl, app);
    if (resolved) out.add(resolved);
    if (out.size >= 200) break;
  }
  return [...out];
}

function resolveRef(ref: string, scriptUrl: string, app: AppTarget): string | null {
  const origin = app.origin;
  let target: URL;
  try {
    if (ref.startsWith("./") || ref.startsWith("../")) target = new URL(ref, scriptUrl);
    else if (ref.startsWith("/")) target = new URL(ref, origin);
    // Next with basePath serves chunks from <basePath>/_next/static/...
    else if (ref.startsWith("static/")) target = new URL(`_next/${ref}`, app.base);
    // Vite with base "/sub/" names deps "assets/x.js" and prefixes the base at runtime.
    else if (ref.includes("/")) target = new URL(ref, app.base);
    else target = new URL(ref, scriptUrl);
  } catch {
    return null;
  }
  if (target.origin !== origin) return null;
  if (target.protocol !== "http:" && target.protocol !== "https:") return null;
  target.hash = "";
  return target.toString();
}

function sourceMapRefs(text: string, scriptUrl: string, origin: string): { url?: string; inline?: string }[] {
  const refs: { url?: string; inline?: string }[] = [];
  for (const match of text.matchAll(MAP_RE)) {
    const ref = match[1];
    if (!ref) continue;
    const inline = ref.match(/^data:application\/json(?:;charset=[^;,]+)?;base64,([A-Za-z0-9+/=]+)$/);
    if (inline?.[1]) {
      refs.push({ inline: Buffer.from(inline[1], "base64").toString("utf8") });
      continue;
    }
    if (ref.startsWith("data:")) continue;
    let target: URL;
    try {
      target = new URL(ref, scriptUrl);
    } catch {
      continue;
    }
    if (target.origin === origin) refs.push({ url: target.toString() });
  }
  return refs;
}

function looksLikeHtml(text: string): boolean {
  return /^\s*<(?:!doctype|html)/i.test(text);
}

export function pathOf(url: string): string {
  try {
    const parsed = new URL(url);
    return `${parsed.pathname}${parsed.search}${parsed.hash}`;
  } catch {
    return url;
  }
}

// One download per scan, shared by bundle-secrets and table discovery.
export function loadBundle(ctx: {
  http: HttpClient;
  origin: string;
  config?: { target: AppTarget };
  bundle?: Promise<Bundle>;
}): Promise<Bundle> {
  ctx.bundle ??= fetchBundle(ctx.http, ctx.config?.target ?? ctx.origin);
  return ctx.bundle;
}
