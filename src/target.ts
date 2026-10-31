import { UsageError } from "./util.js";

// Where the app lives. origin: scheme://host[:port]. base: the app's directory URL, always ending
// in "/" (https://host/ or https://host/sub/). basePath: base without the origin ("/" or "/sub/").
// entry: the page to download first (base, or the named page such as base + "index.html").
export interface AppTarget {
  origin: string;
  base: string;
  basePath: string;
  entry: string;
}

export function parseTarget(input: string, flag = "--url"): AppTarget {
  let url: URL;
  try {
    url = new URL(input.trim());
  } catch {
    throw new UsageError(`${flag} is not a URL: ${input}`);
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new UsageError(`${flag} must be http or https`);
  }
  if (url.username || url.password) throw new UsageError(`${flag} must not include credentials`);
  if (url.search) throw new UsageError(`${flag} must not include a query string`);
  // A fragment never reaches the server (hash routers use #/login). Drop it.
  url.hash = "";
  const rawPath = url.pathname || "/";
  if (/%(?:2e|2f|5c|00)/i.test(rawPath) || rawPath.includes("\\") || rawPath.includes("//")) {
    throw new UsageError(`${flag} has an encoded or empty path segment. Pass the plain app path.`);
  }
  if (rawPath.length > 300) throw new UsageError(`${flag} path is too long`);

  let basePath: string;
  let entryPath: string;
  if (rawPath.endsWith("/")) {
    basePath = rawPath;
    entryPath = rawPath;
  } else {
    const last = rawPath.slice(rawPath.lastIndexOf("/") + 1);
    if (/\.(?:html?|php|aspx?)$/i.test(last)) {
      // https://host/sub/index.html: the app directory is /sub/, the entry page is the file.
      basePath = rawPath.slice(0, rawPath.lastIndexOf("/") + 1);
      entryPath = rawPath;
    } else {
      // https://host/sub: treat it as the directory /sub/.
      basePath = `${rawPath}/`;
      entryPath = basePath;
    }
  }
  return {
    origin: url.origin,
    base: `${url.origin}${basePath}`,
    basePath,
    entry: `${url.origin}${entryPath}`,
  };
}

// The target as shown in reports: the bare origin for a root app, the base URL for a sub-path app.
export function displayTarget(target: AppTarget): string {
  return target.basePath === "/" ? target.origin : target.base;
}

// An app route such as /api/chat, placed under the app's path: /sub/api/chat for a sub-path app.
export function appUrl(target: AppTarget, path: string): string {
  return `${target.origin}${target.basePath.replace(/\/$/, "")}${path}`;
}

// True when url is on the target origin and inside the app path prefix.
export function withinBase(target: AppTarget, url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.origin !== target.origin) return false;
  if (target.basePath === "/") return true;
  const dir = target.basePath;
  return parsed.pathname.startsWith(dir) || parsed.pathname === dir.replace(/\/$/, "");
}
