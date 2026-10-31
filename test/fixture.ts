import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import type { Socket } from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";

const SAMPLE_DIR = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "sample-bundle");

// In-memory stand-in for Supabase Auth, PostgREST, and a small app.
// vulnerable: RLS off, signup open, secrets in app.js, unsigned webhook, open chat route.
// hardened: owner-only rows, signup disabled, clean bundle, signature required, chat requires a bearer token.
// The service role is accepted only on /auth/v1/admin. Data routes use the bearer role.

export type FixtureMode = "vulnerable" | "hardened";

export interface FixtureOptions {
  mode: FixtureMode;
  token?: string;
  tokenStyle?: "text" | "json";
  serveOwnership?: boolean;
  leakSecrets?: boolean;
  sourceMap?: boolean;
  port?: number;
  // "forbidden" mimics hosted Supabase since 2026-04-08: the OpenAPI root 403s for anon and publishable keys.
  openApi?: "allowed" | "forbidden";
  // "publishable" hands out an sb_publishable_ key, which the gateway accepts on apikey and PostgREST rejects as a bearer.
  keyStyle?: "legacy" | "publishable";
  // "sample" serves test/fixtures/sample-bundle instead of the tiny inline app.
  app?: "inline" | "sample";
  // Tables that exist in PostgREST. Defaults to all three; [] mimics a project with nothing public.
  tables?: ("profiles" | "notes" | "posts")[];
  // Serve the app (page, assets, /api routes) under this path, like a GitHub Pages project site.
  // Supabase routes (/auth/v1, /rest/v1) stay at the root. Must start and end with "/".
  basePath?: string;
  // How the sub-path page references its scripts: "relative" (./assets/x.js), "absolute"
  // (/sub/assets/x.js, Vite with base), or "base-href" (<base href="/sub/"> and assets/x.js).
  subpathRefs?: "relative" | "absolute" | "base-href";
  // Where the ownership file is served. Defaults to the base path when basePath is set, else the root.
  ownershipAt?: ("base" | "root")[];
  // Token served at the root location, when it should differ from token.
  rootToken?: string;
}

export interface FixtureRequest {
  method: string;
  pathname: string;
  role: string | null;
  apikeyRole: string | null;
  // True when Authorization carried something that is not a JWT (for example Bearer sb_publishable_...).
  malformedBearer: boolean;
  search: string;
  body: string;
}

export interface Fixture {
  url: string;
  // url + basePath, with a trailing slash. Equals url + "/" for a root app.
  appUrl: string;
  token: string;
  anonKey: string;
  serviceRole: string;
  leakedServiceRole: string;
  mode: FixtureMode;
  requests: FixtureRequest[];
  counts: () => { users: number; profiles: number; notes: number; posts: number };
  close: () => Promise<void>;
}

type Row = Record<string, unknown>;

interface Identity {
  role: string;
  sub: string | null;
  apikeyRole: string | null;
  malformedBearer: boolean;
}

const COLUMNS: Record<"profiles" | "notes" | "posts", string[]> = {
  profiles: ["id", "user_id", "display_name", "note", "role", "is_admin", "plan", "credits"],
  notes: ["id", "user_id", "body", "kind", "level"],
  posts: ["id", "title", "body"],
};

const SENSITIVE = ["role", "is_admin", "is_superadmin", "admin", "plan", "tier", "credits", "credit_balance", "balance"];

export async function startFixture(options: FixtureOptions): Promise<Fixture> {
  const mode = options.mode;
  const token = options.token ?? "nb-probe-test-token";
  const tokenStyle = options.tokenStyle ?? "text";
  const serveOwnership = options.serveOwnership ?? true;
  const leakSecrets = options.leakSecrets ?? mode === "vulnerable";
  const sourceMap = options.sourceMap ?? mode === "vulnerable";
  const secret = crypto.randomBytes(32).toString("hex");
  const openApiMode = options.openApi ?? "allowed";
  const keyStyle = options.keyStyle ?? "legacy";
  const appStyle = options.app ?? "inline";
  const liveTables: string[] = options.tables ?? ["profiles", "notes", "posts"];
  const basePath = options.basePath ?? "/";
  if (!basePath.startsWith("/") || !basePath.endsWith("/")) throw new Error("basePath must start and end with /");
  const subpathRefs = options.subpathRefs ?? "relative";
  const ownershipAt = options.ownershipAt ?? (basePath === "/" ? ["root"] : ["base"]);
  const rootToken = options.rootToken ?? token;
  const anonKey =
    keyStyle === "publishable"
      ? `sb_publishable_${crypto.randomBytes(16).toString("base64url").slice(0, 22)}_${crypto.randomBytes(4).toString("hex")}`
      : signJwt({ role: "anon", iss: "nb-probe-fixture" }, secret);
  const serviceRole =
    keyStyle === "publishable"
      ? `sb_secret_${crypto.randomBytes(16).toString("base64url").slice(0, 22)}_${crypto.randomBytes(4).toString("hex")}`
      : signJwt({ role: "service_role", iss: "nb-probe-fixture", use: "admin" }, secret);
  const leakedServiceRole = signJwt({ role: "service_role", iss: "nb-probe-fixture", use: "leaked" }, secret);

  const usersById = new Map<string, { id: string; email: string; password: string }>();
  const usersByEmail = new Map<string, { id: string; email: string; password: string }>();
  const rows: Record<"profiles" | "notes" | "posts", Row[]> = {
    profiles: [],
    notes: [],
    posts: [
      {
        id: "11111111-1111-4111-8111-111111111111",
        title: "Public note",
        body: "This page is meant to be readable.",
      },
    ],
  };
  const requests: FixtureRequest[] = [];

  function addUser(email: string, password: string): { id: string; email: string; password: string } {
    const existing = usersByEmail.get(email);
    if (existing) return existing;
    const user = { id: crypto.randomUUID(), email, password };
    usersById.set(user.id, user);
    usersByEmail.set(email, user);
    return user;
  }

  function sessionFor(user: { id: string; email: string }): Record<string, unknown> {
    return {
      access_token: signJwt({ sub: user.id, email: user.email, role: "authenticated" }, secret),
      token_type: "bearer",
      expires_in: 3600,
      refresh_token: crypto.randomBytes(12).toString("hex"),
      user: { id: user.id, email: user.email },
    };
  }

  function identify(req: http.IncomingMessage): Identity {
    const apikey = header(req, "apikey");
    let apikeyRole: string | null = null;
    if (apikey) {
      if (keyStyle === "publishable" && apikey === anonKey) apikeyRole = "anon";
      else if (keyStyle === "publishable" && apikey === serviceRole) apikeyRole = "service_role";
      else {
        const payload = verifyJwt(apikey, secret);
        apikeyRole = typeof payload?.role === "string" ? payload.role : "invalid";
      }
    }
    const authorization = header(req, "authorization");
    const bearer = authorization?.toLowerCase().startsWith("bearer ") ? authorization.slice(7).trim() : "";
    if (bearer && bearer.split(".").length !== 3) {
      // PostgREST tries to decode whatever is in Authorization as a JWT.
      return { role: "malformed", sub: null, apikeyRole, malformedBearer: true };
    }
    if (!bearer && apikeyRole && apikeyRole !== "invalid") {
      // Hosted gateway: an opaque or legacy key on apikey alone maps to its role.
      return { role: apikeyRole, sub: null, apikeyRole, malformedBearer: false };
    }
    const tokenValue = bearer || apikey || "";
    if (!tokenValue) return { role: "none", sub: null, apikeyRole, malformedBearer: false };
    const payload = verifyJwt(tokenValue, secret);
    if (!payload || typeof payload.role !== "string") return { role: "invalid", sub: null, apikeyRole, malformedBearer: false };
    const sub = typeof payload.sub === "string" ? payload.sub : null;
    return { role: payload.role, sub, apikeyRole, malformedBearer: false };
  }

  function canRead(table: string, row: Row, role: string, sub: string | null): boolean {
    if (role === "service_role") return true;
    if (table === "posts") return role === "anon" || role === "authenticated";
    if (mode === "vulnerable") return role === "anon" || role === "authenticated";
    return role === "authenticated" && row.user_id === sub;
  }

  function canMutate(table: string, row: Row, role: string, sub: string | null): boolean {
    if (role === "service_role") return true;
    if (mode === "vulnerable") return role === "anon" || role === "authenticated";
    if (table === "posts") return role === "authenticated";
    return role === "authenticated" && row.user_id === sub;
  }

  const server = http.createServer((req, res) => {
    void handle(req, res).catch((err: unknown) => {
      if (!res.headersSent) send(res, 500, { message: err instanceof Error ? err.message : String(err) });
      else res.destroy();
    });
  });
  const sockets = new Set<Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("close", () => sockets.delete(socket));
  });
  server.on("clientError", (_err, socket) => socket.destroy());

  async function handle(req: http.IncomingMessage, res: http.ServerResponse): Promise<void> {
    const url = new URL(req.url ?? "/", "http://127.0.0.1");
    const pathname = url.pathname;
    const method = req.method ?? "GET";
    const bodyText = method === "GET" || method === "HEAD" ? "" : await readBody(req);
    const identity = identify(req);
    requests.push({
      method,
      pathname,
      role: identity.role === "none" ? null : identity.role,
      apikeyRole: identity.apikeyRole,
      malformedBearer: identity.malformedBearer,
      search: url.search,
      body: bodyText.slice(0, 2000),
    });

    if (method === "GET" && pathname === `${basePath}.well-known/neural-breach` && basePath !== "/") {
      if (!serveOwnership || !ownershipAt.includes("base")) return send(res, 404, { message: "not found" });
      return ownershipFile(res, token);
    }
    if (pathname === "/.well-known/neural-breach" && method === "GET") {
      if (!serveOwnership || !ownershipAt.includes("root")) return send(res, 404, { message: "not found" });
      return ownershipFile(res, basePath === "/" ? token : rootToken);
    }
    if (pathname.startsWith("/auth/v1/") || pathname === "/rest/v1" || pathname.startsWith("/rest/v1/")) {
      return supabaseRoute(req, res, pathname, method, url, bodyText, identity);
    }
    // App routes live under basePath. Anything else on the origin is a 404, like another project.
    let appPath: string;
    if (basePath === "/") appPath = pathname;
    else if (pathname.startsWith(basePath)) appPath = `/${pathname.slice(basePath.length)}`;
    else if (pathname === basePath.slice(0, -1) && method === "GET") {
      res.writeHead(301, { location: basePath });
      res.end();
      return;
    } else return send(res, 404, { message: "not found" });

    if (appStyle === "sample" && method === "GET" && (appPath === "/" || appPath === "/index.html" || appPath.startsWith("/assets/"))) {
      return sample(res, appPath);
    }
    if ((appPath === "/" || appPath === "/index.html") && method === "GET") {
      return send(res, 200, html(basePath, subpathRefs), "text/html; charset=utf-8");
    }
    if (appPath === "/assets/app.js" && method === "GET") {
      return send(res, 200, javascript(leakSecrets, sourceMap, anonKey, leakedServiceRole), "text/javascript; charset=utf-8");
    }
    if (appPath === "/api/webhooks/stripe" && method === "POST") return webhook(req, res);
    if (appPath === "/api/chat" && method === "POST") return chat(res, bodyText, identity.role);
    if (appPath === "/api/signup" && method === "POST") return appSignup(res, bodyText);
    return send(res, 404, { message: "not found" });
  }

  function ownershipFile(res: http.ServerResponse, value: string): void {
    if (tokenStyle === "json") return send(res, 200, { token: value });
    return send(res, 200, `${value}\n`);
  }

  async function supabaseRoute(
    _req: http.IncomingMessage,
    res: http.ServerResponse,
    pathname: string,
    method: string,
    url: URL,
    bodyText: string,
    identity: Identity,
  ): Promise<void> {
    if (pathname === "/auth/v1/signup" && method === "POST") return authSignup(res, bodyText, identity);
    if (pathname === "/auth/v1/token" && method === "POST") return authToken(res, bodyText, identity);
    if (pathname === "/auth/v1/admin/users" && method === "POST") return adminCreate(res, bodyText, identity);
    if (pathname.startsWith("/auth/v1/admin/users/") && method === "DELETE") return adminDelete(res, pathname, identity);
    if ((pathname === "/rest/v1" || pathname === "/rest/v1/") && method === "GET") return openApi(res, identity);
    if (pathname.startsWith("/rest/v1/") && method !== "OPTIONS") return rest(res, pathname, method, url, bodyText, identity);
    return send(res, 404, { message: "not found" });
  }

  function requireApiKey(identity: Pick<Identity, "apikeyRole">, res: http.ServerResponse): boolean {
    if (identity.apikeyRole === "anon" || identity.apikeyRole === "service_role") return true;
    send(res, 401, { message: "Invalid API key" });
    return false;
  }

  function sample(res: http.ServerResponse, pathname: string): void {
    const name = pathname === "/" ? "index.html" : pathname.slice(1);
    if (name.includes("..")) return send(res, 404, { message: "not found" });
    const file = path.join(SAMPLE_DIR, name);
    if (!fs.existsSync(file)) return send(res, 404, { message: "not found" });
    const type = name.endsWith(".html")
      ? "text/html; charset=utf-8"
      : name.endsWith(".map")
        ? "application/json"
        : "text/javascript; charset=utf-8";
    let text = fs.readFileSync(file, "utf8");
    if (name === "index.html" && basePath !== "/") text = rebaseHtml(text, basePath, subpathRefs);
    send(res, 200, text, type);
  }

  function webhook(req: http.IncomingMessage, res: http.ServerResponse): void {
    if (mode === "hardened") {
      const signature = header(req, "stripe-signature");
      if (!signature) return send(res, 400, { error: "missing signature" });
      return send(res, 400, { error: "invalid signature" });
    }
    send(res, 200, { received: true });
  }

  function chat(res: http.ServerResponse, bodyText: string, role: string): void {
    const body = parseJson(bodyText) ?? {};
    if (mode === "hardened") {
      if (role !== "authenticated") return send(res, 401, { error: "unauthorized" });
      return send(res, 200, { model: "server-default", max_tokens: 256, reply: "ok" });
    }
    send(res, 200, { model: body.model ?? null, max_tokens: body.max_tokens ?? null, reply: "ok" });
  }

  function appSignup(res: http.ServerResponse, bodyText: string): void {
    const body = parseJson(bodyText) ?? {};
    if (mode === "hardened" && body.invite !== "valid-invite") {
      return send(res, 403, { error: "invite_required" });
    }
    const email = typeof body.email === "string" ? body.email : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!email.includes("@") || password.length < 8) return send(res, 400, { error: "invalid" });
    if (usersByEmail.has(email)) return send(res, 400, { error: "user_already_exists" });
    send(res, 200, sessionFor(addUser(email, password)));
  }

  function authSignup(
    res: http.ServerResponse,
    bodyText: string,
    identity: { apikeyRole: string | null },
  ): void {
    if (!requireApiKey(identity, res)) return;
    if (mode === "hardened") {
      return send(res, 422, {
        code: 422,
        error_code: "signup_disabled",
        msg: "Signups not allowed for this instance",
      });
    }
    const body = parseJson(bodyText) ?? {};
    const email = typeof body.email === "string" ? body.email : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!email.includes("@") || password.length < 8) return send(res, 400, { msg: "invalid" });
    if (usersByEmail.has(email)) return send(res, 400, { error_code: "user_already_exists", msg: "User already registered" });
    send(res, 200, sessionFor(addUser(email, password)));
  }

  function authToken(
    res: http.ServerResponse,
    bodyText: string,
    identity: { apikeyRole: string | null },
  ): void {
    if (!requireApiKey(identity, res)) return;
    const body = parseJson(bodyText) ?? {};
    const email = typeof body.email === "string" ? body.email : "";
    const password = typeof body.password === "string" ? body.password : "";
    const user = usersByEmail.get(email);
    if (!user || user.password !== password) return send(res, 400, { error_code: "invalid_credentials", msg: "Invalid login credentials" });
    send(res, 200, sessionFor(user));
  }

  function adminCreate(res: http.ServerResponse, bodyText: string, identity: { role: string }): void {
    if (identity.role !== "service_role") return send(res, 401, { message: "not allowed" });
    const body = parseJson(bodyText) ?? {};
    const email = typeof body.email === "string" ? body.email : "";
    const password = typeof body.password === "string" ? body.password : "";
    if (!email.includes("@") || password.length < 8) return send(res, 400, { message: "invalid" });
    if (usersByEmail.has(email)) return send(res, 422, { message: "already registered" });
    const user = addUser(email, password);
    send(res, 200, { id: user.id, email: user.email, email_confirmed_at: new Date().toISOString() });
  }

  function adminDelete(res: http.ServerResponse, pathname: string, identity: { role: string }): void {
    if (identity.role !== "service_role") return send(res, 401, { message: "not allowed" });
    const id = decodeURIComponent(pathname.slice("/auth/v1/admin/users/".length));
    const user = usersById.get(id);
    if (!user) return send(res, 404, { message: "not found" });
    usersById.delete(id);
    usersByEmail.delete(user.email);
    send(res, 200, { id });
  }

  function openApi(res: http.ServerResponse, identity: Identity): void {
    if (!requireApiKey(identity, res)) return;
    if (openApiMode === "forbidden" && identity.role !== "service_role") {
      // Body copied from the Supabase changelog for the 2026-04-08 change.
      return send(res, 403, {
        message: "Access to schema is forbidden",
        hint: "Accessing the schema via the Data API is only allowed using a secret API key.",
      });
    }
    send(res, 200, openApiDocument());
  }

  function rest(
    res: http.ServerResponse,
    pathname: string,
    method: string,
    url: URL,
    bodyText: string,
    identity: Identity,
  ): void {
    if (!requireApiKey(identity, res)) return;
    if (identity.role === "malformed") {
      return send(res, 401, { code: "PGRST301", details: null, hint: null, message: "Expected 3 parts in JWT; got 1" });
    }
    if (identity.role === "invalid" || identity.role === "none") return send(res, 401, { message: "Invalid JWT" });
    const rawName = pathname.slice("/rest/v1/".length);
    if (rawName.startsWith("rpc/")) {
      return send(res, 404, { code: "PGRST202", message: `Could not find the function public.${rawName.slice(4)} in the schema cache` });
    }
    if (!liveTables.includes(rawName)) {
      const name = rawName;
      const near = closest(name, liveTables);
      return send(res, 404, {
        code: "PGRST205",
        details: null,
        hint: near ? `Perhaps you meant the table 'public.${near}'` : null,
        message: `Could not find the table 'public.${name}' in the schema cache`,
      });
    }
    const name = rawName as "profiles" | "notes" | "posts";
    const table = name;
    const known = COLUMNS[table];
    const parsed = parseFilters(url.searchParams);
    if (!parsed) return send(res, 400, { message: "unsupported filter" });
    const selectParam = url.searchParams.get("select");
    const projection = selectParam && selectParam !== "*" ? selectParam.split(",").map((item) => item.trim()) : null;
    for (const column of [...(projection ?? []), ...parsed.filters.map(([column]) => column)]) {
      if (!known.includes(column)) {
        const near = closest(column, known);
        return send(res, 400, {
          code: "42703",
          details: null,
          hint: near ? `Perhaps you meant to reference the column "${table}.${near}".` : null,
          message: `column ${table}.${column} does not exist`,
        });
      }
    }
    const project = (row: Row): Row => {
      if (!projection) return row;
      const out: Row = {};
      for (const column of projection) out[column] = row[column];
      return out;
    };
    if ((method === "POST" || method === "PATCH") && bodyText) {
      const keys = Object.keys(parseJson(bodyText) ?? {});
      const unknown = keys.find((key) => !known.includes(key));
      if (unknown) {
        return send(res, 400, {
          code: "PGRST204",
          details: null,
          hint: null,
          message: `Could not find the '${unknown}' column of '${table}' in the schema cache`,
        });
      }
    }
    if ((method === "PATCH" || method === "DELETE") && parsed.filters.length === 0) {
      return send(res, 400, { message: "refusing unfiltered write" });
    }

    if (method === "GET") {
      let matched = rows[table].filter((row) => canRead(table, row, identity.role, identity.sub) && matches(row, parsed.filters));
      if (parsed.limit !== undefined) matched = matched.slice(0, parsed.limit);
      return send(res, 200, matched.map(project));
    }

    if (method === "POST") {
      if (identity.role !== "service_role" && mode === "hardened" && identity.role !== "authenticated") {
        return send(res, 401, { message: "permission denied" });
      }
      if (identity.role !== "service_role" && mode === "vulnerable" && identity.role !== "anon" && identity.role !== "authenticated") {
        return send(res, 401, { message: "permission denied" });
      }
      const body = parseJson(bodyText);
      if (!body) return send(res, 400, { message: "invalid json" });
      if (table === "notes") {
        for (const column of ["body", "kind", "level"]) {
          if (body[column] === undefined || body[column] === null) {
            return send(res, 400, {
              code: "23502",
              details: null,
              hint: null,
              message: `null value in column "${column}" of relation "notes" violates not-null constraint`,
            });
          }
        }
        if (typeof body.level !== "number") {
          return send(res, 400, {
            code: "22P02",
            details: null,
            hint: null,
            message: `invalid input syntax for type integer: "${String(body.level)}"`,
          });
        }
      }
      const row: Row = { ...body };
      if (typeof row.id !== "string") row.id = crypto.randomUUID();
      if (table === "profiles") {
        if (typeof row.display_name !== "string") row.display_name = "";
        if (typeof row.note !== "string") row.note = "";
        if (typeof row.role !== "string") row.role = "user";
        if (typeof row.is_admin !== "boolean") row.is_admin = false;
        if (typeof row.plan !== "string") row.plan = "free";
        if (typeof row.credits !== "number") row.credits = 0;
      }
      if (table !== "posts") {
        if (mode === "hardened") {
          if (!identity.sub) return send(res, 401, { message: "permission denied" });
          row.user_id = identity.sub;
          for (const key of SENSITIVE) delete row[key];
          if (table === "profiles") {
            row.role = "user";
            row.is_admin = false;
            row.plan = "free";
            row.credits = 0;
          }
        } else if (typeof row.user_id !== "string") {
          row.user_id = identity.sub;
        }
      }
      rows[table].push(row);
      return send(res, 201, [row]);
    }

    if (method === "PATCH") {
      const patch = parseJson(bodyText);
      if (!patch) return send(res, 400, { message: "invalid json" });
      const changed: Row[] = [];
      for (const row of rows[table]) {
        if (!matches(row, parsed.filters)) continue;
        if (!canMutate(table, row, identity.role, identity.sub)) continue;
        const clean = { ...patch };
        delete clean.id;
        if (mode === "hardened" && identity.role !== "service_role") {
          for (const key of SENSITIVE) delete clean[key];
          delete clean.user_id;
        }
        Object.assign(row, clean);
        changed.push({ ...row });
      }
      return send(res, 200, changed);
    }

    if (method === "DELETE") {
      const kept: Row[] = [];
      const deleted: Row[] = [];
      for (const row of rows[table]) {
        if (matches(row, parsed.filters) && canMutate(table, row, identity.role, identity.sub)) deleted.push({ ...row });
        else kept.push(row);
      }
      rows[table] = kept;
      return send(res, 200, deleted);
    }

    send(res, 405, { message: "method not allowed" });
  }

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(options.port ?? 0, "127.0.0.1", () => {
      server.off("error", reject);
      resolve();
    });
  });
  const address = server.address() as AddressInfo | null;
  if (!address || typeof address === "string") throw new Error("fixture failed to bind");

  return {
    url: `http://127.0.0.1:${address.port}`,
    appUrl: `http://127.0.0.1:${address.port}${basePath}`,
    token,
    anonKey,
    serviceRole,
    leakedServiceRole,
    mode,
    requests,
    counts: () => ({
      users: usersById.size,
      profiles: rows.profiles.length,
      notes: rows.notes.length,
      posts: rows.posts.length,
    }),
    close: () =>
      new Promise((resolve, reject) => {
        for (const socket of sockets) socket.destroy();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}

function html(basePath = "/", refs: "relative" | "absolute" | "base-href" = "relative"): string {
  const page = `<!doctype html>
<html>
  <head><title>Fixture</title></head>
  <body>
    <div id="root"></div>
    <script src="/assets/app.js"></script>
  </body>
</html>
`;
  return basePath === "/" ? page : rebaseHtml(page, basePath, refs);
}

// Rewrites root-absolute "/assets/..." references for an app served under basePath.
function rebaseHtml(page: string, basePath: string, refs: "relative" | "absolute" | "base-href"): string {
  if (refs === "absolute") return page.replaceAll(`"/assets/`, `"${basePath}assets/`);
  if (refs === "relative") return page.replaceAll(`"/assets/`, `"./assets/`);
  return page.replace(/<head>/i, `<head><base href="${basePath}">`).replaceAll(`"/assets/`, `"assets/`);
}

function javascript(leakSecrets: boolean, sourceMap: boolean, anonKey: string, leakedServiceRole: string): string {
  const lines = [
    `const supabaseUrl = "http://127.0.0.1";`,
    `const anonKey = ${JSON.stringify(anonKey)};`,
    `createClient(supabaseUrl, anonKey);`,
  ];
  if (leakSecrets) {
    lines.push(`const serviceRole = ${JSON.stringify(leakedServiceRole)};`);
    lines.push(`const stripeSecret = "sk_test_nbprobeFakeKey1234";`);
    lines.push(`const secretKey = "sb_secret_nbprobeFakeKey1234";`);
  }
  if (sourceMap) lines.push("//# sourceMappingURL=app.js.map");
  return `${lines.join("\n")}\n`;
}

function openApiDocument(): Record<string, unknown> {
  const pk = "Note:\nThis is a Primary Key.<pk/>";
  return {
    swagger: "2.0",
    info: { title: "nb-probe fixture", version: "0" },
    definitions: {
      profiles: {
        type: "object",
        required: ["id"],
        properties: {
          id: { type: "string", format: "uuid", default: "gen_random_uuid()", description: pk },
          user_id: { type: "string", format: "uuid" },
          display_name: { type: "string" },
          note: { type: "string" },
          role: { type: "string", default: "user" },
          is_admin: { type: "boolean", default: false },
          plan: { type: "string", default: "free" },
          credits: { type: "integer", default: 0 },
        },
      },
      notes: {
        type: "object",
        required: ["id", "body", "kind", "level"],
        properties: {
          id: { type: "string", format: "uuid", default: "gen_random_uuid()", description: pk },
          user_id: { type: "string", format: "uuid" },
          body: { type: "string" },
          kind: { type: "string" },
          level: { type: "integer" },
        },
      },
      posts: {
        type: "object",
        required: ["id"],
        properties: {
          id: { type: "string", format: "uuid", default: "gen_random_uuid()", description: pk },
          title: { type: "string" },
          body: { type: "string" },
        },
      },
    },
    paths: {
      "/profiles": { get: {}, post: {}, patch: {}, delete: {} },
      "/notes": { get: {}, post: {}, patch: {}, delete: {} },
      "/posts": { get: {}, post: {} },
    },
  };
}

function closest(name: string, options: string[]): string | null {
  let best: string | null = null;
  let bestScore = Infinity;
  for (const option of options) {
    const score = distance(name, option);
    if (score < bestScore) {
      best = option;
      bestScore = score;
    }
  }
  return bestScore <= 3 ? best : null;
}

function distance(a: string, b: string): number {
  const row = Array.from({ length: b.length + 1 }, (_, index) => index);
  for (let i = 1; i <= a.length; i++) {
    let previous = row[0] ?? 0;
    row[0] = i;
    for (let j = 1; j <= b.length; j++) {
      const current = row[j] ?? 0;
      row[j] = Math.min((row[j] ?? 0) + 1, (row[j - 1] ?? 0) + 1, previous + (a[i - 1] === b[j - 1] ? 0 : 1));
      previous = current;
    }
  }
  return row[b.length] ?? Infinity;
}

function parseFilters(search: URLSearchParams): { filters: [string, string][]; limit?: number } | null {
  const filters: [string, string][] = [];
  let limit: number | undefined;
  for (const [key, value] of search.entries()) {
    if (key === "select" || key === "order") continue;
    if (key === "limit") {
      limit = Number(value);
      continue;
    }
    if (!value.startsWith("eq.")) return null;
    filters.push([key, value.slice(3)]);
  }
  return limit === undefined ? { filters } : { filters, limit };
}

function matches(row: Row, filters: [string, string][]): boolean {
  return filters.every(([column, value]) => String(row[column]) === value);
}

function parseJson(text: string): Record<string, unknown> | null {
  if (!text) return {};
  try {
    const value: unknown = JSON.parse(text);
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}

function header(req: http.IncomingMessage, name: string): string | undefined {
  const value = req.headers[name];
  if (Array.isArray(value)) return value[0];
  return value;
}

function send(res: http.ServerResponse, status: number, body: unknown, contentType?: string): void {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  const type = contentType ?? (typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8");
  res.writeHead(status, {
    "content-type": type,
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store",
  });
  res.end(text);
}

function readBody(req: http.IncomingMessage, limit = 1_000_000): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limit) {
        reject(new Error("body too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function signJwt(payload: Record<string, unknown>, key: string): string {
  const headerPart = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const bodyPart = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const signature = crypto.createHmac("sha256", key).update(`${headerPart}.${bodyPart}`).digest("base64url");
  return `${headerPart}.${bodyPart}.${signature}`;
}

function verifyJwt(token: string, key: string): Record<string, unknown> | null {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  const [headerPart, bodyPart, signature] = parts;
  if (!headerPart || !bodyPart || !signature) return null;
  const expected = crypto.createHmac("sha256", key).update(`${headerPart}.${bodyPart}`).digest("base64url");
  const actualBuf = Buffer.from(signature);
  const expectedBuf = Buffer.from(expected);
  if (actualBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(actualBuf, expectedBuf)) return null;
  try {
    const value: unknown = JSON.parse(Buffer.from(bodyPart, "base64url").toString("utf8"));
    if (!value || typeof value !== "object" || Array.isArray(value)) return null;
    return value as Record<string, unknown>;
  } catch {
    return null;
  }
}
