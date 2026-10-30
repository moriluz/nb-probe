import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import type { BundleFile } from "../src/bundle.js";
import { resolveConfig } from "../src/config.js";
import {
  columnSuggestion,
  extractUsage,
  missingColumn,
  parsePostgrestError,
  parseSelect,
  tableSuggestion,
} from "../src/discovery.js";
import { HttpClient } from "../src/http.js";
import { exitCode, formatHuman } from "../src/report.js";
import { scan } from "../src/scan.js";
import { SupabaseClient } from "../src/supabase.js";
import type { CheckResult, ScanConfig, ScanReport } from "../src/types.js";
import { isJwt } from "../src/util.js";
import { startFixture, type Fixture, type FixtureOptions } from "./fixture.js";

const SAMPLE = path.join(path.dirname(fileURLToPath(import.meta.url)), "fixtures", "sample-bundle");
const DATA_CHECKS = ["logged-out-read", "idor-read", "idor-write", "self-promotion"];

function sampleFiles(): BundleFile[] {
  const read = (name: string) => fs.readFileSync(path.join(SAMPLE, name), "utf8");
  const map = JSON.parse(read("assets/index-Bx7.js.map")) as { sources: string[]; sourcesContent: string[] };
  return [
    { url: "http://app.test/", kind: "page", text: read("index.html") },
    { url: "http://app.test/assets/index-Bx7.js", kind: "script", text: read("assets/index-Bx7.js") },
    { url: "http://app.test/assets/vendor-c41.js", kind: "script", text: read("assets/vendor-c41.js") },
    { url: "http://app.test/assets/Dashboard-9f2.js", kind: "script", text: read("assets/Dashboard-9f2.js") },
    ...map.sources
      .map((source, index) => ({ source, text: map.sourcesContent[index] ?? "" }))
      .filter((item) => !item.source.includes("node_modules"))
      .map((item) => ({
        url: `http://app.test/assets/index-Bx7.js.map#${item.source}`,
        kind: "source-map" as const,
        text: item.text,
      })),
  ];
}

function config(fixture: Fixture, extra: Partial<ScanConfig> = {}): ScanConfig {
  return {
    url: fixture.url,
    token: fixture.token,
    supabaseUrl: fixture.url,
    anonKey: fixture.anonKey,
    serviceRole: fixture.serviceRole,
    closedSignup: true,
    signupPath: "/api/signup",
    webhookPath: "/api/webhooks/stripe",
    llmPath: "/api/chat",
    timeoutMs: 5000,
    ...extra,
  };
}

function results(report: ScanReport): Map<string, CheckResult> {
  return new Map(report.results.map((result) => [result.id, result]));
}

async function withFixture(options: Partial<FixtureOptions>, run: (fixture: Fixture) => Promise<void>): Promise<void> {
  const fixture = await startFixture({ mode: "vulnerable", token: crypto.randomUUID(), ...options });
  try {
    await run(fixture);
  } finally {
    await fixture.close();
  }
}

// Discovery may only read: GET with limit=0 on tables, never an RPC call.
function assertDiscoveryReadOnly(fixture: Fixture): void {
  const rest = fixture.requests.filter((request) => request.pathname.startsWith("/rest/v1/"));
  assert.equal(rest.some((request) => request.pathname.startsWith("/rest/v1/rpc/")), false, "an rpc was called");
  for (const request of rest) {
    if (request.method !== "GET") {
      assert.ok(["POST", "PATCH", "DELETE"].includes(request.method), `${request.method} ${request.pathname}`);
      assert.ok(["/rest/v1/profiles", "/rest/v1/notes"].includes(request.pathname), `write to ${request.pathname}`);
    }
  }
  assert.equal(fixture.requests.filter((request) => request.malformedBearer).length, 0, "non-JWT sent as bearer");
}

async function mintCredentials(fixture: Fixture, label: string): Promise<{ email: string; password: string }> {
  const email = `nb-probe-${label}-${crypto.randomBytes(4).toString("hex")}@example.com`;
  const password = `pw-${crypto.randomBytes(9).toString("hex")}`;
  const headers: Record<string, string> = { apikey: fixture.serviceRole, "content-type": "application/json" };
  if (isJwt(fixture.serviceRole)) headers.authorization = `Bearer ${fixture.serviceRole}`;
  const created = await fetch(`${fixture.url}/auth/v1/admin/users`, {
    method: "POST",
    headers,
    body: JSON.stringify({ email, password, email_confirm: true }),
  });
  assert.equal(created.status, 200);
  return { email, password };
}

test("bundle parser finds tables, columns, rpcs, buckets, and the project", () => {
  const usage = extractUsage(sampleFiles());
  const tables = [...usage.tables.keys()].sort();
  assert.deepEqual(tables, ["notes", "posts", "profile", "profiles"]);
  const notes = usage.tables.get("notes");
  for (const column of ["id", "body", "user_id", "kind", "created_at"]) {
    assert.ok(notes?.columns.has(column), `notes.${column}`);
  }
  assert.ok(usage.tables.get("profiles")?.columns.has("display_name"));
  assert.ok(usage.tables.get("profiles")?.columns.has("user_id"));
  assert.deepEqual([...(usage.tables.get("posts")?.sources ?? [])], ["source-map"]);
  assert.ok(usage.tables.get("notes")?.sources.has("bundle"));
  assert.deepEqual([...usage.rpcs], ["get_stats"]);
  assert.deepEqual([...usage.buckets], ["avatars"]);
  assert.deepEqual([...usage.projects], ["abcdefghijklmnopqrst.supabase.co"]);
  assert.equal(usage.tables.has("abc"), false);
  assert.equal(usage.tables.has("node_modules_table"), false);
});

test("select parser handles aliases, casts, spreads, and embedded tables", () => {
  const columns = new Set<string>();
  const usage = extractUsage([]);
  parseSelect("id, title::text, total:amount.sum(), author:profiles!inner(name, avatar_url), ...teams(slug), *", columns, usage);
  assert.deepEqual([...columns].sort(), ["amount", "id", "title"]);
  assert.ok(usage.tables.has("profiles"));
  assert.ok(usage.tables.has("teams"));
});

test("PostgREST hints are read from hint and details", () => {
  const hinted = parsePostgrestError(
    JSON.stringify({
      code: "PGRST205",
      details: null,
      hint: "Perhaps you meant the table 'public.profiles'",
      message: "Could not find the table 'public.profile' in the schema cache",
    }),
  );
  assert.ok(hinted);
  assert.equal(tableSuggestion(hinted), "profiles");
  const detailed = parsePostgrestError(
    JSON.stringify({
      code: "PGRST205",
      details: "Perhaps you meant the table 'public.todos'",
      hint: null,
      message: "Could not find the table 'public.todo' in the schema cache",
    }),
  );
  assert.ok(detailed);
  assert.equal(tableSuggestion(detailed), "todos");
  const other = parsePostgrestError(
    JSON.stringify({ code: "PGRST205", hint: "Perhaps you meant the table 'private.keys'", message: "x" }),
  );
  assert.ok(other);
  assert.equal(tableSuggestion(other), null);
  const column = parsePostgrestError(
    JSON.stringify({
      code: "42703",
      details: null,
      hint: 'Perhaps you meant to reference the column "notes.user_id".',
      message: "column notes.userid does not exist",
    }),
  );
  assert.ok(column);
  assert.equal(missingColumn(column), "userid");
  assert.equal(columnSuggestion(column), "user_id");
  assert.equal(parsePostgrestError("<html>"), null);
});

test("key formats: publishable and secret keys never go in Authorization", async () => {
  assert.equal(isJwt("sb_publishable_abcdefghijklmnopqrstuv_0123abcd"), false);
  assert.equal(isJwt("eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYW5vbiJ9.c2ln"), true);
  const seen: http.IncomingHttpHeaders[] = [];
  const server = http.createServer((req, res) => {
    seen.push(req.headers);
    res.writeHead(200, { "content-type": "application/json" });
    res.end("[]");
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
    const publishable = "sb_publishable_abcdefghijklmnopqrstuv_0123abcd";
    // Built at runtime: a fake key, but shaped enough like a real one to trip secret scanners.
    const secretKey = ["sb", "secret", crypto.randomBytes(11).toString("hex"), crypto.randomBytes(4).toString("hex")].join("_");
    const client = new SupabaseClient(new HttpClient(5000), url, publishable);
    await client.select("notes", "select=*&limit=0", publishable);
    await client.select("notes", "select=*&limit=0", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln");
    await client.admin("DELETE", "/auth/v1/admin/users/x", secretKey);
    assert.equal(seen[0]?.apikey, publishable);
    assert.equal(seen[0]?.authorization, undefined);
    assert.equal(seen[1]?.authorization, "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2ln");
    assert.equal(seen[2]?.apikey, secretKey);
    assert.equal(seen[2]?.authorization, undefined);
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
});

test("config takes test-account credentials and checks them", () => {
  const base = {
    url: "https://app.example.com",
    token: "0123456789abcdef",
    supabaseUrl: "https://abcdefghijklmnopqrst.supabase.co",
    anonKey: "sb_publishable_abcdefghijklmnopqrstuv_0123abcd",
  };
  const ok = resolveConfig({
    ...base,
    userAEmail: "a@example.com",
    userAPassword: "pw-a-1234",
    userBEmail: "b@example.com",
    userBPassword: "pw-b-1234",
    tables: ["public.notes", "profiles"],
  });
  assert.deepEqual(ok.userACredentials, { email: "a@example.com", password: "pw-a-1234" });
  assert.deepEqual(ok.tables, ["notes", "profiles"]);
  assert.throws(() => resolveConfig({ ...base, userAEmail: "a@example.com", userAPassword: "x" }), /both/i);
  assert.throws(
    () =>
      resolveConfig({
        ...base,
        userAEmail: "a@example.com",
        userAPassword: "x",
        userBEmail: "a@example.com",
        userBPassword: "y",
      }),
    /differ|same/i,
  );
  assert.throws(() => resolveConfig({ ...base, tables: ["notes; drop"] }));
});

test("403 on the OpenAPI root: discovery from the bundle finds the holes", async () => {
  await withFixture({ openApi: "forbidden", app: "sample", keyStyle: "publishable" }, async (fixture) => {
    const before = fixture.counts();
    const report = await scan(config(fixture));
    const byId = results(report);
    for (const id of DATA_CHECKS) assert.equal(byId.get(id)?.status, "fail", `${id}: ${byId.get(id)?.summary}`);
    assert.equal(exitCode(report), 1);
    const discovery = report.discovery;
    assert.ok(discovery);
    assert.equal(discovery.schema, "discovery");
    assert.equal(discovery.openApi.status, 403);
    const table = (name: string) => discovery.tables.find((item) => item.name === name);
    assert.equal(table("notes")?.status, "probed");
    assert.ok(table("notes")?.sources.includes("bundle"));
    assert.equal(table("profiles")?.status, "probed");
    assert.ok(table("profiles")?.sources.includes("postgrest-hint"));
    assert.equal(table("profiles")?.suggestedFor, "profile");
    assert.equal(table("profile")?.status, "not-found");
    assert.ok(table("posts")?.sources.includes("source-map"));
    assert.equal(table("posts")?.status, "found");
    assert.deepEqual(discovery.rpcs, ["get_stats"]);
    assert.ok(discovery.files.sourceMaps >= 1);
    const human = formatHuman(report);
    assert.match(human, /schema: refused \(HTTP 403\)/);
    assert.match(human, /rpc \(seen in bundle, not called\): get_stats/);
    assertDiscoveryReadOnly(fixture);
    assert.deepEqual(fixture.counts(), before);
  });
});

test("403 on the OpenAPI root: a hardened app passes and is left clean", async () => {
  await withFixture({ mode: "hardened", openApi: "forbidden", app: "sample" }, async (fixture) => {
    const before = fixture.counts();
    const report = await scan(config(fixture));
    const byId = results(report);
    for (const id of DATA_CHECKS) assert.equal(byId.get(id)?.status, "pass", `${id}: ${byId.get(id)?.summary}`);
    assertDiscoveryReadOnly(fixture);
    assert.deepEqual(fixture.counts(), before);
  });
});

test("403 on the OpenAPI root: --tables works without the spec", async () => {
  await withFixture({ openApi: "forbidden" }, async (fixture) => {
    const report = await scan(config(fixture, { tables: ["notes", "profiles"] }));
    const byId = results(report);
    for (const id of DATA_CHECKS) assert.equal(byId.get(id)?.status, "fail", `${id}: ${byId.get(id)?.summary}`);
    for (const name of ["notes", "profiles"]) {
      const entry = report.discovery?.tables.find((item) => item.name === name);
      assert.equal(entry?.status, "probed");
      assert.ok(entry?.sources.includes("--tables"));
    }
    assert.equal(report.results.some((result) => /Schema request/.test(result.summary)), false);
    // notes needs kind (NOT NULL) and an integer level, neither known without the spec.
    assert.equal(report.notes.some((note) => /not inserted/.test(note)), false, report.notes.join("\n"));
    const inserted = fixture.requests.filter((request) => request.method === "POST" && request.pathname === "/rest/v1/notes");
    assert.ok(inserted.length > 2, "insert retried after 23502/22P02");
    assertDiscoveryReadOnly(fixture);
    assert.equal(fixture.counts().notes, 0);
    assert.equal(fixture.counts().profiles, 0);
  });
});

test("nothing discovered is a skip that asks for --tables, and creates no users", async () => {
  await withFixture({ mode: "hardened", openApi: "forbidden", tables: [] }, async (fixture) => {
    const report = await scan(config(fixture));
    const byId = results(report);
    for (const id of DATA_CHECKS) {
      assert.equal(byId.get(id)?.status, "skip");
      assert.equal(byId.get(id)?.summary, "skipped: no tables discovered, pass --tables");
    }
    assert.equal(report.summary.error, 0);
    assert.equal(fixture.requests.some((request) => request.pathname.startsWith("/auth/v1/admin")), false);
    assert.equal(fixture.counts().users, 0);
  });
});

test("missing --tables are named with the PostgREST suggestion", async () => {
  await withFixture({ mode: "hardened", openApi: "forbidden", tables: ["profiles"] }, async (fixture) => {
    const report = await scan(config(fixture, { tables: ["profile"], only: ["idor-read"] }));
    const result = report.results[0];
    assert.notEqual(result?.status, "error", result?.summary);
    const entry = report.discovery?.tables.find((item) => item.name === "profiles");
    assert.equal(entry?.suggestedFor, "profile");
  });
});

test("publishable keys with the spec allowed: no PGRST301 and users are cleaned up", async () => {
  await withFixture({ keyStyle: "publishable" }, async (fixture) => {
    const before = fixture.counts();
    const report = await scan(config(fixture));
    const byId = results(report);
    for (const id of DATA_CHECKS) assert.equal(byId.get(id)?.status, "fail", `${id}: ${byId.get(id)?.summary}`);
    assert.equal(report.discovery?.schema, "openapi");
    assertDiscoveryReadOnly(fixture);
    assert.deepEqual(fixture.counts(), before);
  });
});

test("email and password test accounts sign in and are never deleted", async () => {
  await withFixture({ mode: "hardened", openApi: "forbidden", app: "sample", keyStyle: "publishable" }, async (fixture) => {
    const a = await mintCredentials(fixture, "a");
    const b = await mintCredentials(fixture, "b");
    const report = await scan(
      config(fixture, {
        serviceRole: undefined,
        closedSignup: false,
        signupPath: undefined,
        userAEmail: a.email,
        userAPassword: a.password,
        userBEmail: b.email,
        userBPassword: b.password,
      }),
    );
    const byId = results(report);
    for (const id of DATA_CHECKS) assert.equal(byId.get(id)?.status, "pass", `${id}: ${byId.get(id)?.summary}`);
    assert.equal(fixture.counts().users, 2);
    assert.equal(fixture.counts().notes, 0);
    assert.equal(fixture.counts().profiles, 0);
    assert.equal(fixture.requests.some((request) => request.method === "DELETE" && request.pathname.startsWith("/auth/v1/admin")), false);
    assert.equal(JSON.stringify(report).includes(a.password), false);
    assertDiscoveryReadOnly(fixture);
  });
});

test("a wrong test-account password is a clear error", async () => {
  await withFixture({ mode: "hardened", openApi: "forbidden" }, async (fixture) => {
    const a = await mintCredentials(fixture, "a");
    const b = await mintCredentials(fixture, "b");
    const report = await scan(
      config(fixture, {
        serviceRole: undefined,
        closedSignup: false,
        signupPath: undefined,
        only: ["idor-read"],
        userAEmail: a.email,
        userAPassword: "wrong-password",
        userBEmail: b.email,
        userBPassword: b.password,
      }),
    );
    assert.equal(report.results[0]?.status, "error");
    assert.match(report.results[0]?.summary ?? "", /Could not sign in test user A .*HTTP 400 Invalid login credentials/);
    assert.equal(JSON.stringify(report).includes("wrong-password"), false);
  });
});
