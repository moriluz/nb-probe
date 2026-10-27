import assert from "node:assert/strict";
import { test } from "node:test";

import { CHECK_IDS } from "../src/checks/ids.js";
import { CHECK_LIST } from "../src/checks/index.js";
import { extractScriptSrcs } from "../src/checks/bundle-secrets.js";
import { promotionSeverity } from "../src/checks/self-promotion.js";
import { resolveConfig } from "../src/config.js";
import { buildInsertBody } from "../src/harness.js";
import { parseOpenApi, selectTables } from "../src/openapi.js";
import { exitCode, formatHuman } from "../src/report.js";
import { valueStuck } from "../src/rows.js";
import { findSecrets } from "../src/secrets.js";
import type { ScanReport } from "../src/types.js";
import {
  assertNotServiceRole,
  parseOwnershipBody,
  sameOriginUrl,
  shellQuote,
  toCurl,
  tokensMatch,
  UsageError,
} from "../src/util.js";
import { VERSION } from "../src/version.js";

function fakeJwt(payload: Record<string, unknown>): string {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url");
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  return `${header}.${body}.signatureok`;
}

function report(partial: Partial<ScanReport> & Pick<ScanReport, "ownership" | "results">): ScanReport {
  const summary = {
    pass: partial.results.filter((item) => item.status === "pass").length,
    fail: partial.results.filter((item) => item.status === "fail").length,
    skip: partial.results.filter((item) => item.status === "skip").length,
    error: partial.results.filter((item) => item.status === "error").length,
  };
  return {
    tool: "nb-probe",
    version: VERSION,
    schemaVersion: 1,
    target: "http://127.0.0.1",
    startedAt: "2026-01-01T00:00:00.000Z",
    finishedAt: "2026-01-01T00:00:01.000Z",
    notes: [],
    summary,
    ...partial,
  };
}

test("check ids stay in the documented order", () => {
  assert.deepEqual(
    CHECK_LIST.map((check) => check.id),
    [...CHECK_IDS],
  );
});

test("ownership body parsing and constant-time match", () => {
  assert.equal(tokensMatch("same-token", "same-token"), true);
  assert.equal(tokensMatch("same-token", "same-tokem"), false);
  assert.equal(tokensMatch("short", "much-longer-token"), false);
  assert.equal(parseOwnershipBody("abc-token\n"), "abc-token");
  assert.equal(parseOwnershipBody('{"token":"abc-token"}'), "abc-token");
  assert.equal(parseOwnershipBody("<html>nope</html>"), null);
  assert.equal(parseOwnershipBody("{\"nope\":true}"), null);
});

test("curl quoting survives quotes", () => {
  assert.equal(shellQuote("it's"), `'it'\\''s'`);
  const curl = toCurl({
    method: "PATCH",
    url: "http://127.0.0.1/rest/v1/profiles?id=eq.1",
    headers: { apikey: "anon", authorization: "Bearer anon" },
    body: '{"role":"admin"}',
  });
  assert.match(curl, /^curl -sS -X PATCH /);
  assert.match(curl, /--data-raw '\{"role":"admin"\}'/);
});

test("openapi parser keeps owner, marker, and sensitive columns", () => {
  const tables = parseOpenApi(
    JSON.stringify({
      swagger: "2.0",
      definitions: {
        profiles: {
          type: "object",
          required: ["id"],
          properties: {
            id: { type: "string", format: "uuid", default: "gen", description: "Primary Key.<pk/>" },
            user_id: { type: "string", format: "uuid" },
            note: { type: "string" },
            role: { type: "string", default: "user" },
            is_admin: { type: "boolean", default: false },
            credits: { type: "integer", default: 0 },
          },
        },
        posts: {
          type: "object",
          properties: {
            id: { type: "string", description: "<pk/>" },
            title: { type: "string" },
          },
        },
      },
      paths: { "/profiles": { get: {} }, "/posts": { get: {} }, "/rpc/hidden": { post: {} } },
    }),
  );
  const profiles = tables.find((table) => table.name === "profiles");
  assert.ok(profiles);
  assert.equal(profiles.ownerColumn, "user_id");
  assert.equal(profiles.markerColumn, "note");
  assert.deepEqual(profiles.sensitiveColumns, ["role", "is_admin", "credits"]);
  assert.equal(profiles.columns.find((column) => column.name === "role")?.hasDefault, true);
  const selected = selectTables(tables);
  assert.deepEqual(
    selected.tables.map((table) => table.name),
    ["profiles"],
  );

  const openApi3 = parseOpenApi(
    JSON.stringify({
      openapi: "3.0.0",
      paths: { "/widgets": { get: {} } },
      components: {
        schemas: {
          widgets: {
            type: "object",
            properties: {
              id: { type: "string", description: "<pk/>" },
              owner_id: { type: "string", format: "uuid" },
              body: { type: "string" },
            },
          },
        },
      },
    }),
  );
  assert.equal(openApi3[0]?.ownerColumn, "owner_id");
  assert.equal(openApi3[0]?.markerColumn, "body");
});

test("auto table selection stops at 20", () => {
  const definitions: Record<string, unknown> = {};
  const paths: Record<string, unknown> = {};
  for (let index = 0; index < 21; index += 1) {
    const name = `t${String(index).padStart(2, "0")}`;
    definitions[name] = {
      type: "object",
      properties: {
        id: { type: "string", description: "<pk/>" },
        user_id: { type: "string" },
      },
    };
    paths[`/${name}`] = { get: {} };
  }
  const selected = selectTables(parseOpenApi(JSON.stringify({ definitions, paths })));
  assert.equal(selected.tables.length, 20);
  assert.equal(selected.truncatedFrom, 21);
});

test("insert body does not send privileged columns", () => {
  const [profiles] = parseOpenApi(
    JSON.stringify({
      paths: { "/profiles": { get: {} } },
      definitions: {
        profiles: {
          type: "object",
          required: ["id", "user_id"],
          properties: {
            id: { type: "string", format: "uuid", description: "<pk/>", default: "gen" },
            user_id: { type: "string", format: "uuid" },
            note: { type: "string" },
            role: { type: "string", default: "user" },
            is_admin: { type: "boolean", default: false },
            plan: { type: "string", default: "free" },
            credits: { type: "integer", default: 0 },
          },
        },
      },
    }),
  );
  assert.ok(profiles);
  const body = buildInsertBody(profiles, "user-1", "a@example.com", "nb-probe-a-abc", false);
  assert.equal(body.user_id, "user-1");
  assert.equal(body.note, "nb-probe-a-abc");
  assert.equal("role" in body, false);
  assert.equal("is_admin" in body, false);
  assert.equal("plan" in body, false);
  assert.equal("credits" in body, false);
  assert.equal("id" in body, false);
});

test("secret scan ignores anon keys and comments", () => {
  const anon = fakeJwt({ role: "anon" });
  const service = fakeJwt({ role: "service_role" });
  const hits = findSecrets(
    [
      {
        file: "/assets/app.js",
        text: `
          const anon = "${anon}";
          // never put the service_role key in the client
          const service = "${service}";
          const stripe = "sk_test_nbprobeFakeKey1234";
          const live = "sk_live_notARealKey123";
          const publishable = "pk_test_1234567890abcd";
          const secret = "sb_secret_nbprobeFakeKey1234";
          //# sourceMappingURL=app.js.map
        `,
      },
    ],
    [anon],
  );
  const kinds = hits.map((hit) => `${hit.kind}:${hit.severity}`).sort();
  assert.deepEqual(kinds, [
    "sb_secret:critical",
    "service_role:critical",
    "source_map:low",
    "stripe_secret:critical",
    "stripe_secret:high",
  ]);
  assert.equal(JSON.stringify(hits).includes(service), false);
  assert.equal(JSON.stringify(hits).includes("pk_test_1234567890abcd"), false);
});

test("config rejects a service role passed as the anon key", () => {
  const base = { url: "http://127.0.0.1:9", token: "12345678" };
  assert.throws(() => resolveConfig(base), UsageError);
  assert.throws(
    () =>
      resolveConfig({
        ...base,
        supabaseUrl: "http://127.0.0.1:9/rest/v1",
        anonKey: fakeJwt({ role: "service_role" }),
      }),
    /anon key/i,
  );
  assert.throws(
    () =>
      resolveConfig({
        ...base,
        supabaseUrl: "http://127.0.0.1:9",
        anonKey: "sb_secret_not_the_anon_key",
      }),
    /secret key/i,
  );
  const anon = fakeJwt({ role: "anon" });
  const resolved = resolveConfig({ ...base, supabaseUrl: "http://127.0.0.1:9/rest/v1/", anonKey: anon });
  assert.equal(resolved.supabaseUrl, "http://127.0.0.1:9");
  assert.equal(resolved.anonKey, anon);
  assert.throws(() => resolveConfig({ ...base, signupPath: "https://evil.example/signup" }), /path/i);
  assert.throws(() => assertNotServiceRole(fakeJwt({ role: "service_role" })));
  assert.doesNotThrow(() => assertNotServiceRole(fakeJwt({ role: "authenticated" })));
});

test("script URLs stay on the origin", () => {
  const origin = "http://127.0.0.1:9";
  const html = `
    <script src="/assets/app.js"></script>
    <script src="https://cdn.example/app.js"></script>
    <script src="../secret.js"></script>
    <script>inline</script>
  `;
  assert.deepEqual(extractScriptSrcs(html, origin), ["http://127.0.0.1:9/assets/app.js"]);
  assert.equal(sameOriginUrl(origin, "//cdn.example/app.js"), null);
});

test("exit code follows severity", () => {
  assert.equal(exitCode(report({ ownership: "refused", results: [] })), 2);
  assert.equal(
    exitCode(
      report({
        ownership: "verified",
        results: [
          {
            id: "bundle-secrets",
            title: "Secrets",
            status: "fail",
            severity: "low",
            summary: "source map",
            repro: "curl -sS http://127.0.0.1/",
          },
        ],
      }),
    ),
    0,
  );
  assert.equal(
    exitCode(
      report({
        ownership: "verified",
        results: [
          {
            id: "closed-signup",
            title: "Closed signup",
            status: "fail",
            severity: "medium",
            summary: "open",
            repro: "curl -sS http://127.0.0.1/",
          },
        ],
      }),
    ),
    1,
  );
  assert.equal(
    exitCode(
      report({
        ownership: "verified",
        results: [{ id: "logged-out-read", title: "read", status: "error", severity: "info", summary: "nope" }],
      }),
    ),
    1,
  );
});

test("human report keeps the curl on its own line", () => {
  const text = formatHuman(
    report({
      ownership: "verified",
      results: [
        {
          id: "logged-out-read",
          title: "Logged-out read",
          status: "fail",
          severity: "high",
          summary: "The anon key read probe rows in profiles.",
          fix: "Turn on RLS.",
          repro: "curl -sS 'http://127.0.0.1/rest/v1/profiles'",
        },
      ],
    }),
  );
  assert.match(text, /^nb-probe 0\.1\.0\n/);
  assert.match(text, /FAIL\s+high\s+logged-out-read/);
  assert.match(text, /^curl -sS /m);
  assert.match(text, /1 passed, 0 failed|0 passed, 1 failed/);
});

test("value comparison and promotion severity", () => {
  assert.equal(valueStuck("admin", "admin"), true);
  assert.equal(valueStuck("999999", 999999), true);
  assert.equal(valueStuck("true", true), true);
  assert.equal(valueStuck("user", "admin"), false);
  assert.equal(promotionSeverity("role"), "critical");
  assert.equal(promotionSeverity("is_admin"), "critical");
  assert.equal(promotionSeverity("credits"), "high");
  assert.equal(promotionSeverity("plan"), "high");
});
