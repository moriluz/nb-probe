import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { test } from "node:test";

import { chunkRefs, documentBase, extractScriptSrcs, fetchBundle } from "../src/bundle.js";
import { reproAll } from "../src/checks/common.js";
import { resolveConfig } from "../src/config.js";
import { HttpClient } from "../src/http.js";
import { ownershipUrls } from "../src/ownership.js";
import { exitCode, formatHuman } from "../src/report.js";
import { scan } from "../src/scan.js";
import { appUrl, parseTarget, withinBase } from "../src/target.js";
import type { CheckResult, ScanReport } from "../src/types.js";
import { startFixture, type Fixture, type FixtureOptions } from "./fixture.js";

const BASE = "/team/app/";
const DATA_CHECKS = ["logged-out-read", "idor-read", "idor-write", "self-promotion"];

function results(report: ScanReport): Map<string, CheckResult> {
  return new Map(report.results.map((result) => [result.id, result]));
}

async function withFixture(options: Partial<FixtureOptions>, run: (fixture: Fixture) => Promise<void>): Promise<void> {
  const fixture = await startFixture({ mode: "vulnerable", token: crypto.randomUUID(), basePath: BASE, ...options });
  try {
    await run(fixture);
  } finally {
    await fixture.close();
  }
}

// App requests (not Supabase, not the root ownership file) must stay under the base path.
function assertStayedInBase(fixture: Fixture): void {
  const outside = fixture.requests.filter(
    (request) =>
      !request.pathname.startsWith(BASE) &&
      !request.pathname.startsWith("/rest/v1") &&
      !request.pathname.startsWith("/auth/v1") &&
      request.pathname !== "/.well-known/neural-breach",
  );
  assert.deepEqual(
    outside.map((request) => `${request.method} ${request.pathname}`),
    [],
    "requests outside the app path",
  );
}

test("parseTarget: origin, sub-path, trailing slash, index.html, fragment", () => {
  assert.deepEqual(parseTarget("https://app.example"), {
    origin: "https://app.example",
    base: "https://app.example/",
    basePath: "/",
    entry: "https://app.example/",
  });
  for (const input of [
    "https://moriluz.github.io/nb-lab",
    "https://moriluz.github.io/nb-lab/",
    "https://moriluz.github.io/nb-lab/#/login",
  ]) {
    const target = parseTarget(input);
    assert.equal(target.base, "https://moriluz.github.io/nb-lab/", input);
    assert.equal(target.basePath, "/nb-lab/");
    assert.equal(target.entry, "https://moriluz.github.io/nb-lab/");
  }
  const page = parseTarget("https://host.example/a/b/index.html");
  assert.equal(page.base, "https://host.example/a/b/");
  assert.equal(page.entry, "https://host.example/a/b/index.html");
  assert.equal(parseTarget("https://host.example/a/../b/").basePath, "/b/");
  assert.throws(() => parseTarget("https://host.example/app/?x=1"), /query/);
  assert.throws(() => parseTarget("https://host.example/a%2fb/"), /encoded/);
  assert.throws(() => parseTarget("https://host.example//evil/"), /empty path/);
  assert.throws(() => parseTarget("ftp://host.example/app/"), /http or https/);
  assert.throws(() => parseTarget("https://u:p@host.example/app/"), /credentials/);
});

test("resolveConfig keeps root targets as before and shows sub-path targets as the base URL", () => {
  const root = resolveConfig({ url: "https://app.example/", token: "0123456789abcdef" });
  assert.equal(root.url, "https://app.example");
  assert.equal(root.target.basePath, "/");
  const sub = resolveConfig({ url: "https://user.github.io/my-app", token: "0123456789abcdef" });
  assert.equal(sub.url, "https://user.github.io/my-app/");
  assert.equal(sub.target.basePath, "/my-app/");
});

test("ownership locations: root app checks the root, sub-path app checks the path then the root", () => {
  assert.deepEqual(ownershipUrls(parseTarget("https://app.example")), ["https://app.example/.well-known/neural-breach"]);
  assert.deepEqual(ownershipUrls(parseTarget("https://user.github.io/my-app/index.html")), [
    "https://user.github.io/my-app/.well-known/neural-breach",
    "https://user.github.io/.well-known/neural-breach",
  ]);
});

test("app routes and scope under a path", () => {
  const target = parseTarget("https://host.example/team/app/");
  assert.equal(appUrl(target, "/api/chat"), "https://host.example/team/app/api/chat");
  assert.equal(appUrl(parseTarget("https://host.example"), "/api/chat"), "https://host.example/api/chat");
  assert.equal(withinBase(target, "https://host.example/team/app/"), true);
  assert.equal(withinBase(target, "https://host.example/team/app"), true);
  assert.equal(withinBase(target, "https://host.example/team/app/x/y.html"), true);
  assert.equal(withinBase(target, "https://host.example/team/application/"), false);
  assert.equal(withinBase(target, "https://host.example/"), false);
  assert.equal(withinBase(target, "https://other.example/team/app/"), false);
});

test("page references resolve against the page URL or <base href>", () => {
  const page = "https://host.example/team/app/";
  const html = `
    <script type="module" src="./assets/main.js"></script>
    <script src="assets/legacy.js"></script>
    <script src="/team/app/assets/abs.js"></script>
    <script src="/shared/vendor.js"></script>
    <script src="../other/x.js"></script>
    <script src="https://cdn.example/lib.js"></script>
  `;
  assert.deepEqual(extractScriptSrcs(html, page), [
    "https://host.example/team/app/assets/main.js",
    "https://host.example/team/app/assets/legacy.js",
    "https://host.example/team/app/assets/abs.js",
    "https://host.example/shared/vendor.js",
    "https://host.example/team/other/x.js",
  ]);
  const withBase = `<head><base href="/team/app/"></head>`;
  assert.equal(documentBase(withBase, "https://host.example/team/app/index.html", "https://host.example"), page);
  assert.equal(
    documentBase(`<base href="https://evil.example/">`, "https://host.example/team/app/", "https://host.example"),
    "https://host.example/team/app/",
  );
  // A root page keeps resolving against the root.
  assert.deepEqual(extractScriptSrcs(`<script src="assets/a.js"></script>`, "https://app.example"), [
    "https://app.example/assets/a.js",
  ]);
});

test("chunk refs: Vite assets/ and Next static/ resolve under the app path", () => {
  const target = parseTarget("https://host.example/team/app/");
  const text =
    'import("./Billing-K4.js");const deps=["assets/Dashboard-x1.js","static/chunks/page-9.js"];import("/team/app/assets/abs-2.js");import("../vendor/v-3.js")';
  const refs = chunkRefs(text, "https://host.example/team/app/assets/main.js", target).sort();
  assert.deepEqual(
    refs,
    [
      "https://host.example/team/app/_next/static/chunks/page-9.js",
      "https://host.example/team/app/assets/Billing-K4.js",
      "https://host.example/team/app/assets/Dashboard-x1.js",
      "https://host.example/team/app/assets/abs-2.js",
      "https://host.example/team/app/vendor/v-3.js",
    ].sort(),
  );
  // Root apps behave as before.
  const root = chunkRefs('const a="assets/D-1.js",b="static/chunks/p-2.js"', "https://app.example/assets/main.js", "https://app.example");
  assert.deepEqual(root.sort(), ["https://app.example/_next/static/chunks/p-2.js", "https://app.example/assets/D-1.js"]);
});

test("reproAll: one bare curl for one table, one tagged line per table for several", () => {
  assert.equal(reproAll([]), undefined);
  assert.equal(reproAll([{ label: "notes", repro: "curl -sS 'a'" }]), "curl -sS 'a'");
  assert.equal(
    reproAll([
      { label: "invoices", repro: "curl -sS 'a'" },
      { label: "messages", repro: "curl -sS 'b'" },
      { label: "messages", repro: "curl -sS 'c'" },
    ]),
    "curl -sS 'a'  # invoices\ncurl -sS 'b'  # messages",
  );
});

for (const subpathRefs of ["relative", "absolute", "base-href"] as const) {
  test(`sub-path app (${subpathRefs} script paths): verified, bundle read, routes stay under the path`, async () => {
    await withFixture({ subpathRefs }, async (fixture) => {
      const report = await scan({
        url: `${fixture.url}/team/app`,
        token: fixture.token,
        supabaseUrl: fixture.url,
        anonKey: fixture.anonKey,
        serviceRole: fixture.serviceRole,
        llmPath: "/api/chat",
        webhookPath: "/api/webhooks/stripe",
        timeoutMs: 5000,
      });
      assert.equal(report.ownership, "verified");
      assert.equal(report.target, fixture.appUrl);
      assert.equal(report.ownershipFile, `${fixture.appUrl}.well-known/neural-breach`);
      const byId = results(report);
      assert.equal(byId.get("bundle-secrets")?.status, "fail", byId.get("bundle-secrets")?.summary);
      assert.equal(byId.get("webhook-signature")?.status, "fail", byId.get("webhook-signature")?.summary);
      assert.match(byId.get("webhook-signature")?.repro ?? "", /\/team\/app\/api\/webhooks\/stripe/);
      assert.equal(byId.get("llm-endpoint")?.status, "fail", byId.get("llm-endpoint")?.summary);
      for (const id of DATA_CHECKS) assert.equal(byId.get(id)?.status, "fail", `${id}: ${byId.get(id)?.summary}`);
      // Two leaking tables: a curl for each.
      const repro = byId.get("idor-read")?.repro ?? "";
      assert.match(repro, /# notes$/m);
      assert.match(repro, /# profiles$/m);
      assert.equal(exitCode(report), 1);
      assert.ok(fixture.requests.some((request) => request.pathname === `${BASE}assets/app.js`));
      // The root ownership file is not needed when the path one matches.
      assert.equal(fixture.requests.some((request) => request.pathname === "/.well-known/neural-breach"), false);
      assertStayedInBase(fixture);
      assert.deepEqual(fixture.counts(), { users: 0, profiles: 0, notes: 0, posts: 1 });
      assert.match(formatHuman(report), /ownership: verified \(\/team\/app\/\.well-known\/neural-breach\)/);
    });
  });
}

test("sub-path app with hosted-style 403 schema: tables come from the sub-path bundle and source map", async () => {
  await withFixture({ openApi: "forbidden", app: "sample", keyStyle: "publishable", subpathRefs: "absolute" }, async (fixture) => {
    const report = await scan({
      url: `${fixture.appUrl}index.html`,
      token: fixture.token,
      supabaseUrl: fixture.url,
      anonKey: fixture.anonKey,
      serviceRole: fixture.serviceRole,
      timeoutMs: 5000,
    });
    assert.equal(report.ownership, "verified");
    const discovery = report.discovery;
    assert.ok(discovery);
    assert.equal(discovery.schema, "discovery");
    const table = (name: string) => discovery.tables.find((item) => item.name === name);
    assert.equal(table("notes")?.status, "probed");
    assert.ok(table("notes")?.sources.includes("bundle"));
    assert.ok(table("posts")?.sources.includes("source-map"));
    assert.ok(discovery.files.scripts >= 3, `scripts: ${discovery.files.scripts}`);
    assert.deepEqual(discovery.files.errors, []);
    for (const id of DATA_CHECKS) assert.equal(results(report).get(id)?.status, "fail");
    assertStayedInBase(fixture);
  });
});

test("sub-path app: the origin-root ownership file also proves ownership", async () => {
  await withFixture({ mode: "hardened", ownershipAt: ["root"], leakSecrets: false, sourceMap: false }, async (fixture) => {
    const report = await scan({ url: fixture.appUrl, token: fixture.token, only: "bundle-secrets", timeoutMs: 5000 });
    assert.equal(report.ownership, "verified");
    assert.equal(report.ownershipFile, `${fixture.url}/.well-known/neural-breach`);
    assert.equal(results(report).get("bundle-secrets")?.status, "pass");
  });
});

test("sub-path app: a wrong token under the path refuses without trying the root", async () => {
  const token = crypto.randomUUID();
  await withFixture({ token: crypto.randomUUID(), rootToken: token, ownershipAt: ["base", "root"] }, async (fixture) => {
    const report = await scan({ url: fixture.appUrl, token, timeoutMs: 5000 });
    assert.equal(report.ownership, "refused");
    assert.match(report.message ?? "", /\/team\/app\/\.well-known\/neural-breach did not match/);
    assert.equal(exitCode(report), 2);
    assert.deepEqual(
      fixture.requests.map((request) => request.pathname),
      [`${BASE}.well-known/neural-breach`],
    );
  });
});

test("sub-path app: a wrong token at the root is refused too", async () => {
  await withFixture({ ownershipAt: ["root"], rootToken: crypto.randomUUID() }, async (fixture) => {
    const report = await scan({ url: fixture.appUrl, token: fixture.token, timeoutMs: 5000 });
    assert.equal(report.ownership, "refused");
    assert.match(report.message ?? "", /did not match/);
    assert.equal(report.results.length, 0);
  });
});

test("sub-path app: no ownership file anywhere is refused and names both paths", async () => {
  await withFixture({ serveOwnership: false }, async (fixture) => {
    const report = await scan({ url: fixture.appUrl, token: fixture.token, timeoutMs: 5000 });
    assert.equal(report.ownership, "refused");
    assert.match(report.message ?? "", /\/team\/app\/\.well-known\/neural-breach or \/\.well-known\/neural-breach/);
    assert.match(report.message ?? "", /HTTP 404/);
    assert.equal(report.results.length, 0);
    assert.ok(fixture.requests.every((request) => request.pathname.endsWith(".well-known/neural-breach")));
  });
});

test("an HTML page at the path location falls through to the root file", async () => {
  const token = crypto.randomUUID();
  const server = http.createServer((req, res) => {
    if (req.url === "/app/.well-known/neural-breach") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<!doctype html><title>SPA</title>");
      return;
    }
    if (req.url === "/.well-known/neural-breach") {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end(token);
      return;
    }
    if (req.url === "/app/") {
      res.writeHead(200, { "content-type": "text/html" });
      res.end("<!doctype html><title>App</title>");
      return;
    }
    res.writeHead(404);
    res.end();
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address() as AddressInfo;
    const report = await scan({ url: `http://127.0.0.1:${port}/app/`, token, only: "bundle-secrets" });
    assert.equal(report.ownership, "verified");
    assert.equal(report.ownershipFile, `http://127.0.0.1:${port}/.well-known/neural-breach`);
  } finally {
    server.close();
  }
});

test("an entry page that redirects out of the path is not read", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/app/") {
      res.writeHead(302, { location: "/login/" });
      res.end();
      return;
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end(`<!doctype html><script src="/login/x.js"></script>`);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  try {
    const { port } = server.address() as AddressInfo;
    const bundle = await fetchBundle(new HttpClient(5000), parseTarget(`http://127.0.0.1:${port}/app/`));
    assert.match(bundle.pageError ?? "", /outside \/app\//);
    assert.equal(bundle.files.length, 0);
  } finally {
    server.close();
  }
});
