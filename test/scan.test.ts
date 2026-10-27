import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import crypto from "node:crypto";
import http from "node:http";
import { promisify } from "node:util";
import { test } from "node:test";

import { CHECK_IDS } from "../src/checks/ids.js";
import { HttpClient } from "../src/http.js";
import { exitCode } from "../src/report.js";
import { scan } from "../src/scan.js";
import { SupabaseClient } from "../src/supabase.js";
import type { CheckResult, ScanConfig, ScanReport } from "../src/types.js";
import { startFixture, type Fixture } from "./fixture.js";

const execFileAsync = promisify(execFile);

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

function resultMap(report: ScanReport): Map<string, CheckResult> {
  return new Map(report.results.map((result) => [result.id, result]));
}

function assertFail(result: CheckResult | undefined, severity: CheckResult["severity"]): void {
  assert.ok(result, "missing result");
  assert.equal(result.status, "fail");
  assert.equal(result.severity, severity);
  assert.match(result.repro ?? "", /^curl /);
  assert.equal(result.fix && result.fix.length > 20, true);
}

async function runCurl(command: string): Promise<string> {
  const { stdout } = await execFileAsync("bash", ["-c", command], { timeout: 10_000, maxBuffer: 1_000_000 });
  return stdout;
}

test("refuses to scan when the ownership token does not match", async () => {
  const fixture = await startFixture({ mode: "vulnerable", token: crypto.randomUUID() });
  try {
    const report = await scan({ url: fixture.url, token: "0123456789abcdef", timeoutMs: 5000 });
    assert.equal(report.ownership, "refused");
    assert.equal(report.results.length, 0);
    assert.match(report.message ?? "", /did not match/);
    assert.equal(exitCode(report), 2);
    assert.ok(fixture.requests.every((request) => request.pathname === "/.well-known/neural-breach"));
    assert.equal(JSON.stringify(report).includes(fixture.token), false);
  } finally {
    await fixture.close();
  }
});

test("refuses a missing ownership file and a redirect", async () => {
  const missing = await startFixture({ mode: "hardened", serveOwnership: false, token: crypto.randomUUID() });
  try {
    const report = await scan({ url: missing.url, token: missing.token, timeoutMs: 5000 });
    assert.equal(report.ownership, "refused");
    assert.match(report.message ?? "", /HTTP 404/);
    assert.equal(exitCode(report), 2);
  } finally {
    await missing.close();
  }

  const redirect = http.createServer((_req, res) => {
    res.writeHead(302, { location: "/moved" });
    res.end();
  });
  await new Promise<void>((resolve) => redirect.listen(0, "127.0.0.1", resolve));
  const address = redirect.address();
  assert.ok(address && typeof address !== "string");
  try {
    const report = await scan({
      url: `http://127.0.0.1:${address.port}`,
      token: "0123456789abcdef",
      timeoutMs: 5000,
    });
    assert.equal(report.ownership, "refused");
    assert.match(report.message ?? "", /redirect/i);
  } finally {
    redirect.close();
  }
});

test("accepts a JSON ownership file", async () => {
  const token = crypto.randomUUID();
  const fixture = await startFixture({ mode: "hardened", token, tokenStyle: "json", leakSecrets: false, sourceMap: false });
  try {
    const report = await scan({ url: fixture.url, token, only: ["bundle-secrets"], timeoutMs: 5000 });
    assert.equal(report.ownership, "verified");
    assert.equal(report.results.length, 1);
    assert.equal(report.results[0]?.status, "pass");
  } finally {
    await fixture.close();
  }
});

test("vulnerable fixture fails the checks and the curl reproduces the read", async () => {
  const token = crypto.randomUUID();
  const fixture = await startFixture({ mode: "vulnerable", token });
  try {
    const report = await scan(config(fixture));
    assert.equal(report.ownership, "verified");
    assert.deepEqual(
      report.results.map((result) => result.id),
      [...CHECK_IDS],
    );
    const results = resultMap(report);
    assertFail(results.get("logged-out-read"), "high");
    assertFail(results.get("idor-read"), "high");
    assertFail(results.get("idor-write"), "critical");
    assertFail(results.get("self-promotion"), "critical");
    assertFail(results.get("closed-signup"), "medium");
    assertFail(results.get("bundle-secrets"), "critical");
    assertFail(results.get("webhook-signature"), "high");
    assertFail(results.get("llm-endpoint"), "high");
    assert.equal(exitCode(report), 1);

    const leaks = results.get("logged-out-read")?.evidence?.leaks as { marker: string; table: string }[];
    assert.ok(Array.isArray(leaks));
    assert.ok(leaks.some((leak) => leak.table === "profiles"));
    assert.ok(leaks.some((leak) => leak.table === "notes"));

    const bundleBody = await runCurl(results.get("bundle-secrets")?.repro ?? "");
    assert.ok(bundleBody.includes(fixture.leakedServiceRole));

    const blob = JSON.stringify(report);
    assert.equal(blob.includes(fixture.serviceRole), false);
    assert.equal(blob.includes(fixture.leakedServiceRole), false);
    assert.equal(blob.includes(token), false);
    assert.match(results.get("self-promotion")?.summary ?? "", /role/);
    assert.equal(
      fixture.requests.some((request) => request.pathname.startsWith("/rest/v1/posts")),
      false,
    );
    const data = fixture.requests.filter((request) => request.pathname.startsWith("/rest/v1"));
    assert.ok(data.length > 0);
    assert.ok(data.every((request) => request.role !== "service_role" && request.apikeyRole !== "service_role"));
    assert.equal(fixture.counts().users, 0);
    assert.equal(fixture.counts().profiles, 0);
    assert.equal(fixture.counts().notes, 0);
    assert.equal(fixture.counts().posts, 1);
  } finally {
    await fixture.close();
  }
});

test("hardened fixture passes, including cleanup", async () => {
  const token = crypto.randomUUID();
  const fixture = await startFixture({ mode: "hardened", token });
  try {
    const report = await scan(config(fixture));
    assert.equal(report.ownership, "verified");
    for (const result of report.results) {
      assert.equal(result.status, "pass", `${result.id}: ${result.summary}`);
    }
    assert.equal(exitCode(report), 0);
    assert.equal(fixture.counts().users, 0);
    assert.equal(fixture.counts().profiles, 0);
    assert.equal(fixture.counts().notes, 0);
    const blob = JSON.stringify(report);
    assert.equal(blob.includes(fixture.serviceRole), false);
    assert.equal(blob.includes(token), false);
  } finally {
    await fixture.close();
  }
});

test("a public source map alone does not fail the process", async () => {
  const fixture = await startFixture({
    mode: "hardened",
    token: crypto.randomUUID(),
    sourceMap: true,
    leakSecrets: false,
  });
  try {
    const report = await scan(config(fixture));
    const bundle = report.results.find((result) => result.id === "bundle-secrets");
    assert.equal(bundle?.status, "fail");
    assert.equal(bundle?.severity, "low");
    assert.match(bundle?.repro ?? "", /sourceMappingURL/);
    assert.ok(report.results.filter((result) => result.id !== "bundle-secrets").every((result) => result.status === "pass"));
    assert.equal(exitCode(report), 0);
  } finally {
    await fixture.close();
  }
});

test("signup disabled without a service role is an error, not a pass", async () => {
  const fixture = await startFixture({ mode: "hardened", token: crypto.randomUUID() });
  try {
    const { serviceRole: _serviceRole, ...withoutRole } = config(fixture);
    const report = await scan(withoutRole);
    const read = report.results.find((result) => result.id === "logged-out-read");
    assert.equal(read?.status, "error");
    assert.match(read?.summary ?? "", /service-role|user-a|signup/i);
    const signup = report.results.find((result) => result.id === "closed-signup");
    assert.equal(signup?.status, "pass");
    assert.equal(exitCode(report), 1);
    assert.equal(fixture.counts().users, 0);
  } finally {
    await fixture.close();
  }
});

test("existing user JWTs are enough for the data checks", async () => {
  const fixture = await startFixture({ mode: "hardened", token: crypto.randomUUID() });
  try {
    const userA = await mintUser(fixture, `nb-probe-jwt-a-${crypto.randomBytes(4).toString("hex")}@example.com`);
    const userB = await mintUser(fixture, `nb-probe-jwt-b-${crypto.randomBytes(4).toString("hex")}@example.com`);
    const report = await scan(
      config(fixture, { userA, userB, serviceRole: undefined, closedSignup: false, signupPath: undefined }),
    );
    for (const id of ["logged-out-read", "idor-read", "idor-write", "self-promotion"]) {
      const result = report.results.find((item) => item.id === id);
      assert.equal(result?.status, "pass", `${id}: ${result?.summary}`);
    }
    assert.equal(fixture.counts().profiles, 0);
    assert.equal(fixture.counts().notes, 0);
    assert.equal(fixture.counts().users, 2);
  } finally {
    await fixture.close();
  }
});

test("--only runs a single check", async () => {
  const fixture = await startFixture({ mode: "vulnerable", token: crypto.randomUUID() });
  try {
    const report = await scan(config(fixture, { only: ["logged-out-read"], closedSignup: false }));
    assert.deepEqual(
      report.results.map((result) => result.id),
      ["logged-out-read"],
    );
    assert.equal(report.results[0]?.status, "fail");
    assert.equal(exitCode(report), 1);
  } finally {
    await fixture.close();
  }
});

test("--no-cleanup leaves probe rows and users", async () => {
  const fixture = await startFixture({ mode: "vulnerable", token: crypto.randomUUID() });
  try {
    const report = await scan(config(fixture, { cleanup: false }));
    assert.equal(exitCode(report), 1);
    assert.ok(fixture.counts().users >= 2);
    assert.ok(fixture.counts().profiles >= 1);
    assert.ok(fixture.counts().notes >= 1);
    assert.match(report.notes.join(" "), /no-cleanup/i);

    const results = resultMap(report);
    const leaks = results.get("logged-out-read")?.evidence?.leaks as { marker: string }[] | undefined;
    const marker = leaks?.[0]?.marker;
    assert.ok(marker);
    const readBody = await runCurl(results.get("logged-out-read")?.repro ?? "");
    assert.ok(readBody.includes(marker), readBody);
    const idor = results.get("idor-read")?.evidence?.leaks as { id: string }[] | undefined;
    const idorId = idor?.[0]?.id;
    assert.ok(idorId);
    const idorBody = await runCurl(results.get("idor-read")?.repro ?? "");
    assert.ok(idorBody.includes(idorId), idorBody);
  } finally {
    await fixture.close();
  }
});

test("service role helper refuses data API paths", async () => {
  const fixture = await startFixture({ mode: "hardened", token: crypto.randomUUID() });
  try {
    const client = new SupabaseClient(new HttpClient(5000), fixture.url, fixture.anonKey);
    await assert.rejects(() => client.admin("GET", "/rest/v1/profiles", fixture.serviceRole), /auth\/v1\/admin/);
  } finally {
    await fixture.close();
  }
});

async function mintUser(fixture: Fixture, email: string): Promise<string> {
  const password = "nb-probe-jwt-user-password";
  const created = await fetch(`${fixture.url}/auth/v1/admin/users`, {
    method: "POST",
    headers: {
      apikey: fixture.serviceRole,
      authorization: `Bearer ${fixture.serviceRole}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ email, password, email_confirm: true }),
  });
  assert.equal(created.status, 200);
  const granted = await fetch(`${fixture.url}/auth/v1/token?grant_type=password`, {
    method: "POST",
    headers: {
      apikey: fixture.anonKey,
      authorization: `Bearer ${fixture.anonKey}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ email, password }),
  });
  assert.equal(granted.status, 200);
  const body = (await granted.json()) as { access_token?: string };
  assert.equal(typeof body.access_token, "string");
  return body.access_token ?? "";
}
