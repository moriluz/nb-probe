import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import crypto from "node:crypto";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

import { startFixture } from "./fixture.js";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

// The CLI reads NB_* variables. A shell that exported test-user credentials (NB_USER_A_EMAIL, ...)
// must not leak into these runs.
function cleanEnv(): NodeJS.ProcessEnv {
  return Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith("NB_")));
}

function run(
  args: string[],
  env: NodeJS.ProcessEnv = {},
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve, reject) => {
    const child = spawn(path.join(root, "node_modules", ".bin", "tsx"), ["src/cli.ts", ...args], {
      cwd: root,
      env: { ...cleanEnv(), ...env },
    });
    let stdout = "";
    let stderr = "";
    child.stdout.setEncoding("utf8");
    child.stderr.setEncoding("utf8");
    child.stdout.on("data", (chunk: string) => {
      stdout += chunk;
    });
    child.stderr.on("data", (chunk: string) => {
      stderr += chunk;
    });
    child.on("error", reject);
    child.on("close", (code) => resolve({ code: code ?? 1, stdout, stderr }));
  });
}

test("token and help commands", async () => {
  const token = await run(["token"]);
  assert.equal(token.code, 0);
  assert.match(token.stdout, /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/);
  assert.match(token.stdout, /\/\.well-known\/neural-breach/);

  const help = await run(["--help"]);
  assert.equal(help.code, 0);
  assert.match(help.stdout, /logged-out-read/);
  assert.match(help.stdout, /service role key is never sent/);

  const missing = await run(["scan"]);
  assert.equal(missing.code, 2);
  assert.match(missing.stderr, /--url/);

  const version = await run(["--version"]);
  assert.equal(version.code, 0);
  assert.match(version.stdout, /^0\.3\.0\n/);
});

test("cli scan against the vulnerable fixture exits 1", { timeout: 60_000 }, async () => {
  const token = crypto.randomUUID();
  const fixture = await startFixture({ mode: "vulnerable", token });
  try {
    const result = await run([
      "scan",
      "--url",
      fixture.url,
      "--token",
      token,
      "--supabase-url",
      fixture.url,
      "--anon-key",
      fixture.anonKey,
      "--service-role",
      fixture.serviceRole,
      "--only",
      "logged-out-read",
      "--json",
    ]);
    assert.equal(result.code, 1, result.stderr);
    const report = JSON.parse(result.stdout) as { ownership: string; results: { status: string; repro?: string }[] };
    assert.equal(report.ownership, "verified");
    assert.equal(report.results[0]?.status, "fail");
    assert.match(report.results[0]?.repro ?? "", /^curl /);
    assert.equal(result.stdout.includes(fixture.serviceRole), false);
  } finally {
    await fixture.close();
  }
});

test("cli scan against the hardened fixture exits 0", { timeout: 60_000 }, async () => {
  const token = crypto.randomUUID();
  const fixture = await startFixture({ mode: "hardened", token });
  try {
    const result = await run(["scan", "--json"], {
      NB_URL: fixture.url,
      NB_TOKEN: token,
      NB_SUPABASE_URL: fixture.url,
      NB_ANON_KEY: fixture.anonKey,
      NB_SERVICE_ROLE: fixture.serviceRole,
      NB_CLOSED_SIGNUP: "1",
      NB_SIGNUP_PATH: "/api/signup",
      NB_WEBHOOK_PATH: "/api/webhooks/stripe",
      NB_LLM_PATH: "/api/chat",
    });
    assert.equal(result.code, 0, `${result.stderr}\n${result.stdout}`);
    const report = JSON.parse(result.stdout) as { ownership: string; summary: { fail: number; error: number } };
    assert.equal(report.ownership, "verified");
    assert.equal(report.summary.fail, 0);
    assert.equal(report.summary.error, 0);
    assert.equal(result.stdout.includes(fixture.serviceRole), false);
  } finally {
    await fixture.close();
  }
});

test("NB_USER_* in the shell does not leak into the CLI tests", async () => {
  const leaked = cleanEnv();
  assert.equal(Object.keys(leaked).some((key) => key.startsWith("NB_")), false);
});

test("cli scan of an app under a path, NB_USER_* set in the parent shell", { timeout: 60_000 }, async () => {
  const token = crypto.randomUUID();
  const fixture = await startFixture({ mode: "vulnerable", token, basePath: "/team/app/" });
  const saved = { email: process.env.NB_USER_A_EMAIL, password: process.env.NB_USER_A_PASSWORD };
  process.env.NB_USER_A_EMAIL = "leak@example.com";
  process.env.NB_USER_A_PASSWORD = "leaked-password";
  try {
    const result = await run([
      "scan",
      "--url",
      `${fixture.url}/team/app`,
      "--token",
      token,
      "--supabase-url",
      fixture.url,
      "--anon-key",
      fixture.anonKey,
      "--service-role",
      fixture.serviceRole,
      "--only",
      "logged-out-read,bundle-secrets",
    ]);
    assert.equal(result.code, 1, result.stderr);
    assert.match(result.stdout, /target: http:\/\/127\.0\.0\.1:\d+\/team\/app\//);
    assert.match(result.stdout, /ownership: verified \(\/team\/app\/\.well-known\/neural-breach\)/);
    assert.match(result.stdout, /FAIL .*logged-out-read/);
    assert.match(result.stdout, /FAIL .*bundle-secrets/);
    // Two leaking tables, one curl each.
    assert.match(result.stdout, /^curl .*\/rest\/v1\/notes.*# notes$/m);
    assert.match(result.stdout, /^curl .*\/rest\/v1\/profiles.*# profiles$/m);
    // Exit 1, not 2: the half set of leaked NB_USER_A_* credentials never reached the CLI.
    assert.doesNotMatch(result.stderr, /user-b|test account/i);
  } finally {
    if (saved.email === undefined) delete process.env.NB_USER_A_EMAIL;
    else process.env.NB_USER_A_EMAIL = saved.email;
    if (saved.password === undefined) delete process.env.NB_USER_A_PASSWORD;
    else process.env.NB_USER_A_PASSWORD = saved.password;
    await fixture.close();
  }
});
