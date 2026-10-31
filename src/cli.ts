#!/usr/bin/env node
import crypto from "node:crypto";
import { parseArgs } from "node:util";

import { CHECK_LIST } from "./checks/index.js";
import { exitCode, formatHuman, formatJson } from "./report.js";
import { scan } from "./scan.js";
import type { ScanConfig } from "./types.js";
import { errorMessage, UsageError } from "./util.js";
import { VERSION } from "./version.js";

const HELP = `nb-probe ${VERSION}
Ownership-gated checks for an app you control. Supabase first.

Usage:
  nb-probe token
  nb-probe scan --url <app url> --token <token> [options]

Options:
  --url              Where the app is served: https://app.example, or a
                     sub-path such as https://user.github.io/my-app/
  --token            Value served at .well-known/neural-breach under the
                     app path, or at the origin root
  --supabase-url     Supabase project origin
  --anon-key         Supabase anon or publishable key
  --service-role     Optional. Used only to create and delete probe users
  --tables           Comma-separated tables to probe. Checked against
                     PostgREST directly when the API schema is not
                     readable (hosted Supabase since April 2026)
  --user-a           Existing user JWT. Requires --user-b
  --user-b           Existing user JWT. Requires --user-a
  --user-a-email     Test account A email. Signs in with the password below
  --user-a-password  Test account A password (prefer NB_USER_A_PASSWORD)
  --user-b-email     Test account B email
  --user-b-password  Test account B password (prefer NB_USER_B_PASSWORD)
  --signup-path      App path to call when --closed-signup is set
                     (--signup-path, --webhook-path and --llm-path are
                     relative to the app path in --url)
  --closed-signup    Assert that public registration must fail
  --webhook-path     Webhook path to probe
  --llm-path         LLM path to probe
  --only             Comma-separated check ids to run
  --timeout          Per-request timeout in ms (default 10000)
  --json             Print a JSON report on stdout
  --no-cleanup       Leave probe rows and users in place
  -h, --help
  -v, --version

Checks:
${CHECK_LIST.map((check) => `  ${check.id.padEnd(20)} ${check.title}`).join("\n")}

The ownership file is required. The scan does not start without it.
A service role key is never sent to the Data API.

Exit codes:
  0  no failed check at medium or above
  1  a medium, high, or critical failure, or a check error
  2  ownership refused, or the command line was wrong
  3  unexpected failure

A low failure on its own (a public source map) exits 0.
Keys in the command line are visible to other users on the machine. Prefer
NB_URL, NB_TOKEN, NB_SUPABASE_URL, NB_ANON_KEY, NB_SERVICE_ROLE,
NB_USER_A_EMAIL, NB_USER_A_PASSWORD, NB_USER_B_EMAIL, and NB_USER_B_PASSWORD.
`;

function env(name: string): string | undefined {
  const value = process.env[name];
  if (!value) return undefined;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : undefined;
}

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    strict: true,
    options: {
      url: { type: "string" },
      token: { type: "string" },
      "supabase-url": { type: "string" },
      "anon-key": { type: "string" },
      "service-role": { type: "string" },
      tables: { type: "string" },
      "user-a": { type: "string" },
      "user-b": { type: "string" },
      "user-a-email": { type: "string" },
      "user-a-password": { type: "string" },
      "user-b-email": { type: "string" },
      "user-b-password": { type: "string" },
      "signup-path": { type: "string" },
      "closed-signup": { type: "boolean" },
      "webhook-path": { type: "string" },
      "llm-path": { type: "string" },
      only: { type: "string" },
      timeout: { type: "string" },
      json: { type: "boolean" },
      "no-cleanup": { type: "boolean" },
      help: { type: "boolean", short: "h" },
      version: { type: "boolean", short: "v" },
    },
  });

  if (values.help || positionals[0] === "help") {
    process.stdout.write(HELP);
    return;
  }
  if (values.version || positionals[0] === "version") {
    process.stdout.write(`${VERSION}\n`);
    return;
  }

  const command = positionals[0];
  if (!command) {
    process.stdout.write(HELP);
    return;
  }
  if (positionals.length > 1) throw new UsageError("Too many arguments.");
  if (command === "token") {
    printToken();
    return;
  }
  if (command !== "scan") throw new UsageError(`Unknown command "${command}".`);

  const timeoutRaw = values.timeout ?? env("NB_TIMEOUT");
  const config: ScanConfig = {
    closedSignup: Boolean(values["closed-signup"]) || env("NB_CLOSED_SIGNUP") === "1",
    cleanup: !values["no-cleanup"],
  };
  const url = values.url ?? env("NB_URL");
  const token = values.token ?? env("NB_TOKEN");
  const supabaseUrl = values["supabase-url"] ?? env("NB_SUPABASE_URL");
  const anonKey = values["anon-key"] ?? env("NB_ANON_KEY");
  const serviceRole = values["service-role"] ?? env("NB_SERVICE_ROLE");
  const tables = values.tables ?? env("NB_TABLES");
  const userA = values["user-a"] ?? env("NB_USER_A");
  const userB = values["user-b"] ?? env("NB_USER_B");
  const userAEmail = values["user-a-email"] ?? env("NB_USER_A_EMAIL");
  const userAPassword = values["user-a-password"] ?? process.env.NB_USER_A_PASSWORD;
  const userBEmail = values["user-b-email"] ?? env("NB_USER_B_EMAIL");
  const userBPassword = values["user-b-password"] ?? process.env.NB_USER_B_PASSWORD;
  const signupPath = values["signup-path"] ?? env("NB_SIGNUP_PATH");
  const webhookPath = values["webhook-path"] ?? env("NB_WEBHOOK_PATH");
  const llmPath = values["llm-path"] ?? env("NB_LLM_PATH");
  const only = values.only ?? env("NB_ONLY");
  if (url) config.url = url;
  if (token) config.token = token;
  if (supabaseUrl) config.supabaseUrl = supabaseUrl;
  if (anonKey) config.anonKey = anonKey;
  if (serviceRole) config.serviceRole = serviceRole;
  if (tables) config.tables = tables;
  if (userA) config.userA = userA;
  if (userB) config.userB = userB;
  if (userAEmail) config.userAEmail = userAEmail;
  if (userAPassword) config.userAPassword = userAPassword;
  if (userBEmail) config.userBEmail = userBEmail;
  if (userBPassword) config.userBPassword = userBPassword;
  if (signupPath) config.signupPath = signupPath;
  if (webhookPath) config.webhookPath = webhookPath;
  if (llmPath) config.llmPath = llmPath;
  if (only) config.only = only;
  if (timeoutRaw) {
    const timeoutMs = Number(timeoutRaw);
    if (!Number.isInteger(timeoutMs)) throw new UsageError("--timeout must be an integer");
    config.timeoutMs = timeoutMs;
  }

  const report = await scan(config);
  process.stdout.write(values.json ? formatJson(report) : formatHuman(report));
  process.exitCode = exitCode(report);
}

function printToken(): void {
  const token = crypto.randomUUID();
  process.stdout.write(`${token}\n\n`);
  process.stdout.write("Serve that line, and nothing else, at /.well-known/neural-breach\n");
  process.stdout.write("on the origin you are about to scan. text/plain is enough.\n");
  process.stdout.write("For an app under a path, such as https://user.github.io/my-app/, put it at\n");
  process.stdout.write("/my-app/.well-known/neural-breach instead. The origin root also works.\n");
  process.stdout.write(`JSON also works: {"token":"${token}"}\n\n`);
  process.stdout.write("Anyone who can request the URL can read the token. Remove the file when you are done.\n");
}

main().catch((err: unknown) => {
  if (err instanceof UsageError || (err instanceof TypeError && /option|argument/i.test(err.message))) {
    process.stderr.write(`nb-probe: ${errorMessage(err)}\n`);
    process.exitCode = 2;
    return;
  }
  process.stderr.write(`nb-probe: ${errorMessage(err)}\n`);
  process.exitCode = 3;
});
