import crypto from "node:crypto";

import { shellQuote } from "../src/util.js";
import { startFixture, type FixtureMode } from "./fixture.js";

const mode: FixtureMode = process.argv[2] === "hardened" ? "hardened" : "vulnerable";
const port = Number(process.env.PORT ?? 40123);
const token = process.env.NB_TOKEN ?? crypto.randomUUID();
const fixture = await startFixture({ mode, port, token });

const scan = [
  "npx tsx src/cli.ts scan",
  "--url",
  fixture.url,
  "--token",
  fixture.token,
  "--supabase-url",
  fixture.url,
  "--anon-key",
  fixture.anonKey,
  "--service-role",
  fixture.serviceRole,
  "--closed-signup",
  "--signup-path",
  "/api/signup",
  "--webhook-path",
  "/api/webhooks/stripe",
  "--llm-path",
  "/api/chat",
]
  .map((part, index) => (index === 0 ? part : shellQuote(part)))
  .join(" ");

process.stdout.write(`fixture: ${mode}\n`);
process.stdout.write(`url: ${fixture.url}\n`);
process.stdout.write(`token: ${fixture.token}\n`);
process.stdout.write("\n");
process.stdout.write(`${scan}\n`);
process.stdout.write("\nCtrl-C stops the fixture. It listens on 127.0.0.1 only.\n");

for (const signal of ["SIGINT", "SIGTERM"] as const) {
  process.on(signal, () => {
    void fixture.close().then(() => process.exit(0));
  });
}
