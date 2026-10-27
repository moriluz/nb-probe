# nb-probe

nb-probe is a small CLI that checks an app you control for the failures that show up when an agent scaffolds a Supabase project and moves on: RLS left off, a service role key compiled into the client, a webhook that trusts its body, a chat route with no session.

It is free, MIT licensed, and it does not phone home. The package name and the bin are `nb-probe`. Publishing to npm is not wired up. After `npm run build`, `node dist/cli.js` works, and so does `npx tsx src/cli.ts`. A later `npm publish` is a separate step.

Neural Breach (neural-breach.com) is the name on the work. This repository is the scanner, not a pitch.

## Install

Node 20 or newer.

```bash
npm install
npm test
npm run build
node dist/cli.js --help
```

During development:

```bash
npx tsx src/cli.ts token
npx tsx src/cli.ts scan --help
```

Keys on the command line are visible to other users on the same machine. The flags below all have environment equivalents: `NB_URL`, `NB_TOKEN`, `NB_SUPABASE_URL`, `NB_ANON_KEY`, `NB_SERVICE_ROLE`, `NB_TABLES`, `NB_USER_A`, `NB_USER_B`, `NB_SIGNUP_PATH`, `NB_CLOSED_SIGNUP=1`, `NB_WEBHOOK_PATH`, `NB_LLM_PATH`, `NB_ONLY`, `NB_TIMEOUT`.

## Prove you own the origin

The scan does not start until the origin serves a token you generated.

```bash
npx tsx src/cli.ts token
```

That prints one line. Put that line, alone, in a file served at:

```text
https://YOUR_ORIGIN/.well-known/neural-breach
```

Requirements:

- `GET` returns HTTP 200 from that exact path. No redirect.
- Body is the token as `text/plain`, with an optional trailing newline.
- Or JSON: `{"token":"<the same value>"}`.
- The route is not behind a login. The probe fetches it with no credentials.
- The file lives on the app origin you pass as `--url`, not on the Supabase project URL.
- The token is 8 to 200 characters: letters, digits, `.`, `_`, `~`, `-`. A UUID from the `token` command is the intended shape.

On a Next.js or Vite app, save it as `public/.well-known/neural-breach` (no file extension).

Then:

```bash
npx tsx src/cli.ts scan --url https://app.example --token 'THE_TOKEN'
```

The file is public to anyone who can request that URL. It is an opt-in, not a password. Remove it when you are done. If you cannot place the file, the tool will not scan the host. That is the whole authorization model.

## Scan

```bash
npx tsx src/cli.ts scan \
  --url https://app.example \
  --token "$NB_TOKEN" \
  --supabase-url "$NB_SUPABASE_URL" \
  --anon-key "$NB_ANON_KEY" \
  --service-role "$NB_SERVICE_ROLE" \
  --tables profiles,notes \
  --closed-signup \
  --signup-path /api/signup \
  --webhook-path /api/webhooks/stripe \
  --llm-path /api/chat
```

`--url` is the app origin, with no path. `--supabase-url` may be the same origin in local tests, or `https://<project>.supabase.co`. A trailing `/rest/v1` is stripped.

What the Supabase checks actually do: create two users, insert a marked row for each in the tables you named (or, if you omit `--tables`, tables whose schema has `user_id`, `owner_id`, `created_by`, or `author_id`), then request that row as the anon key, as the other user, and with a patched `role` / `is_admin` / `plan` / `credits` column. It does not dump the table. When the run ends it deletes the rows. It deletes the users too if you passed `--service-role`.

That service role key is sent only to `/auth/v1/admin/*`. The client refuses to put it on the Data API. Passing it as `--anon-key` is a usage error: the checks would be meaningless. If public signup is disabled and you have neither a service role nor two user JWTs, the table checks error instead of reporting a pass.

If you already have two sessions:

```bash
npx tsx src/cli.ts scan --url https://app.example --token "$NB_TOKEN" \
  --supabase-url "$NB_SUPABASE_URL" --anon-key "$NB_ANON_KEY" \
  --user-a "$USER_A_JWT" --user-b "$USER_B_JWT" --tables profiles
```

`--json` prints a single JSON document on stdout (`schemaVersion` 1). Human output is the default. Every failure includes a `curl` that reproduces the request, and a short fix note.

Run this against staging. The probe inserts rows, updates a field on a row it created, posts one unsigned webhook event whose id is `evt_nb_probe_canary`, and posts `{"messages":[{"content":"nb-probe ping"}]}` to the chat route. A broken webhook handler might still act on that event.

A pass means this probe did not observe that failure. It does not mean the app is safe.

## Checks

| Id | What it looks for | Fail severity |
| --- | --- | --- |
| `logged-out-read` | Anon key can read a row a user just inserted | high |
| `idor-read` | User A can read User B's probe row | high |
| `idor-write` | User A can update or delete User B's probe row | critical |
| `self-promotion` | User A can set their own `role`, `is_admin`, `plan`, or `credits` | critical for role or admin flags, high for plan or credits |
| `closed-signup` | Public signup creates a user when you pass `--closed-signup` | medium |
| `bundle-secrets` | `service_role` JWT, `sb_secret_...`, Stripe `sk_`/`rk_` secret, or a source map in same-origin scripts | critical, high, or low |
| `webhook-signature` | POST with no signature is accepted | high on HTTP 2xx, medium on 5xx |
| `llm-endpoint` | Chat route answers with no session, or honors client `model` / `max_tokens` | high if anonymous use works, medium if only the override works |

Severity is a local label for the exit code. It is not a CVSS score and it is not a CVE.

`--only logged-out-read,idor-read` runs a subset. Unknown ids are a usage error.

Webhook defaults, if you do not pass `--webhook-path`: `/api/webhooks/stripe`, `/api/stripe/webhook`, `/api/webhook`. LLM defaults: `/api/chat`, `/api/llm`, `/api/ai`. A 404 on all of them is a skip, not a failure. The bundle check reads the entry HTML and same-origin `<script src>` files only. It does not fetch a CDN.

`--closed-signup` is off unless you set it. The check calls GoTrue `/auth/v1/signup` and, if you passed `--signup-path`, that path, with no invite field. It does not try to bypass captchas or confirmation mail.

The bundle check redacts secrets in the report (a short prefix and suffix). The curl greps the file instead of echoing the key. Anon keys are ignored. They are public.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No failed check at medium or above. A lone low failure (a public source map) still exits 0. |
| 1 | A medium, high, or critical failure, or a check that errored. |
| 2 | Ownership refused, or the command line was wrong. |
| 3 | Something else threw. |

## Output

Human, trimmed:

```text
nb-probe 0.1.0
target: http://127.0.0.1:40123
ownership: verified
supabase: http://127.0.0.1:40123

FAIL   high      logged-out-read
       The anon key read probe rows in notes, profiles.
       fix: Turn on RLS for the table. Add a select policy for authenticated with auth.uid() = user_id (or your owner column). Do not add a select policy for anon.

curl -sS 'http://127.0.0.1:40123/rest/v1/notes?id=eq.ROW&select=*' -H 'apikey: ANON' -H 'authorization: Bearer ANON' -H 'accept: application/json'

0 passed, 1 failed, 0 skipped, 0 errors
```

The curl is on its own line so you can copy it. Failing curls for the cross-user checks contain the probe user's access token. They do not contain the service role key.

JSON has `results[].status`, `severity`, `summary`, `fix`, `repro`, and `evidence`. `notes` lists leftovers: a row the delete did not remove, probe users left behind because no service role was passed, tables the schema did not contain.

## Try it locally

`npm test` starts a vulnerable fixture and a hardened one on random loopback ports. You do not need a Supabase project.

To poke at the vulnerable app yourself:

```bash
npm run fixture
```

That listens on `127.0.0.1:40123` and prints a scan command. Expect failures. `npm run fixture -- hardened` is the same app with RLS, signup disabled, a clean bundle, a webhook that wants a signature, and a chat route that wants a bearer token. Expect passes if you pass `--service-role` (the fixture prints one). Ctrl-C stops it. The fixture is not a real Supabase. It speaks enough of Auth and PostgREST for these checks.

If a real project confirms email before it issues a session, public signup cannot provision probe users. Pass `--service-role`, or mint two sessions yourself and pass `--user-a` and `--user-b`. The service role is optional and is not required to run the checks once those sessions exist.

## What this does not do

- Scan a host that has not published the ownership file.
- Guess passwords, brute force logins, or turn one bug into a second one.
- Test tables it did not insert a probe row into. A public table with no owner column is left alone unless you name it in `--tables`.
- Crawl third-party script hosts. A key that only exists in a CDN bundle will be missed.
- Send the service role key as the data-plane credential.
- Claim a CVE, score a product, or write you a pentest report.
- Persist results anywhere but your stdout.
- Phone home.

If a table is meant to be world-readable and it has a `user_id` column, auto mode will flag an anon read. Pass `--tables` and list only the private ones.

## Layout

```text
src/cli.ts            flags, exit codes
src/scan.ts           ownership gate, then the checks
src/harness.ts        two users, probe rows, cleanup
src/checks/           one file per check
test/fixture.ts       the vulnerable and hardened apps
```

## License

MIT. See [LICENSE](LICENSE).
