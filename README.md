# nb-probe

User A calls `GET /rest/v1/orders?id=eq.<user B's id>` with a valid session. The token is real, the route exists, the status is 200. A scanner that does not know who owns the row has nothing to flag.

nb-probe creates two users in an app you run, inserts one row for each, and makes that request. It also checks logged-out reads, self-promotion of `role` / `is_admin` / `plan` / `credits`, a signup that should be closed, secrets in the client bundle, an unsigned webhook, and an LLM route that answers with no session.

It is MIT licensed. It does not phone home. Supabase is the first target. A pass means this probe did not observe the failure. It does not mean the app is safe.

## Quickstart

Node 18 or newer.

```bash
npx nb-probe token
```

Put that line, alone, at `https://YOUR_ORIGIN/.well-known/neural-breach` (for an app under a path, see [Apps under a path](#apps-under-a-path)). Then:

```bash
npx nb-probe scan \
  --url https://app.example \
  --token "$NB_TOKEN" \
  --supabase-url "$NB_SUPABASE_URL" \
  --anon-key "$NB_ANON_KEY"
```

From a checkout, after `npm install` and `npm run build`:

```bash
node dist/cli.js scan --url https://app.example --token "$NB_TOKEN" \
  --supabase-url "$NB_SUPABASE_URL" --anon-key "$NB_ANON_KEY"
```

Without a build:

```bash
npx tsx src/cli.ts scan --url https://app.example --token "$NB_TOKEN" \
  --supabase-url "$NB_SUPABASE_URL" --anon-key "$NB_ANON_KEY"
```

`--help` lists the flags. The same names exist as `NB_URL`, `NB_TOKEN`, `NB_SUPABASE_URL`, `NB_ANON_KEY`, `NB_SERVICE_ROLE`, `NB_TABLES`, `NB_USER_A`, `NB_USER_B`, `NB_USER_A_EMAIL`, `NB_USER_A_PASSWORD`, `NB_USER_B_EMAIL`, `NB_USER_B_PASSWORD`, `NB_SIGNUP_PATH`, `NB_CLOSED_SIGNUP=1`, `NB_WEBHOOK_PATH`, `NB_LLM_PATH`, `NB_ONLY`, and `NB_TIMEOUT`. Keys on the command line are visible to other users on the machine.

## Hosted Supabase

Since April 8, 2026, hosted Supabase refuses the Data API schema (`GET /rest/v1/`) to anon and publishable keys. Depending on the project it answers HTTP 403 `Access to schema is forbidden` or HTTP 401 `Secret API key required`; nb-probe treats any non-200 the same way. Projects created after March 11, 2026 had it from the start. nb-probe 0.1.0 read the table list from that schema, so on hosted projects every data check errored, and `--tables` did not help.

From 0.2.0, when the schema is refused, nb-probe finds tables another way:

1. It reads the app's own HTML, same-origin scripts, lazy chunks, and same-origin source maps, and collects supabase-js calls: `.from("table")`, the columns in `.select(...)`, filter columns, `insert` / `update` / `upsert` keys, `.rpc("name")`, and storage buckets. `node_modules` sources in a source map are skipped.
2. It adds `--tables` and a short list of common table names.
3. It confirms each candidate with `GET /rest/v1/<table>?select=*&limit=0` as anon. `limit=0` returns no rows. A PostgREST "Perhaps you meant the table ..." hint adds the suggested table, and "column ... does not exist" errors confirm columns.

The report says where each table came from (`openapi`, `--tables`, `bundle`, `source-map`, `postgrest-hint`, or `guess`), which ones were probed, and why the others were not. RPCs are listed and never called. If nothing user-scoped is found, the data checks are skipped with `skipped: no tables discovered, pass --tables`.

`--tables` chooses what gets probed in both modes. Tables discovered outside it are listed and left alone.

Without the schema nb-probe does not know which columns are required or how they are typed. A failed insert writes nothing, so it reads the Postgres error (`null value in column`, `invalid input syntax for type`, unknown column) and retries, up to six times per row.

Keys: `--anon-key` takes a legacy anon JWT or an `sb_publishable_...` key. `--service-role` takes a legacy service role JWT or an `sb_secret_...` key. The new key formats are sent on the `apikey` header only. Only JWTs go in `Authorization`.

Test accounts: on most hosted projects you will not want to pass a secret key, and public signup may be off. Create two ordinary, confirmed users in the project and pass them:

```bash
NB_USER_A_EMAIL=a@yourapp.test NB_USER_A_PASSWORD=... \
NB_USER_B_EMAIL=b@yourapp.test NB_USER_B_PASSWORD=... \
npx nb-probe scan --url https://app.example --token "$NB_TOKEN" \
  --supabase-url https://<ref>.supabase.co --anon-key sb_publishable_...
```

nb-probe signs in with the password grant. It never creates, changes, or deletes these accounts. It inserts one probe row per account per table and deletes them at the end.

## Apps under a path

`--url` can point at an app served from a path instead of the origin root, such as a GitHub Pages project site:

```bash
npx nb-probe scan --url https://user.github.io/my-app/ --token "$NB_TOKEN" \
  --supabase-url https://<ref>.supabase.co --anon-key sb_publishable_...
```

- `https://user.github.io/my-app`, `https://user.github.io/my-app/` and `https://user.github.io/my-app/index.html` are the same target. A `#/route` fragment is dropped. A query string is refused.
- The entry page is fetched from that path. Scripts are resolved the way a browser does: relative to the page, or to `<base href>` if the page sets one. Absolute `/assets/...` paths, `./chunk.js` imports, Vite `assets/...` preload lists (relative to the app path), Next `static/chunks/...` (under `<app path>/_next/`), and source maps next to each script are followed.
- Only the entry page inside the path is fetched as a page. Scripts, chunks and maps it references are fetched from anywhere on the same origin. Nothing on another origin is fetched, and a redirect of the entry page out of the path stops the bundle read.
- `--webhook-path`, `--llm-path`, `--signup-path` and the default routes are relative to the app path: `--llm-path /api/chat` with `--url https://host/my-app/` posts to `https://host/my-app/api/chat`.

## Ownership token

The scan does not start until the ownership file returns the token you passed.

Where nb-probe looks:

| `--url` | Checked, in order |
| --- | --- |
| `https://app.example` | `https://app.example/.well-known/neural-breach` |
| `https://host/my-app/` | `https://host/my-app/.well-known/neural-breach`, then `https://host/.well-known/neural-breach` |

For an app under a path, put the file under that path. The origin root also works, because whoever controls the root of an origin controls every path on it. The first location that serves your token wins. If a location serves a different token, the scan stops there and does not try the next one. A 404, a redirect, or an HTML page at the first location moves on to the second.

- HTTP 200 from that exact path. No redirect.
- Body is the token as text, with an optional trailing newline, or JSON `{"token":"<the same value>"}`.
- The route is not behind a login. The probe fetches it with no credentials.
- The file is on the app origin (`--url`), not on the Supabase project URL.
- On GitHub Pages, `.well-known` is a dot folder, which Jekyll skips. Add an empty `.nojekyll` file at the root of the published branch, or deploy with GitHub Actions.
- The token is 8 to 200 characters: letters, digits, `.`, `_`, `~`, `-`. `nb-probe token` prints a UUID.

On Next.js or Vite, save it as `public/.well-known/neural-breach` with no extension. The file is public to anyone who can request that URL. It is an opt-in, not a password. Remove it when you are done. If you cannot place the file, the tool will not scan the host.

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

`--service-role` is optional. It is sent only to `/auth/v1/admin` to create and delete probe users. Passing it as `--anon-key` is a usage error. If you already have two sessions, pass `--user-a` and `--user-b` and skip the service role, or pass two test accounts with `--user-a-email` / `--user-a-password` / `--user-b-email` / `--user-b-password`. `--tables` limits the probe to named tables. Without it, tables whose schema has `user_id`, `owner_id`, `created_by`, `author_id`, `sender_id`, `creator_id`, or `uploaded_by` are selected, up to 20. `--only` runs a subset of the ids above.

Webhook defaults: `/api/webhooks/stripe`, `/api/stripe/webhook`, `/api/webhook`. LLM defaults: `/api/chat`, `/api/llm`, `/api/ai`. A 404, 405, or 501 on all of them is a skip: those mean no POST handler, which is what a static host returns. `--closed-signup` is off unless you set it.

The probe inserts rows, may patch a field on a row it created, posts one unsigned event id `evt_nb_probe_canary`, and posts `{"messages":[{"content":"nb-probe ping"}]}` to the chat route. Run it against staging. Cleanup deletes the probe rows before exit, and deletes the users when a service role was passed, so a curl copied from the report often returns `[]` afterward. `--no-cleanup` leaves them.

## Failing output

This is a run against the vulnerable fixture (`npm run fixture`), with keys and row ids shortened. Exit code 1.

```text
nb-probe 0.2.0
target: http://127.0.0.1:40177
ownership: verified
supabase: http://127.0.0.1:40177

FAIL   high      logged-out-read
       The anon key read probe rows in notes, profiles.
       fix: Turn on RLS for the table. Add a select policy for authenticated with auth.uid() = user_id (or your owner column). Do not add a select policy for anon.

curl -sS 'http://127.0.0.1:40177/rest/v1/notes?id=eq.<row>&select=*' -H 'apikey: <anon>' -H 'authorization: Bearer <anon>' -H 'accept: application/json'

FAIL   high      idor-read
       User A read User B's probe rows in notes, profiles.
       fix: Add a select policy so a user can read only their own rows: auth.uid() = user_id. Drop any policy whose expression is true.

curl -sS 'http://127.0.0.1:40177/rest/v1/notes?id=eq.<row>&select=*' -H 'apikey: <anon>' -H 'authorization: Bearer <user-a>' -H 'accept: application/json'

FAIL   critical  idor-write
       User A wrote User B's probe rows in notes, profiles.
       fix: Add update and delete policies with both USING and WITH CHECK set to auth.uid() = user_id. USING alone can still allow an owner change on some setups, so set WITH CHECK as well.

curl -sS -X PATCH 'http://127.0.0.1:40177/rest/v1/notes?id=eq.<row>' -H 'apikey: <anon>' -H 'authorization: Bearer <user-a>' -H 'content-type: application/json' --data-raw '{"body":"nb-probe-tamper-<id>"}'

FAIL   critical  self-promotion
       Probe user changed role, is_admin, plan, credits on their own row in profiles.
       fix: Revoke UPDATE on role, is_admin, plan, and credits from authenticated and anon. RLS that only checks auth.uid() = user_id still lets a user promote their own row. Use a column grant, a security definer function, or a before-update trigger that rejects changes to those columns.

curl -sS -X PATCH 'http://127.0.0.1:40177/rest/v1/profiles?id=eq.<row>' -H 'apikey: <anon>' -H 'authorization: Bearer <user-a>' -H 'content-type: application/json' --data-raw '{"role":"admin"}'

FAIL   medium    closed-signup
       Signup created a user without an invite (GoTrue HTTP 200, app signup HTTP 200).
       fix: Turn off public signups in the Supabase Auth settings, or reject them in a before-user-created hook. An invite check in the client, or only on your own signup route, leaves GoTrue open.

curl -sS -X POST 'http://127.0.0.1:40177/auth/v1/signup' -H 'apikey: <anon>' -H 'content-type: application/json' --data-raw '{"email":"nb-probe-closed-<id>@example.com","password":"nb-probe-signup-check"}'

FAIL   critical  bundle-secrets
       Client bundle exposes a service_role JWT, an sb_secret key, a Stripe secret key, and a source map reference.
       fix: Rotate the leaked key, then remove it from the client bundle. The anon key is public. A service role key, an sb_secret key, and a Stripe secret key are not. NEXT_PUBLIC_ and Vite env values are shipped to the browser.

curl -sS 'http://127.0.0.1:40177/assets/app.js' | node -e '<decode JWTs; print those whose payload role is service_role>'

FAIL   high      webhook-signature
       Unsigned POST to /api/webhooks/stripe was accepted (HTTP 200).
       fix: Verify Stripe-Signature against the raw body and the endpoint secret before parsing the event. Return 400 when the header is missing or invalid.

curl -sS -X POST 'http://127.0.0.1:40177/api/webhooks/stripe' -H 'content-type: application/json' --data-raw '{"id":"evt_nb_probe_canary",...}'

FAIL   high      llm-endpoint
       POST /api/chat answered without a session (HTTP 200). The response honored a client model or max_tokens override.
       fix: Require a session before the handler calls a model. Choose model and max_tokens on the server, and ignore those fields if the client sends them.

curl -sS -X POST 'http://127.0.0.1:40177/api/chat' -H 'content-type: application/json' --data-raw '{"messages":[{"role":"user","content":"nb-probe ping"}],"model":"nb-probe-override-model","max_tokens":999999}'

0 passed, 8 failed, 0 skipped, 0 errors
```

The report text does not contain the service role key. The bundle curl, when you run it, prints a matching token.

## Hardened fixture

`npm run fixture -- hardened` is the same local app with owner-only rows, signup disabled, a clean bundle, a webhook that wants `Stripe-Signature`, and a chat route that wants a bearer token. The same scan exits 0: the anon key cannot read the probe rows, user A cannot read or write user B, self-promotion is refused, public signup is refused, the bundle check passes, the unsigned webhook is rejected, and `/api/chat` returns 401.

`npm test` runs both fixtures. You do not need a Supabase project.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No failed check at medium or above. A lone low failure (a public source map) still exits 0. |
| 1 | A medium, high, or critical failure, or a check that errored. |
| 2 | Ownership refused, or the command line was wrong. |
| 3 | Something else threw. |

## JSON

`--json` prints one document on stdout (`schemaVersion` 1). Human output is the default and stays on stdout otherwise. Each result has `status`, `severity`, `summary`, `fix`, `repro`, and `evidence`. `discovery` says whether the schema was read or refused and lists each table with its `sources`, `status` (`probed`, `found`, `not-found`, `error`), and owner column, plus RPC names and storage buckets seen in the bundle. `notes` lists leftovers: a row the delete did not remove, probe users left behind because no service role was passed, tables the schema did not contain.

## Only scan apps you own

This is a defensive check for an origin you control. It will not scan a host that has not published the ownership file. It does not guess passwords, crawl third-party script hosts, or send the service role key to the Data API. It does not claim a CVE. Do not point it at someone else's application.

If a table is meant to be world-readable and it has a `user_id` column, auto mode will flag an anon read. Pass `--tables` and list only the private ones.

## License

MIT. See [LICENSE](LICENSE). Security reports for the tool itself: [SECURITY.md](SECURITY.md).

For a human review of an app you are shipping: https://neural-breach.com
