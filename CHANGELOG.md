# Changelog

## 0.2.0 - 2026-10-31

Hosted Supabase works again.

- Fixed: a 401 or 403 on `GET /rest/v1/` stopped every data check with "Schema request returned HTTP 403" (or 401). Hosted Supabase refuses that schema to anon and publishable keys since 2026-04-08. `--tables` did not help, because the names were looked up in the empty schema.
- Fixed: `sb_publishable_` and `sb_secret_` keys were also sent as `Authorization: Bearer`, which PostgREST and GoTrue reject (`PGRST301`). Non-JWT keys now go on `apikey` only.
- New: when the schema is refused, tables and columns are found from the app's scripts and source maps (supabase-js `.from`, `.select`, filters, insert/update keys) and confirmed with `select=*&limit=0` requests, PostgREST table and column hints, and a short list of common names. `--tables` works without the schema.
- New: the report shows where each table came from (`openapi`, `--tables`, `bundle`, `source-map`, `postgrest-hint`, `guess`), what was probed, RPC names (never called), and storage buckets. JSON has a `discovery` field.
- New: `--user-a-email`, `--user-a-password`, `--user-b-email`, `--user-b-password` (and `NB_USER_*` env vars) sign in two existing test accounts. They are never created or deleted.
- New: probe inserts retry with the column fixed after `23502` (NOT NULL), `22P02` (type), and `PGRST204` (unknown column) errors.
- Changed: when no user-scoped table is found, the data checks are skipped with `skipped: no tables discovered, pass --tables` instead of erroring, and no probe users are created.
- New: `sender_id`, `creator_id`, and `uploaded_by` count as owner columns, alongside `user_id`, `owner_id`, `created_by`, and `author_id`.
- Fixed: bare names like `Node.js` in library strings are no longer fetched as script chunks. Chunk refs need a path.
- Changed: the webhook and LLM checks treat 404, 405, and 501 as "no endpoint" and skip, instead of only 404. Static hosts answer POST with 405.
- Docs: the README says hosted Supabase answers the schema request with 401 or 403, depending on the project.
- Unchanged: the ownership gate, the probe-row-only writes, and cleanup.

## 0.1.0 - 2026-10-27

First public release.

- The scan does not start unless `GET /.well-known/neural-breach` returns the token you pass.
- Eight checks: logged-out read, cross-user read, cross-user write, column self-promotion, closed signup, secrets in the client bundle, unsigned webhook, LLM route auth and client `model` / `max_tokens` overrides.
- Human output by default, `--json` for a single document (`schemaVersion` 1). A failure includes a curl and a short fix.
- Exit 1 on a medium, high, or critical failure, or on a check error. A source-map finding alone exits 0. Exit 2 if the ownership token does not match.
- `--service-role` is optional and is sent only to `/auth/v1/admin` to create and delete probe users.
