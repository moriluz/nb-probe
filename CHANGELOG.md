# Changelog

## 0.1.0 - 2026-10-27

First public release.

- The scan does not start unless `GET /.well-known/neural-breach` returns the token you pass.
- Eight checks: logged-out read, cross-user read, cross-user write, column self-promotion, closed signup, secrets in the client bundle, unsigned webhook, LLM route auth and client `model` / `max_tokens` overrides.
- Human output by default, `--json` for a single document (`schemaVersion` 1). A failure includes a curl and a short fix.
- Exit 1 on a medium, high, or critical failure, or on a check error. A source-map finding alone exits 0. Exit 2 if the ownership token does not match.
- `--service-role` is optional and is sent only to `/auth/v1/admin` to create and delete probe users.
