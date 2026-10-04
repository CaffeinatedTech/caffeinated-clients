# AGENTS.md — guidance for coding agents working on caffeinated-clients

## Context (read this first)

This is a single-user, self-hosted CRM for an IT services operator whose
contacts are **all existing clients**. The product deliberately has no
acquisition flow: no pipelines, leads, deals, or funnels. Do not add
them, and do not "helpfully" introduce sales-shaped concepts.

The app stores **customer credentials and private details**. The
database file is assumed to be leakable; the encryption key in the
environment is not. The entire database is encrypted at rest
(SQLCipher), and confidentiality of everything in it is the product.
Security shortcuts are never acceptable here (see "Security rules"
below). Read [REQUIREMENTS.md](REQUIREMENTS.md) before changing behavior
— it is the spec, not decoration — and keep [PLAN.md](PLAN.md) phase
checkboxes current as work lands.

This repo currently contains **documentation only**. Phase 1 of PLAN.md
is the first code.

## Product guardrails

- Clients only, no prospects/pipeline. If a feature only makes sense for
  winning new business, it does not belong here.
- Mobile-first. The primary device is an Android phone with the app
  installed as a PWA. If it is awkward one-handed, it is wrong.
- Minimal-commit creation: adding a client must never require more than
  a name. Everything else is optional and editable later.
- Low resource use is a feature. Single binary, single encrypted SQLite
  file, one container. Do not introduce a second stateful service.
- No third-party runtime requests: no CDN, analytics, hosted fonts, or
  telemetry. All assets are self-hosted and embedded.
- Secrets are notes with a flag, not a separate object. Do not invent a
  `secrets` table or a separate credential abstraction.

## Stack and conventions

- **Go, stdlib-first.** `net/http` with 1.22+ method+pattern routing
  (`mux.HandleFunc("GET /clients/{id}", ...)`), `html/template`,
  `log/slog`, `crypto/*`, `embed`. No web framework, no router
  dependency, no DI container, no interface with one implementation.
- **Templating:** stdlib `html/template` with `//go:embed` for both
  templates and static assets. `templ` is intentionally **not** used in
  v1; do not introduce it without an explicit decision recorded in
  PLAN.md.
- **HTMX** is a vendored static file (`web/static/htmx.min.js`), served
  locally. No CDN. **Tailwind CSS** is compiled with the standalone CLI
  during the Docker build into one CSS file; no Node in the runtime and
  no Node requirement for local dev beyond the Tailwind binary.
- **Database:** SQLite under **SQLCipher** (AES-256 page encryption +
  per-page HMAC), opened with a raw 32-byte key from `CCLIENTS_DB_KEY`.
  This requires **CGO**; the binary is linked statically against musl.
  Driver selection is a Phase 1 task (see PLAN.md) — pin one and record
  why. `modernc.org/sqlite` cannot be used here: it has no encryption
  codec.
  - Open with `PRAGMA key = "x'<64 hex>'"`, `cipher_memory_security=ON`,
    WAL, `foreign_keys=ON`. Never open a database without the key; a
    wrong key must fail closed, never create an empty file.
  - Migrations are embedded SQL files applied idempotently at startup
    and tracked with `PRAGMA user_version`. Never edit an applied
    migration — add a new one.
- **Password hashing:** `golang.org/x/crypto/argon2`. **TOTP:** stdlib
  `crypto/hmac` + `encoding/base32` + `crypto/rand`. **Sessions/CSRF
  tokens:** `crypto/rand`.
- **Secrets at rest:** there is no per-field crypto. The whole database
  is encrypted by SQLCipher, so `notes.body` (secret or not) is covered
  automatically. Do not add a second encryption layer or a plaintext
  secret column.
- **Config:** environment variables only (see README table), prefix
  `CCLIENTS_`. No config file. `CCLIENTS_TRUST_PROXY` gates
  `X-Forwarded-*` handling.
- **Logging:** `log/slog`. Never log secret note bodies, passwords,
  session tokens, TOTP secrets, or recovery codes. Use the redaction
  helper.
- Go module path `github.com/CaffeinatedTech/caffeinated-clients`.
- **Ignore rules / delete over add:** if a dependency or abstraction can
  be deleted, delete it. See the Ponytail section.

## Commands

```
go build ./...                       # CGO required (SQLCipher)
go vet ./... && gofmt -l .           # must be clean
go test ./...                        # offline, no network, no live services
go run . --bootstrap-admin           # first-run: create the single user
go run .                             # serve on :8080
go run . --healthcheck               # decrypting DB ping, non-zero on failure
tailwindcss -i web/input.css -o web/static/app.css --minify   # build CSS
docker build -t ghcr.io/caffeinatedtech/caffeinated-clients:dev .
```

Tests are offline and use temporary SQLite files (`t.TempDir()`). Never
write tests that depend on a real phone, real DNS, or the network.
Encryption tests must prove: the database file bytes do not contain a
known plaintext marker; opening with the wrong key fails and does not
create/replace the file; and data survives a close/reopen with the
correct key.

## Domain model

Authoritative shape is in [PLAN.md](PLAN.md) "Target data model". Key
invariants:

- Exactly one `users` row.
- There is **no `secrets` table**. A secret is `notes.is_secret = 1`;
  the only non-note secret is the TOTP secret on `users`, still covered
  by whole-database encryption.
- A contact is primary for at most one client; setting a new primary
  clears the previous one.
- A `project` and each of its `jobs` share the same `client_id`; enforce
  this in the store layer, not just the UI.
- `notes.body` is text; any Markdown rendering is sanitized. No raw
  HTML passthrough.
- Secret notes are excluded from search (`AND is_secret = 0`) and from
  all ordinary renders; the body appears only in the reveal response.
- `audit_log` is append-only; `detail` is JSON and must never contain a
  secret note body, password, token, or recovery code.
- Deleting a client cascades to its contacts, notes, projects, and
  jobs, after a confirmation that names the client and the counts.

## Security rules (non-negotiable)

1. No secret note body, password, session token, TOTP secret, or
   recovery code in logs, errors, URLs, or ordinary rendered HTML. The
   only exception is the explicit reveal response for the current
   request, which is audited.
2. Reveal responses set `Cache-Control: no-store` and the value
   re-masks after 15 seconds on the client.
3. Never weaken the single-user + password + TOTP model. The only
   break-glass is `CCLIENTS_DISABLE_2FA=true`, which must log loudly and
   still require the password.
4. Every state-changing request goes through CSRF verification.
5. All state changes are authenticated; there are no unauthenticated
   write routes.
6. Security headers per REQUIREMENTS F11.7/S7. The theme bootstrap is
   an external script, not inline, so CSP needs no `unsafe-inline`.
7. Do not trust forwarded headers unless `CCLIENTS_TRUST_PROXY=true`.
8. Never open the database without `CCLIENTS_DB_KEY`; a wrong key fails
   closed. Never introduce an unencrypted mode or a fallback key.
9. Any new dependency needs a one-line justification ("stdlib can't do
   X"). Prefer stdlib and already-present packages.
10. Input validation happens at the boundary; SQL always uses
    parameters, never string-built queries.

## HTMX and template conventions

- The shell sets `hx-boost` for app-like navigation; full-page fallback
  must always work (Q5). Every HTMX form keeps a real `action`/`method`.
- Search: `hx-get="/search"`, `hx-trigger="input changed delay:250ms"`,
  `hx-target="#search-results"`.
- Mutations return the replaced component partial; validation errors
  return the same form partial with inline messages and preserved
  values.
- Secret reveal: `hx-post="/notes/{id}/reveal"` swaps in the body
  fragment and starts the 15-second auto-mask timer.
- Use `hx-indicator` for slow actions; never block the whole page on a
  single widget.
- Templates live under `web/templates/`; keep partials small and named
  by what they render.

## Migrations and data

- Add a new embedded migration; never modify one that has shipped.
- Keep `PRAGMA user_version` in lockstep with the migration count.
- Backups: document `VACUUM INTO` or WAL checkpoint + copy. Backups are
  encrypted because encryption is transparent; never tell a user to
  copy a live WAL database without checkpointing.
- The JSON export is plaintext, so it excludes secret notes by default;
  including them is a separate, clearly-labelled action with its own
  confirmation.

## Deployment

- One container, non-root, distroless static runtime, no shell.
- Built with CGO and statically linked against musl (SQLCipher bundles
  its own crypto). Confirm the static build in Phase 1.
- Listens on `CCLIENTS_LISTEN_ADDR` (default `:8080`), state in
  `/data`, health at `/healthz`.
- Published to `ghcr.io/caffeinatedtech/caffeinated-clients` for
  `linux/amd64` and `linux/arm64` on `v*` tags (`latest` + `vX.Y.Z` +
  sha).
- Runs on Coolify behind TLS. TLS/HSTS is the proxy's job; the app sets
  the rest of the security headers.
- Losing `CCLIENTS_DB_KEY` is permanent data loss; never log or echo
  the key, and never commit a real one.

## Open source

This repo is public and MIT-licensed. Treat everything as public:

- No real client names, businesses, phone numbers, emails, hostnames,
  IPs, tokens, credentials, or `CCLIENTS_DB_KEY` values in code,
  fixtures, docs, tests, or commit messages. Use synthetic data
  (`Acme Co`, `555-0100`, `clients.example.com`).
- Default/sample config ships with placeholders; real values come from
  the environment and are never committed.
- `.gitignore` before the first commit: the SQLite file, `*.db`,
  `*.db-wal`, `*.db-shm`, `.env`, backups.
- The DB key and all credentials live only in the deployment
  environment.

## Ponytail

Ponytail (lazy-senior-dev) is in effect for this project: the laziest
solution that actually works, stdlib before custom code, native platform
features before dependencies, one line before fifty. Load the
`ponytail` skill on coding tasks. Climb the ladder: does it need to
exist (YAGNI) → already in this repo → stdlib → native feature →
already-installed dependency → one line → minimum code.

Because this is a security-sensitive app, the ponytail "never simplify
away" list applies in full: input validation at trust boundaries, error
handling that prevents data loss, security measures, accessibility
basics, and anything explicitly requested are **not** candidates for
laziness. Whole-database encryption is itself the lazy-correct choice —
do not replace it with bespoke field crypto or blind indexes. Laziness
shortens the solution, never the reading — trace the whole flow first,
then climb. Mark deliberate corner-cuts with a `ponytail:` comment
naming the ceiling and the upgrade path.

Pair with Caveman for terse prose if desired; ponytail governs what is
built, not how you talk.

## Definition of done

- `go build ./...`, `go vet ./...`, `gofmt -l .` clean; `go test ./...`
  green offline.
- `--healthcheck` passes against a migrated, encrypted database.
- Any behavior change is reflected in REQUIREMENTS.md; phase status in
  PLAN.md is updated.
- No secret note body ever appears in logs, search results, exports
  (unless explicitly opted in), or non-reveal responses.
- No new dependency without a one-line justification.
- No unauthenticated write route, no CSRF-less mutation, no weakened
  session or 2FA behavior, no unencrypted database path.
- Mobile check: the changed screen is usable one-handed at 360 px.
- No real client data anywhere in the repo.
