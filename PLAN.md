# PLAN — caffeinated-clients

Implementation plan for a single-user, installable, self-hosted CRM for
existing IT clients. Phase checkboxes track what has landed. Phases are
ordered so each ends somewhere runnable.

## Why this shape

### Hypermedia, not an SPA

| | Go + HTMX + Tailwind (chosen) | React/Vue SPA + JSON API | Astro/Next SSR |
|---|---|---|---|
| JS shipped | ~14 kB HTMX + a little glue | Hundreds of kB, build toolchain | Varies, often a runtime |
| Mobile feel | Server-rendered, instant on cheap phones | Needs hydration budget | Depends on island strategy |
| Memory / ops | One binary, no Node in the runtime image | Node build + asset pipeline | Node build |
| Fit for a solo maintainer | One language (Go) end to end | Two stacks and an API contract | Two stacks |
| "Modern" look | Tailwind + dark mode | Yes | Yes |

The operator wants lightweight memory and a phone-installable app, not
an app platform. Server-rendered fragments with HTMX give app-like
navigation (via `hx-boost`) without a client framework.

### Whole-database encryption, not field-level

The requirement is that **all** client details are encrypted at rest
*and* that names stay indexed and searchable. Those two pull against
each other for field-level crypto, so the encryption is pushed down to
the database page layer.

| | Whole-DB encryption, SQLCipher (chosen) | Field-level AES-GCM + pure-Go driver | Blind/prefix indexes over encrypted fields |
|---|---|---|---|
| Coverage | Every page: data, indexes, sessions, audit | Each app-level field | Each indexed field |
| Search / indexes | Normal SQLite `LIKE`/FTS5, works as-is | No DB index on ciphertext; decrypt into memory | Custom index; works but leaks |
| Leakage | Nothing useful without the key | Nothing useful without the key | Equality/prefix patterns leak from the index |
| Complexity | One key, one driver, zero crypto in app code | Crypto at every read/write; app-side search | Most complex, bespoke crypto |
| Cost | CGO build (static musl) | Stays pure Go | Stays pure Go, but risky crypto |
| Driver | SQLCipher-backed `database/sql` driver | `modernc.org/sqlite` | `modernc.org/sqlite` |

`modernc.org/sqlite` has **no encryption codec** (no `SQLITE_HAS_CODEC`
and no encryption API), so field-level or whole-file encryption with it
means writing crypto in the app. For a credentials app, reusing
SQLCipher's audited AES-256 + HMAC page format is strictly safer and
simpler than bespoke crypto or blind indexes. The CGO cost is accepted
and contained in the Docker build.

### Search

Because the database is encrypted as a whole, ordinary SQLite indexes
and `LIKE` queries work; there is no application-side decryption loop
and no separate search index. Indexed and searchable: client
name/business, contact name, contact phone (normalized digits), contact
email, project name, and note title. Secret notes are excluded from
search entirely; note bodies are not searched in v1. FTS5 is a safe,
straightforward future upgrade (the index pages are encrypted too) but
is deferred — `LIKE` plus indexes is enough for a personal CRM.

### SQLite, not Postgres

| | SQLite (chosen) | PostgreSQL |
|---|---|---|
| Containers | One | Two |
| Backup | Copy one file | `pg_dump` + volume |
| Coolify footprint | Minimal | Extra service + volume |
| Single-user read/write needs | More than enough | Overkill |

Single user, one writer, low concurrency. SQLite with WAL is the
correct lazy choice; Postgres would add operational surface for no
benefit at this scale.

### Sessions and 2FA in-process

No auth SaaS or identity provider: it is one user. Server-side sessions
in SQLite mean logout and expiry are real, not just a cookie deletion.
Argon2id for the password, stdlib HMAC-based TOTP (no dependency),
hashed one-time recovery codes. This keeps the security-critical path
small and auditable.

### PWA: installable shell, no data cache

The user installs to Android and needs it to *open* offline. Caching
authenticated HTML would leave client data on the device and risk stale
or cross-session leakage. So the service worker caches only the app
shell, versioned static assets, and an offline page; data always needs
the network. This is the right security/usability trade for an
encrypted CRM.

## Stack decisions (locked)

- Go stdlib `net/http` with 1.22+ method+pattern routing. No router
  dependency.
- `html/template` with `//go:embed` for templates and static assets.
  **`templ` is deliberately not used in v1** — revisit only if
  component reuse becomes painful (risk below).
- HTMX vendored (`web/static/htmx.min.js`), served locally, no CDN.
- Tailwind CSS standalone CLI, built in the Docker build stage.
- SQLite under SQLCipher, driven by a SQLCipher-backed `database/sql`
  driver (CGO). **Driver chosen at Phase 1:** `github.com/sjzar/go-sqlcipher`
  v0.0.5 (package `sqlite3`, driver name `sqlcipher`; released 2026-09-21,
  tracks `mattn/go-sqlite3` v1.14.52 and bundles SQLCipher 4.12.0 / SQLite
  3.51.1 with libtomcrypt AES, so the binary links fully static against musl
  with no OpenSSL). The original candidate `github.com/mutecomm/go-sqlcipher/v4`
  was last released 2020-12-07 and is effectively unmaintained. Rejected: the
  newer pure-Go "encryption at rest" drivers until they have real-world
  security review — do not adopt unvetted crypto for this app.
- Migrations embedded and applied at startup.
- `golang.org/x/crypto/argon2` for password hashing. TOTP implemented
  with stdlib `crypto/hmac` + `encoding/base32` + `crypto/rand`.
- No JS framework; icons are inline SVG.
- Go module path `github.com/CaffeinatedTech/caffeinated-clients`.
- Image `ghcr.io/caffeinatedtech/caffeinated-clients`.

## Database key design

- `CCLIENTS_DB_KEY` is a base64-encoded 32-byte value. The app converts
  it to SQLCipher's raw key form and opens with
  `PRAGMA key = "x'<64 hex>'"` (raw key, no KDF passphrase ambiguity).
- Key is validated at startup: correct length, correct decode, and a
  successful `SELECT` against `sqlite_master`. A wrong key must fail
  closed (never create/overwrite an empty database).
- `PRAGMA cipher_memory_security = ON`. `PRAGMA cipher_page_size` is pinned
  to **4096** at creation (SQLCipher 4's default) and documented here;
  changing page size later requires a re-encryption migration, so it is set
  once in the connection DSN.
- WAL mode + `foreign_keys=ON` on every connection.
- Rotation is deferred: a future `rekey` command runs `PRAGMA rekey`
  with the new key. The README warns that losing the key is permanent
  data loss.

## Target data model

```
clients    (id, name, status, website, address, phone, phone_digits,
            summary, tags, created_at, updated_at, archived_at)
contacts   (id, client_id, name, role, phone, phone_digits, email,
            notes, is_primary, created_at, updated_at)
notes      (id, client_id, title, body, pinned, is_secret,
            created_at, updated_at)
projects   (id, client_id, name, description, status, due_date,
            started_at, completed_at, created_at, updated_at)
jobs       (id, client_id, project_id, title, description, status,
            priority, due_date, completed_at, created_at, updated_at)
users      (id, username, password_hash, totp_secret, totp_enabled,
            totp_enrolled_at, created_at, updated_at)
recovery_codes (id, user_id, code_hash, used_at, created_at)
sessions   (id, token_hash, user_id, created_at, last_seen_at,
            expires_at, user_agent, ip)
audit_log  (id, at, event, entity, entity_id, client_id, ip, detail)
```

Notes:

- There is **no `secrets` table**. Secret notes are `notes` rows with
  `is_secret = 1`. The TOTP secret is the one non-note secret and lives
  on `users`, still protected by whole-database encryption.
- `phone_digits` is a normalized digits-only copy for search.
- ALL of the above is encrypted at rest by SQLCipher; the model makes
  no distinction for encryption purposes.
- `audit_log` is append-only; `detail` is JSON but must never contain
  the body of a secret note, passwords, tokens, or recovery codes.
- Indexes: `clients(name)`, `clients(phone_digits)`,
  `contacts(phone_digits)`, `contacts(client_id)`,
  `contacts(client_id) WHERE is_primary = 1` (unique), `notes(client_id)`,
  `notes(title)`, `projects(client_id, status)`, `projects(name)`,
  `jobs(client_id, status, due_date)`, `jobs(project_id)`,
  `sessions(token_hash)`, `audit_log(at)`, `audit_log(client_id)`.
  Secret-note rows are excluded from search at query time
  (`AND is_secret = 0`), not by index structure.
- FTS5 tables are intentionally omitted from v1.

## Request/UX map

```
GET  /                     dashboard (search + ongoing + jobs + recent)
GET  /search?q=            HTMX results partial (also full-page fallback)
GET  /login                login form
POST /login                password step -> TOTP step
GET  /login/totp           TOTP / recovery-code form
POST /login/totp           complete login
POST /logout               destroy session
GET  /setup                TOTP enrollment + recovery codes (first login)
POST /setup                confirm enrollment
GET  /clients              list/filter/sort
GET  /clients/new          quick add
POST /clients              create (name required)
GET  /clients/{id}         client page (tabs)
POST /clients/{id}         update
POST /clients/{id}/archive archive/restore
POST /clients/{id}/delete  cascade delete (confirm)
  contacts/notes/projects/jobs are nested under /clients/{id}
POST /notes/{id}/reveal    reveal a secret note (audited, no-store)
GET  /projects  /projects/{id}
GET  /jobs      /jobs/{id}
GET  /settings             password, 2FA, export, audit
GET  /healthz              health
GET  /manifest.webmanifest, /sw.js, /offline, /static/*
```

HTMX conventions:

- Navigation uses `hx-boost="true"` on the shell for SPA-like swaps.
- Search input uses `hx-get="/search"`, `hx-trigger="input changed
  delay:250ms"`, `hx-target="#search-results"`.
- Create/edit forms use `hx-post`/`hx-put` with `hx-target` set to the
  component being replaced; errors return the form partial with inline
  messages.
- Secret reveal uses `hx-post="/notes/{id}/reveal"` targeting the note
  body element; the returned fragment includes the body plus a small
  script that re-masks after 15 seconds.
- Every HTMX form still has a normal `action`/`method` so it works
  without JS (Q5).

## Security design

- **Database:** SQLCipher whole-file encryption, raw key from
  `CCLIENTS_DB_KEY`, fail-closed on wrong/missing key. Encryption of
  indexes means search does not weaken at-rest secrecy.
- **Startup guards:** validate the DB key; warn loudly when
  `CCLIENTS_DISABLE_2FA=true`.
- **Password:** Argon2id; parameters from env with conservative
  defaults.
- **TOTP:** RFC 6238, SHA-1, 6 digits, 30 s, ±1 step; secret stored in
  the encrypted `users` row.
- **Recovery codes:** 10 codes, `crypto/rand`, shown once, stored as
  Argon2id hashes, single-use.
- **Sessions:** 32-byte random token; store SHA-256 of it; cookie
  `HttpOnly; Secure; SameSite=Lax; Path=/`.
- **CSRF:** per-session token embedded in forms and as an HTMX header;
  verified on all non-GET requests.
- **Rate limiting:** in-memory token buckets per IP and per username
  (single instance, so no shared store needed).
- **Secret reveal:** tap-to-reveal, immediate, `no-store`, audited,
  auto-masks after 15 s client-side; never rendered in lists/search.
- **Headers:** strict CSP (`default-src 'self'`; no inline script — the
  theme bootstrap is an external file), `nosniff`, `Referrer-Policy:
  same-origin`, `frame-ancestors 'none'`.
- **Proxy trust:** forwarded headers honored only when
  `CCLIENTS_TRUST_PROXY=true`.
- **Logging:** a small redaction rule; never log form bodies from note
  or login routes.
- **Audit:** append-only entries per F13.

## Deployment design

- **Dockerfile:** multi-stage.
  - Stage 1: `golang:1.24-alpine` — Alpine gives musl for a static
    CGO link. Download modules, build the Tailwind CSS with the
    standalone CLI, then `CGO_ENABLED=1 go build` with
    `-ldflags '-linkmode external -extldflags "-static"'` so the
    SQLCipher binary is fully static (SQLCipher bundles its own crypto,
    so no OpenSSL).
  - Stage 2: `gcr.io/distroless/static-debian12:non-root` — copy the
    static binary and embedded assets only. No shell.
- **Runtime:** listens on `:8080`, reads/writes `/data`, exposes
  `/healthz`.
- **GHCR publishing:** GitHub Actions builds multi-arch
  (`linux/amd64`, `linux/arm64`) on `v*` tags and pushes `vX.Y.Z`,
  `latest`, and `sha-<short>`. (Deliberate change from the sibling
  repos' manual dated-tag builds — this project is public and PWA users
  expect a pullable `latest`.) Multi-arch CGO means buildx + QEMU for
  arm64.
- **Coolify:** deploy from the GHCR image or the repo Dockerfile; set
  the domain + TLS, mount a volume at `/data`, set env vars, health
  check `/healthz`. Documented step by step in `docs/DEPLOY.md`
  (written in Phase 7).
- **Backup:** `VACUUM INTO '/data/backup-YYYYMMDD.db'` (output is
  encrypted like the source) or WAL checkpoint + copy; restore is
  stopping the container and replacing the file. Documented, not
  automated, in v1.
- **Key handling:** generate with `head -c 32 /dev/urandom | base64`,
  store in Coolify's secret env, keep an offline copy. Losing it is
  unrecoverable.

## Phases

### Phase 0 — Scaffold and docs (done)

- [x] Create the four docs: README, REQUIREMENTS, PLAN, AGENTS.
- [x] Add LICENSE (MIT), `.gitignore`, `env.example`.
- [x] Initialise the git repository and make the first commit.
- **State:** docs and repo scaffold only; no buildable code.

### Phase 1 — Skeleton, config, encrypted database, health

- [x] `go mod init github.com/CaffeinatedTech/caffeinated-clients`,
      plus `docker-compose.yml` and `Dockerfile` — deferred from Phase 0
      because they cannot be verified until a buildable binary exists.
- [x] `main.go` with flags (`--bootstrap-admin`, `--healthcheck`) and
      env config loader with validation.
- [x] Select and pin the SQLCipher driver after a maintenance check;
      open the DB with the raw key, `PRAGMA key`, `cipher_memory_security`,
      WAL, and `foreign_keys=ON`. Verify a fully static musl build
      early (the risk is the build, not the app).
- [x] Embedded migrations runner with `PRAGMA user_version`; full
      schema from the data model above.
- [x] `GET /healthz` doing a decrypting DB ping.
- [x] Structured logging (`log/slog`) with redaction helper.
- [x] `go build/vet/gofmt/test` clean.
- **Decisions landed:** driver pinned to `github.com/sjzar/go-sqlcipher
  v0.0.5` (see Stack decisions); `cipher_page_size = 4096`;
  connections are `MaxOpenConns(1)`; encryption tests prove the file has
  no plaintext marker and a wrong key fails closed without touching the
  file.
- **Note:** `--bootstrap-admin` initialises and migrates the database;
  the single-user account itself is created in Phase 2. The static musl
  link is produced by the Docker build stage — verify with
  `docker build .` where a Docker daemon is available.

### Phase 2 — Auth, sessions, CSRF, bootstrap

- [x] Single-user bootstrap (env or `--bootstrap-admin`).
- [x] Argon2id password hashing + login password step.
- [x] TOTP enrollment (`/setup`) + verification, recovery codes.
- [x] Server-side sessions, secure cookie, idle + absolute expiry.
- [x] CSRF tokens for all non-GET requests.
- [x] Login rate limiting and audit entries.
- [x] `CCLIENTS_DISABLE_2FA` break-glass path (loud warning).
- [x] Tests: password verify, TOTP window, session expiry, CSRF reject,
      recovery-code single use, wrong DB key fails closed.
- **Decisions landed:** auth lives in `internal/auth` (pure crypto +
  DB access) and HTTP in the `web` package with `//go:embed` templates
  under `web/templates/`; no new web dependency. Sessions are stored
  server-side with a hashed token; the raw token never touches the DB.
  Migration `0002_auth.sql` adds `sessions.stage`
  (`pending`/`full`) and `sessions.csrf_token`: a session is `pending`
  between the password step and a completed second factor, and only
  `full` sessions reach app routes. The session token is rotated on
  every stage transition (no fixation). The login form uses a
  double-submit CSRF cookie; authenticated POSTs use the per-session
  token. Argon2id parameters are env-tunable
  (`CCLIENTS_ARGON2_MEMORY`/`_TIME`/`_THREADS`) and recorded inside each
  PHC hash. Recovery codes keep the planned Argon2id hashing.
  `--bootstrap-admin` and first-run auto-bootstrap both create the
  single user from the bootstrap env vars.
- **Deferred:** a QR image for TOTP enrollment (the `<secret>` and
  `otpauth://` URI are shown; a QR needs a decoder/generator dependency
  or a client-side library — revisit in Phase 3 if wanted).

### Phase 3 — App shell, theming, PWA

- [x] `html/template` layout + partials, `//go:embed` templates and
      static assets.
- [x] Tailwind standalone build wired into the Makefile/Dockerfile;
      dark/light theme with persisted override and no FOUC.
- [x] Mobile nav (bottom bar), responsive layouts, accessible
      components.
- [x] `manifest.webmanifest`, icons, service worker (static assets +
      offline page), registration script.
- [x] CSP/security headers middleware.
- [x] Tests: template render smoke tests, header presence.
- **Decisions landed:** pages live under `web/templates/pages/`, shared
  chrome in `web/templates/partials/`, and `parseTemplates` clones the
  layout per page so every page can define the one `content` block
  without collision. `web/static/app.css` is committed so a plain
  `go build`/`go test` works offline with no Tailwind CLI; `make css`
  regenerates it and the Docker build compiles it anyway. Dark mode is
  class-driven (`@custom-variant dark`) with `theme.js` seeding from
  `prefers-color-scheme` before first paint and `app.js` persisting the
  manual override in `localStorage`; the toggle click is delegated so it
  survives `hx-boost` body swaps. HTMX's injected inline `<style>` is
  disabled via `<meta name="htmx-config">` (indicator CSS ships in
  `app.css`) so the CSP keeps `script-src`/`style-src 'self'` with no
  `unsafe-inline`. Static assets are versioned by `web.BuildVersion`
  (`-X` ldflag; defaults `dev`), which also names the service-worker
  cache; `dev` builds skip service-worker registration and use
  `no-cache` so local edits are never pinned. The service worker caches
  only `/static/*`, the manifest, and `/offline`, and navigations are
  network-only with the offline page as fallback — no HTML or client
  data is ever cached (F9.2).

### Phase 4 — Clients, contacts, search, dashboard

- [x] Client CRUD, archive/restore, cascade delete with confirmation.
- [x] Contacts CRUD with single-primary rule.
- [x] Client page with tabs and overview.
- [x] Search across clients, contacts, projects, and non-secret note
      titles as an HTMX partial with full-page fallback; phone
      normalization.
- [x] Dashboard: search, recently updated clients.
- [x] Tests: phone normalization, grouping, secret notes excluded from
      search, primary-contact invariant, cascade delete.
- **Decisions landed:** domain data lives in `internal/crm` (one concrete
  `Store` over the same encrypted `*sql.DB`), keeping SQL out of the HTTP
  layer and out of `auth`. The single-primary-contact rule is enforced in
  the store with a transaction that clears the previous primary before
  setting the new one (the partial unique index is the backstop), not
  only in the UI. Cascade delete relies on the existing
  `ON DELETE CASCADE` foreign keys with `foreign_keys=ON`; the delete
  confirmation renders the client name and per-kind row counts
  (F12.5). Search is parameterized `LIKE` over indexed columns plus a
  normalized `phone_digits` match that accepts `555-0100`,
  `(555) 0100`, and `+15550100` in either direction; non-secret notes
  only (`is_secret = 0`), and note bodies are never searched. Mutations
  return the replaced contacts partial for HTMX and a redirect /
  full-page render otherwise, so Q5 holds. The dashboard surfaces search
  and recently-updated clients; ongoing-projects and upcoming-jobs
  widgets stay with Phase 6.
- **Decisions landed (templ):** the `html/template` ergonomics risk is
  resolved for v1 — stay on stdlib templates with small composable
  partials (`client_fields`, `contacts_panel`, `search_results`) and a
  flat per-page view model. No `templ`.

### Phase 5 — Notes, secret notes, audit

- [ ] Notes CRUD, pinned ordering, safe Markdown rendering.
- [ ] Secret flag: masking in all lists/renders, tap-to-reveal
      endpoint with `no-store`, 15-second auto-mask, clipboard copy.
- [ ] Audit log writes on all F13 events; per-client Activity tab and
      global audit view.
- [ ] Tests: reveal audit entry recorded, secret note absent from
      search and from ordinary renders, reveal response carries
      `no-store`, `is_secret` toggle preserved across edits.

### Phase 6 — Projects and jobs

- [ ] Projects CRUD + status lifecycle; progress from jobs.
- [ ] Jobs CRUD, link to project (same-client constraint enforced),
      completion timestamps.
- [ ] Dashboard widgets: ongoing projects, upcoming/overdue jobs.
- [ ] Global projects and jobs views with filters.
- [ ] Tests: same-client project/job constraint, ongoing status set,
      overdue query.

### Phase 7 — Settings, export, deploy polish

- [ ] Settings: change password (re-auth), re-enroll 2FA, view/regenerate
      recovery codes, theme, JSON export (secret notes opt-in only).
- [ ] `docs/DEPLOY.md`: Coolify walkthrough, key generation and storage,
      backup and restore, break-glass recovery, `PRAGMA rekey` note.
- [ ] Dockerfile + multi-arch GitHub Actions publish to GHCR.
- [ ] `docker-compose.yml` + `.env.example` + `env.example`.
- [ ] README final pass against the real commands.
- [ ] Cut `v0.1.0`.

### Later / explicitly out of scope for v1

- Database key rotation command (`PRAGMA rekey`) plus re-encryption
  runbook.
- SQLite FTS5 full-text search over clients and non-secret notes.
- Asset/device inventory per client.
- Attachments/file uploads.
- Time tracking and invoicing.
- Notifications (email/push) for upcoming jobs.
- Import from other CRMs.
- Multi-user and sharing.
- Full offline read/write with conflict resolution.

## Risks and open questions

- **CGO + static musl build for SQLCipher.** The main new build risk.
  Prove it in Phase 1 with a hello-world open, then wire the Docker
  build. buildx + QEMU for `linux/arm64`.
- **SQLCipher driver maintenance.** `mutecomm/go-sqlcipher` and its
  forks vary in liveness. Pick one, pin it, and record the choice and
  its last-release date in Phase 1. If none look maintained, the
  fallback is a maintained fork of `mattn/go-sqlite3` with SQLCipher
  bundled.
- **Whole-DB key management.** A lost `CCLIENTS_DB_KEY` is total,
  unrecoverable data loss. Document bluntly; no key-escrow in v1.
- **Wrong-key behavior.** Must fail closed. A test must assert that
  opening an existing encrypted file with a wrong key does not create
  an empty database or wipe data.
- **`html/template` ergonomics.** Many partials and per-component data
  structs can get verbose without `templ`. **Resolved at Phase 4:** the
  client/contact/search screens landed on stdlib templates with a few
  named partials and a flat view model; it did not become painful.
  Revisit only if it genuinely does.
- **Encryption + WAL + backups.** `VACUUM INTO` produces an encrypted
  copy; WAL checkpoint + copy also works because encryption is
  transparent. Document both and warn against copying a live WAL file.
- **Search with SQLCipher.** Page encryption is transparent to queries,
  so no special handling; confirm index usage with `EXPLAIN QUERY PLAN`
  for phone/name search on a seeded database.
- **Service worker staleness.** Version static asset cache keys by the
  build hash and skip-waiting on new deploy; never cache HTML.
- **Coolify reverse-proxy headers.** Correct client IPs for rate
  limiting depend on `CCLIENTS_TRUST_PROXY`; documented and off by
  default.
- **Single instance assumption.** Rate limiting and sessions assume one
  process (SQLite is single-writer anyway). Scaling out is out of
  scope; note it explicitly.
