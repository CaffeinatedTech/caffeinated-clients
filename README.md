# caffeinated-clients

A self-hosted, installable CRM for a solo IT services provider. Every
contact in here is **already a client** — so there is no pipeline, no
lead scoring, no sales stages, no "deal" objects. This is the system of
record for the people and businesses you support: their contact
details, notes, credentials, projects, and jobs.

Ships as a single Go binary in one small Docker image, storing
everything in one SQLite file that is **encrypted at rest** with a key
held in the environment. Runs on your Coolify server. Installs to your
Android phone as a PWA with light and dark themes.

## What it is / what it isn't

| It is | It isn't |
|---|---|
| A private system of record for existing clients | A sales pipeline or lead tracker |
| Encrypted client details, notes, and credentials | A password manager or helpdesk |
| A single-user, mobile-first, installable PWA | A multi-tenant SaaS |
| One container + one encrypted SQLite file | A service that needs Postgres/Redis/queues |
| Open source, GHCR-hosted image | A hosted product with an account |

## Features

- **Dashboard with instant search.** One search box finds clients by
  business name, contact name, phone, or email, and also finds projects
  by name and notes by title. Ongoing projects and upcoming jobs are on
  the dashboard.
- **Minimal-commit client creation.** Add a client with just a name and
  a phone number; enrich everything else later. Never block on a form.
- **Everything encrypted at rest.** The entire SQLite database (client
  names, businesses, phone numbers, emails, notes, projects, jobs,
  sessions, audit) is encrypted with SQLCipher using a key from the
  environment. A copied database file, and any backup of it, is inert
  without the key.
- **Secret notes with tap-to-reveal.** Any note can be flagged as a
  secret. Secret notes are masked everywhere — lists, search, and the
  client page — and shown only when you tap reveal. They re-mask after
  15 seconds, and every reveal is written to the audit log.
- **Projects and jobs.** Long-running work lives on the dashboard; jobs
  are the discrete bits of work that roll up to a project or stand
  alone.
- **Single-user password + TOTP 2FA.** Argon2id password hashing,
  authenticator-app second factor, one-time recovery codes,
  server-side sessions, CSRF protection, login rate limiting. Change the
  password, re-enroll the authenticator, regenerate recovery codes, and
  export a JSON copy from Settings — every security-sensitive change
  re-authenticates first.
- **Installable PWA.** Add to home screen on Android, standalone
  display, app shell and static assets cached for offline load; client
  data always requires the network.
- **Light and dark themes**, responsive from phone to desktop, no
  giant JS bundle and no CDN calls.

## Screens

| Route | Purpose |
|---|---|
| `/login`, `/login/totp` | Password + authenticator login |
| `/setup` | First-run TOTP enrollment + recovery codes |
| `/` | Dashboard: search, ongoing projects, upcoming jobs, recent clients |
| `/search?q=` | HTMX search results partial (clients, contacts, projects, note titles) |
| `/clients` | Client list (filter/sort/archive) |
| `/clients/new` | Quick add (name + phone), optional details |
| `/clients/{id}` | Client page with tabs |
| `/projects`, `/projects/{id}` | Projects across clients |
| `/jobs`, `/jobs/{id}` | Jobs across clients |
| `/settings` | Password, 2FA, recovery codes, theme, export |
| `/healthz` | Liveness/readiness for Coolify |

## Stack

| Concern | Choice | Why |
|---|---|---|
| Language | Go (stdlib `net/http`, 1.22+ routing) | One binary, low memory, no framework |
| Templates | stdlib `html/template` + `//go:embed` | Zero codegen, matches the house "stdlib-first" rule |
| Interactivity | HTMX (vendored single file) | Server-rendered fragments, ~14 kB, no build step |
| Styling | Tailwind CSS (standalone CLI, built at image build) | Utility CSS, dark mode, tiny final CSS |
| Database | SQLite via a SQLCipher-backed `database/sql` driver | Whole-file AES encryption at rest, normal indexed queries |
| Auth | stdlib sessions in SQLite + `golang.org/x/crypto/argon2` + stdlib TOTP | No auth SaaS, audit-friendly |
| Secrets | SQLCipher whole-DB encryption, key from env | Every page (data + indexes) encrypted; DB file alone is inert |
| Packaging | Multi-stage Docker, CGO + static musl, distroless non-root | Small image, no shell surface |
| PWA | Web App Manifest + service worker (static assets only) | Installable, offline shell, installs on Android |

Note on the database driver: `modernc.org/sqlite` has no encryption
codec, so this project uses a SQLCipher-backed driver (CGO). Phase 1
pinned **[`github.com/sjzar/go-sqlcipher`](https://github.com/sjzar/go-sqlcipher)**
v0.0.5 — a maintained fork of `mattn/go-sqlite3` that bundles SQLCipher
4.12.0 / SQLite 3.51.1 with libtomcrypt AES, so the binary links fully
static against musl with no OpenSSL. The earlier candidate
`mutecomm/go-sqlcipher` was last released in 2020. See
[PLAN.md](PLAN.md) for the decision.

## Quick start

Local (needs Go and a C toolchain for SQLCipher; the compiled
`web/static/app.css` is committed, so the Tailwind CLI is only needed
after changing templates — `make css`):

```sh
git clone https://github.com/CaffeinatedTech/caffeinated-clients
cd caffeinated-clients
export CCLIENTS_DB_KEY=$(head -c 32 /dev/urandom | base64)
export CCLIENTS_DATA_DIR=./data
export CCLIENTS_BOOTSTRAP_USERNAME=admin
export CCLIENTS_BOOTSTRAP_PASSWORD='pick-a-long-passphrase'
go run . --bootstrap-admin     # initialise + migrate, create the single user
go run .                       # serve; log in and enrol TOTP at /setup
```

`CCLIENTS_DATA_DIR` is created if missing and defaults to `./data` for a
local checkout; the container image sets it to `/data`.

Docker:

```sh
docker run -d --name caffeinated-clients \
  -p 8080:8080 \
  -v cclients-data:/data \
  -e CCLIENTS_BASE_URL=https://clients.example.com \
  -e CCLIENTS_DB_KEY="$(head -c 32 /dev/urandom | base64)" \
  -e CCLIENTS_BOOTSTRAP_USERNAME=admin \
  -e CCLIENTS_BOOTSTRAP_PASSWORD='change-me-then-remove' \
  ghcr.io/caffeinatedtech/caffeinated-clients:latest
```

Then visit `/`, log in, enroll TOTP at `/setup`, and **remove the
bootstrap password env var**.

## Configuration

Everything is environment variables — there is no config file to mount
and no plaintext secret on disk outside the running process. For Docker
Compose, copy [`.env.example`](.env.example) to `.env` (git-ignored) and
fill in the key; `.env.example` documents every variable with safe
defaults.

| Env var | Default | Purpose |
|---|---|---|
| `CCLIENTS_BASE_URL` | `http://localhost:8080` | Public URL; used for secure cookies, PWA, TOTP issuer |
| `CCLIENTS_DB_KEY` | — (**required**) | Base64 32-byte key; the SQLCipher database key |
| `CCLIENTS_DATA_DIR` | `./data` | Directory holding the SQLite file (container sets `/data`) |
| `CCLIENTS_DB_PATH` | `$DATA_DIR/clients.db` | Override database location |
| `CCLIENTS_LISTEN_ADDR` | `:8080` | Bind address |
| `CCLIENTS_SESSION_TTL` | `720h` | Absolute session lifetime; idle timeout is 1/8 of it |
| `CCLIENTS_TRUST_PROXY` | `false` | Set `true` behind Coolify so client IPs are real |
| `CCLIENTS_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `CCLIENTS_BOOTSTRAP_USERNAME` | — | First-run only: create the single user |
| `CCLIENTS_BOOTSTRAP_PASSWORD` | — | First-run only: initial password (min 8 chars) |
| `CCLIENTS_DISABLE_2FA` | `false` | Break-glass only; logs loudly and requires the password |
| `CCLIENTS_ARGON2_MEMORY` | `65536` | Argon2id memory cost, in KiB |
| `CCLIENTS_ARGON2_TIME` | `3` | Argon2id iterations |
| `CCLIENTS_ARGON2_THREADS` | `4` | Argon2id parallelism |

Generate a key:

```sh
head -c 32 /dev/urandom | base64
```

**Back this key up somewhere safe and offline.** Without it the
database cannot be opened at all — no client names, no notes, nothing.
Changing it is a deliberate `PRAGMA rekey` operation (see PLAN.md).

## Deploy on Coolify

1. Create a resource from the GHCR image
   `ghcr.io/caffeinatedtech/caffeinated-clients:latest` (or build from
   Git using the repo's Dockerfile).
2. Set the domain, e.g. `https://clients.example.com`, and enable
   Let's Encrypt. Coolify terminates TLS.
3. Add a persistent volume mounted at `/data`.
4. Set the environment: `CCLIENTS_BASE_URL`, `CCLIENTS_DB_KEY`,
   `CCLIENTS_TRUST_PROXY=true`, and the two bootstrap vars.
5. Set the health check path to `/healthz`, port `8080`.
6. Deploy, log in, enroll TOTP, then delete the bootstrap vars and
   redeploy.

Full walkthrough — key generation and storage, backup and restore,
break-glass recovery, and upgrades — is in
[docs/DEPLOY.md](docs/DEPLOY.md).

## Security model in one paragraph

The whole database is encrypted at rest with SQLCipher (AES-256 page
encryption, HMAC per page) using a key that exists only in the
environment; client names, phones, notes, and everything else are
unreadable without it, including through any index. One user logs in
with an Argon2id password plus TOTP; sessions are random tokens stored
hashed server-side, cookies are `HttpOnly`, `Secure`, `SameSite=Lax`,
and every state change carries a CSRF token. Secret notes are masked by
default; a reveal returns the value for that request only with
`Cache-Control: no-store`, re-masks after 15 seconds, and is logged.
Secrets never appear in normal responses, search, or logs. The app sets
a strict CSP and makes no third-party requests. See
[REQUIREMENTS.md](REQUIREMENTS.md) §Security for the full list.

## Search and indexing

Because the database is encrypted as a whole, ordinary SQLite indexes
and queries still work — no application-side crypto or blind indexes.
Indexed and searchable: client name, contact name, contact phone
(normalized), contact email, project name, and note title. Secret notes
and note bodies are excluded from search. Full-text search (FTS5) is
possible later and is safe under whole-database encryption; v1 uses
indexed `LIKE` queries (see PLAN.md).

## Backups

The entire application state is one encrypted SQLite file. Back up
safely by stopping the container cleanly (SQLite checkpoints the WAL) and
copying the file, or with `VACUUM INTO` from a build that has a shell —
never copy a live WAL database blindly. Backups are encrypted exactly
like the live file. The Settings page offers a JSON export; **secret
notes are excluded from that export by default**, since the export is
plaintext. Backup, restore, and recovery commands are documented in
[docs/DEPLOY.md](docs/DEPLOY.md).

## Why not just use ...

- **Monica / personal CRMs** — great for remembering people, but no
  encrypted-at-rest credential notes, no projects/jobs, no PWA focus.
- **EspoCRM / SuiteCRM / a full CRM** — PHP + MySQL, heavy, built
  around sales pipelines and acquisition flows you explicitly do not
  want.
- **Notion / a spreadsheet** — no encryption at rest, no installable
  mobile app, no structured projects and jobs.
- **Vaultwarden / a password manager** — excellent for secrets, but it
  is not a client CRM with notes, projects, and jobs.

caffeinated-clients exists for the overlap: existing clients, an
encrypted database, credential notes, projects and jobs, one small
container, installable on your phone.

## Status

**v0.1.4 — Phase 7 complete.** Everything in this README is implemented:
clients (created with just a name), contacts with a single-primary rule,
notes with pinned and secret flags and audited tap-to-reveal, projects and
jobs, grouped search, dashboard widgets, and the mobile PWA shell. Settings
covers password change (re-auth), authenticator re-enrollment (a pending
secret is only promoted after you confirm a code from it), recovery-code
regeneration, the theme toggle, and a JSON export that excludes secret notes
unless you explicitly opt in. The service ships as a multi-arch GHCR image
built by GitHub Actions on `v*` tags.

## License

MIT — see [LICENSE](LICENSE).
