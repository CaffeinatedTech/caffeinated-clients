# REQUIREMENTS — caffeinated-clients

This is the specification. It describes intended behavior, not
implementation. When behavior changes, change this file first, and keep
it honest. Requirement IDs (F/Q/S/N) are stable — reference them in
commits and issues.

## 1. Purpose and problem

A solo IT services operator manages a fixed set of clients: support,
small web apps, credentials, ongoing projects, and day-to-day jobs.
Existing CRMs are built around winning *new* business — pipelines,
leads, campaigns — which is noise for someone whose contacts are all
already customers. What is missing is a private, fast, phone-installable
system of record whose contents are encrypted at rest.

caffeinated-clients is that system. It is single-user, self-hosted, and
optimized for one person pulling up a client in seconds while on a call.

## 2. Target user and operating context

- **One operator**, not a team. No roles, no sharing, no permissions
  matrix in v1.
- **Mobile-first.** Used most often from an Android phone installed as
  a PWA, often one-handed, sometimes on bad connectivity.
- **Self-hosted** on a Coolify server, behind HTTPS, in one container.
- **Low-resource.** Must be comfortable on a small VPS; idle memory is
  a design constraint, not an afterthought.
- **Privacy-sensitive.** The database contains customer details and
  credentials. Assume the database file and every backup may leak; they
  must be unreadable without the environment key.

## 3. Non-goals (v1)

- No sales pipeline, deals, lead capture, funnels, or marketing.
- No multi-user, teams, tenants, or role-based access control.
- No time tracking, invoicing, or billing.
- No email/calendar integration, no inbound mail.
- No asset/device inventory (possible future; see PLAN.md).
- No external network calls at runtime (no analytics, CDNs, telemetry).
- No full offline read/write of client data (offline is the app shell
  only; see F9).

## 4. Glossary

| Term | Meaning |
|---|---|
| **Client** | A business or person you support. The top-level record. |
| **Contact** | A person at a client (name, role, phone, email). A client has one or more. |
| **Note** | Free-form text attached to a client. May be flagged as a secret. |
| **Secret note** | A note with the secret flag set. Masked in the UI and revealed only on demand. Used for passwords, API keys, tokens, licenses. |
| **Passkey** | A WebAuthn credential (synced or device-bound) used to sign in. The private key stays on the authenticator; the server holds only the public key. |
| **Project** | A body of work for a client with a lifecycle and optional due date. |
| **Job** | A discrete unit of work, optionally under a project, with its own status. |

There is no separate "credential" object. Secrets are notes with a flag.

## 5. Functional requirements

### F1 — Authentication and access control

- F1.1 Exactly one user account exists. The app must not start serving
  authenticated routes until that user exists.
- F1.2 First-run bootstrap creates the single user from
  `CCLIENTS_BOOTSTRAP_USERNAME` / `CCLIENTS_BOOTSTRAP_PASSWORD`, via an
  explicit `--bootstrap-admin` CLI command, or via the first-run web
  screen at `/register` (passkey-first, or with a password). The web
  screen is available only while no complete account exists.
- F1.3 Passwords are hashed with Argon2id (sane default parameters,
  tunable via env) and never stored, logged, or returned in plaintext.
- F1.4 A password login requires the password **and** a TOTP code. TOTP
  enrollment is mandatory when an account is created with a password,
  before any client data is shown. The enrollment screen offers a
  scannable QR of the `otpauth://` URI as well as the manual setup key;
  the same QR is shown when re-enrolling. See F1.13 for passkey sign-in,
  which is a complete factor on its own.
- F1.5 Ten single-use recovery codes are generated at enrollment,
  displayed exactly once, stored only as hashes, and accepted in place
  of a TOTP code.
- F1.6 Sessions are server-side random tokens stored hashed in SQLite.
  The cookie is `HttpOnly`, `Secure` (when `CCLIENTS_BASE_URL` is
  https), `SameSite=Lax`, path `/`.
- F1.7 Sessions expire on an absolute TTL (`CCLIENTS_SESSION_TTL`) and
  after an idle period (one eighth of the TTL). Logout deletes the
  server-side session.
- F1.8 Every state-changing request requires a valid CSRF token tied to
  the session.
- F1.9 Login attempts are rate limited per IP and per username with
  backoff; failures are audited. `CCLIENTS_TRUST_PROXY=true` makes rate
  limiting use the forwarded client IP.
- F1.10 `CCLIENTS_DISABLE_2FA=true` is a documented break-glass switch:
  it logs a loud warning at startup, still requires the password, and is
  intended only to recover from a lost authenticator.
- F1.11 Changing the password, re-enrolling TOTP, and regenerating
  recovery codes all require re-authentication with the current password
  and, unless 2FA is disabled, a current TOTP or recovery code.
- F1.12 TOTP can be re-enrolled from Settings: a replacement secret takes
  effect only after a code generated from it is confirmed, so the current
  authenticator keeps working until then. Re-enrollment regenerates the
  recovery codes, which are shown once.
- F1.13 Passkeys (WebAuthn) are a complete, independent sign-in factor.
  A successful passkey assertion creates a full session without a
  password or TOTP code. The login page shows a
  **Sign in with a passkey** button whenever at least one passkey is
  registered, in addition to the password form when a password exists.
- F1.14 The first and only account can be created passkey-first. The
  first-run screen (`/register`, available only while no complete account
  exists) asks for a display name and creates the account with a passkey,
  or, alternatively, with a password (which then enrolls TOTP). No email
  or SMS is used.
- F1.15 When the account has no password (passkey-only), the password
  form is not rendered and `POST /login` is refused before any password
  verification, so there is no password attack surface.
- F1.16 Passkeys are managed in Settings: list, add, rename, and remove.
  Adding or removing a passkey requires re-authentication when a password
  exists. The last remaining credential (passkey or password) can never
  be removed. Removing the password requires at least one passkey and
  disables TOTP with it.
- F1.17 Recovery codes are accepted at the TOTP step and, when the
  account has no password, as a standalone sign-in. Each code is
  single-use and is the documented break-glass for a passkey-only
  account.
- F1.18 Passkeys require a secure context (HTTPS, or `http://localhost`
  for local development) and a real host; the relying-party ID and origin
  are derived from `CCLIENTS_BASE_URL`. A bare IP address is not
  supported. The server stores only the credential public key and
  metadata, never a private key or other secret.

### F2 — Client management

- F2.1 A client can be created with only a **name** (business or
  person). Every other field is optional.
- F2.2 Client fields: business/display name, status
  (`active` \| `inactive` \| `archived`), website, address, free-form
  summary, tags, created/updated timestamps.
- F2.3 A phone number can be stored on the client (main line) and on
  contacts. Phone numbers are normalized (digits) for search.
- F2.4 Clients can be edited, archived (hidden from default lists but
  not deleted), and permanently deleted with confirmation.
- F2.5 The client list supports text filter, status filter, and sort by
  name / recently updated / recently created.
- F2.6 A client page is the hub: header with name, primary contact,
  quick actions (call, email, open website/map), then tabs for
  Overview, Contacts, Notes, Projects, Jobs, Activity.

### F3 — Contacts

- F3.1 A client may have zero or more contacts.
- F3.2 Contact fields: name, role/title, phone, email, notes, primary
  flag.
- F3.3 Exactly zero or one contact per client is primary; setting a new
  primary clears the old one.
- F3.4 Contacts are searchable by name, phone, and email and link back
  to their client.

### F4 — Notes

- F4.1 Notes are attached to a client, or to one of that client's jobs
  (F7.6), and have a title, a body (plain text or minimal Markdown
  rendered safely), a pinned flag, and a secret flag. A note's title is
  optional.
- F4.2 Pinned notes sort first on the client page and can surface on
  the dashboard.
- F4.3 Notes support create, edit, pin/unpin, toggle secret, and
  delete. Deletion of a non-empty note requires confirmation.
- F4.4 Note bodies are stored as text, rendered escaped by default;
  any Markdown rendering must be sanitized (no raw HTML passthrough).
- F4.5 Note **titles** are indexed and searchable. Note bodies are not
  searched in v1. The schema must not preclude adding SQLite FTS5 later
  (N4).
- F4.6 A note's secret flag can be toggled; toggling changes only the
  UI treatment and search exclusion, not the stored body.

### F5 — Secret notes

- F5.1 Any note can be flagged as a secret. There is no separate
  credential object and no separate secret table.
- F5.2 Secret notes are masked everywhere they appear: client lists,
  search results, the Activity feed, the client page, and the job page.
  Masking shows the title and metadata but not the body.
- F5.3 Revealing a secret note requires an explicit tap. As soon as the
  user taps reveal, the body is shown; there is no confirmation dialog.
  The revealed body re-masks after 15 seconds (auto-hide).
- F5.4 A reveal returns the body only for the request that requested
  it, with `Cache-Control: no-store`. The body is never present in a
  normal page render, list, or search result.
- F5.5 Secret notes are excluded from search entirely (neither title
  nor body), so a secret can never surface in a search result.
- F5.6 Every reveal, create, update, secret-flag change, and delete of
  a secret note is written to the audit log (F13).
- F5.7 Secret notes remain in the encrypted database like every other
  row; the "encryption at rest" requirement (S2) applies to the whole
  database, not only to secret fields.
- F5.8 Copy-to-clipboard is offered on a revealed secret note and must
  not write the value anywhere outside the clipboard.

### F6 — Projects

- F6.1 A project belongs to one client and has: name, description,
  status (`planning` \| `active` \| `waiting` \| `done` \| `archived`),
  optional due date, and started/completed timestamps.
- F6.2 Projects with status `planning`, `active`, or `waiting` count as
  **ongoing** and appear on the dashboard and a global projects view.
- F6.3 Projects aggregate their jobs and show progress (jobs done vs
  total).
- F6.4 A project can be created from a client page or from the global
  projects view; a project must always have a client.
- F6.5 Project names are indexed and searchable.

### F7 — Jobs

- F7.1 A job belongs to one client and optionally to one project (which
  must belong to the same client).
- F7.2 Job fields: title, description, status (`open` \|
  `in_progress` \| `waiting` \| `done`), priority
  (`low` \| `normal` \| `high`), optional due/scheduled date, completed
  timestamp.
- F7.3 Jobs can be created from a client page, a project page, or the
  global jobs view (choosing a client).
- F7.4 The dashboard shows upcoming/overdue open jobs; the global jobs
  view filters by status, client, project, and due window.
- F7.5 Marking a job done records a completion timestamp; reopening
  clears it.
- F7.6 A job has its own notes: individual notes captured while working
  the job, each optionally titled and optionally secret. Job notes reuse
  the note fields and rules (F4/F5) and the audited secret reveal, appear
  only on the job page (not mixed into the client's Notes tab), and are
  deleted with the job. A job note's client is always its job's client.

### F8 — Dashboard and search

- F8.1 The dashboard is the landing page after login and contains:
  - a prominent search box,
  - ongoing projects (F6.2) with client and due date,
  - upcoming and overdue open jobs (F7.4),
  - recently viewed/updated clients.
- F8.2 Search matches, at minimum:
  - client business/display name,
  - contact name, phone number, and email,
  - project name,
  - note title (non-secret notes only).
  Phone matching normalizes formatting so `555-0100`, `(555) 0100`, and
  `+15550100` all match.
- F8.3 Search results are grouped by kind (clients, contacts, projects,
  notes) and link to the relevant page.
- F8.4 Search is debounced and served as an HTMX partial
  (`/search?q=`) targeting a results region; results work without
  JavaScript via a full-page fallback.
- F8.5 Search **never** returns secret notes, note bodies, or any
  secret material (F5.5).
- F8.6 The dashboard loads fast: the search box is usable before any
  project/job widgets finish rendering if they are ever deferred.

### F9 — PWA and mobile

- F9.1 The app ships a Web App Manifest (name, short name, icons at
  192 and 512 including maskable, `display: standalone`, theme and
  background colors, `start_url: /`).
- F9.2 A service worker caches only the app shell and versioned static
  assets (CSS, JS, icons, font if self-hosted) and an offline fallback
  page. **Authenticated HTML and all client data are never cached by
  the service worker.**
- F9.3 The app is installable on Android Chrome; installed it launches
  standalone with no browser chrome.
- F9.4 All primary actions are reachable one-handed on a phone: bottom
  navigation on small screens, large touch targets (>= 44 px), no
  hover-only interactions.
- F9.5 The layout is responsive from ~360 px wide through desktop.
- F9.6 Service worker registration is HTTPS-only; on plain HTTP
  (local dev) the app still functions, just without install/offline.

### F10 — UI and theming

- F10.1 Light and dark themes, following `prefers-color-scheme` by
  default with a manual override that persists.
- F10.2 The theme is applied before first paint to avoid a flash
  (external, non-inline theme script to satisfy CSP).
- F10.3 No third-party runtime requests: no CDN, no hosted fonts, no
  analytics. All assets are served from the app.
- F10.4 Visual language: clean, modern, calm; generous spacing,
  readable type, one accent color. No emojis in the product UI unless
  the operator adds them in their own note text.
- F10.5 Basic accessibility: semantic HTML, labelled form controls,
  visible focus states, keyboard-operable navigation and menus.

### F11 — Deployment and configuration

- F11.1 The app runs as a single container listening on
  `CCLIENTS_LISTEN_ADDR` (default `:8080`).
- F11.2 All configuration is environment variables (see README table).
  No config file is required.
- F11.3 Persistent state is the encrypted SQLite file under
  `CCLIENTS_DATA_DIR`; the container filesystem is otherwise read-only
  and disposable.
- F11.4 The container runs as a non-root user with a static binary and
  no shell in the runtime image.
- F11.5 `GET /healthz` returns 200 when the process is up and the
  database is reachable and decryptable, and 503 otherwise; used by
  Coolify's health check.
- F11.6 The image is published to
  `ghcr.io/caffeinatedtech/caffeinated-clients` with `latest`,
  `vX.Y.Z`, and commit-sha tags, built for `linux/amd64` and
  `linux/arm64`.
- F11.7 The app sets a strict Content-Security-Policy, `X-Content-Type-
  Options: nosniff`, `Referrer-Policy`, and frame-ancestors `'none'`.
  HSTS is set by the TLS-terminating proxy.
- F11.8 The app performs no outbound network requests at runtime.

### F12 — Data integrity, export, and backup

- F12.1 SQLite runs with WAL mode and foreign keys enabled, under
  SQLCipher.
- F12.2 Schema migrations are embedded and applied idempotently at
  startup, tracked via `PRAGMA user_version`.
- F12.3 The Settings page offers a JSON export of all data.
  **Secret notes are excluded from that export by default** because the
  export is plaintext; including them requires a separate, clearly-
  labelled action with its own confirmation.
- F12.4 Documented backup/copy procedure uses `VACUUM INTO` (or WAL
  checkpoint + copy) to produce a consistent single file. Backups
  remain encrypted because whole-database encryption is transparent.
- F12.5 Deleting a client cascades to its contacts, notes, projects,
  and jobs, after explicit confirmation that names the client and the
  counts being removed.

### F13 — Audit log

- F13.1 The app records an append-only audit log of security-relevant
  events: login success/failure, TOTP enrollment, recovery-code use,
  session logout, note create/update, secret-note create/update/reveal/
  delete, secret-flag toggle, client create/delete, password change,
  TOTP re-enrollment, recovery-code regeneration, data export, account
  registration (method: passkey or password), and passkey
  register/rename/remove/password-removal.
- F13.2 Audit entries carry timestamp, event, target entity and id, and
  client IP; entries never contain the body of a secret note or any
  password material. For a reveal, the entry records the note id and
  the event only.
- F13.3 The client Activity tab shows that client's audit entries; a
  global audit view is available in Settings.

### F14 — Open source and distribution

- F14.1 The project is public and MIT-licensed.
- F14.2 No real client data, hostnames, tokens, or personal details
  appear in code, fixtures, docs, or commit messages (see AGENTS.md).
- F14.3 The README documents self-hosting on Coolify and running
  locally.

## 6. Security requirements (non-functional, mandatory)

- **S1** Threat model: the SQLite file and every backup may be obtained
  by an attacker; the environment key may not. Confidentiality of all
  client data rests on S2.
- **S2** The entire database is encrypted at rest with SQLCipher
  (AES-256 page encryption with per-page HMAC). The key is a 32-byte
  value from `CCLIENTS_DB_KEY` and exists only in the environment. There
  is no unencrypted database mode and no fallback key. Names, phones,
  notes, sessions, and audit rows are all covered, including their
  indexes.
- **S3** No secret note body, password, session token, TOTP secret, or
  recovery code is ever written to logs or error messages.
- **S4** Password hashing is Argon2id. TOTP is RFC 6238, SHA-1, 6
  digits, 30-second period, with drift tolerance of one step.
- **S5** Session and CSRF tokens are generated with `crypto/rand`.
- **S6** All user-supplied text rendered into HTML goes through
  `html/template` auto-escaping; Markdown, if enabled, is sanitized.
- **S7** Security headers per F11.7; revealed-secret responses are
  `no-store`; secret notes never appear in search or ordinary renders.
- **S8** Dependencies are minimized; every added dependency needs a
  one-line justification ("stdlib can't do X"). Known-good additions:
  a SQLCipher-backed SQLite driver, `golang.org/x/crypto`. HTMX is a
  vendored asset, not a Go dependency.
- **S9** The app never trusts `X-Forwarded-*` unless
  `CCLIENTS_TRUST_PROXY=true`.
- **S10** Losing `CCLIENTS_DB_KEY` means permanent loss of all data;
  the app must state this at startup and in the README. Wrong keys must
  fail closed (never open a database as if empty).
- **S11** Passkey ceremonies are verified server-side (challenge,
  origin, RP ID, signature, and sign counter) with no client-supplied
  trust. Challenges are single-use, short-lived, and stored server-side;
  the server stores only public keys and metadata. A passkey-only
  account has no password hash and its password endpoint is disabled.

## 7. Quality requirements

- **Q1** Idle memory target: comfortable under 100 MB RSS on
  `linux/amd64`; the binary and image stay small despite CGO.
- **Q2** Dashboard and search feel instant on a mid-range phone:
  search results return in well under 200 ms for databases with
  thousands of clients on local SSD.
- **Q3** No JavaScript framework; JS is limited to HTMX, reveal
  auto-masking, the theme toggle, clipboard copy, and PWA registration.
- **Q4** Graceful handling of bad input: every form returns inline
  errors and preserves entered values; no unhandled 500s for expected
  validation failures.
- **Q5** The app degrades gracefully without JavaScript: reads and
  form submissions work via full-page requests.
- **Q6** `go build ./...`, `go vet ./...`, `gofmt -l .`, and
  `go test ./...` are clean before anything is considered done.

## 8. Out of scope for v1 (tracked in PLAN.md)

- Database key rotation (`PRAGMA rekey`) command.
- SQLite FTS5 full-text search over clients and non-secret notes.
- Asset/device inventory per client.
- Time tracking and invoicing.
- Attachments/file uploads.
- Email/calendar/notification integrations.
- Multi-user and sharing.
- Full offline read/write with sync.
- Import from other CRMs.
