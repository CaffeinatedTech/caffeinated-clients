# Deploying caffeinated-clients

Operational guide for a self-hosted install: Coolify, the database key,
backups, restore, and recovery. Examples use synthetic values
(`clients.example.com`, `Acme Co`) — never a real key or client detail.

- [What you are deploying](#what-you-are-deploying)
- [1. Generate and store the database key](#1-generate-and-store-the-database-key)
- [2. Deploy on Coolify](#2-deploy-on-coolify)
- [3. First login](#3-first-login)
- [4. Backups](#4-backups)
- [5. Restore](#5-restore)
- [6. Break-glass recovery](#6-break-glass-recovery)
- [7. JSON export](#7-json-export)
- [8. Key rotation (not in v1)](#8-key-rotation-not-in-v1)
- [9. Upgrades and health](#9-upgrades-and-health)

## What you are deploying

One container running one static binary. It listens on `:8080`, keeps all
state in one SQLCipher-encrypted SQLite file under `/data`, and makes no
outbound network requests. TLS and HSTS are the reverse proxy's job.

The runtime image is distroless and has **no shell**. Anything that edits
files inside the container is done by mounting a volume or by the app
itself, not by `docker exec`.

## 1. Generate and store the database key

The key is a base64-encoded 32-byte value. Generate it once, on a trusted
machine:

```sh
head -c 32 /dev/urandom | base64
```

Store it in **two** places:

1. Coolify's secret environment variable `CCLIENTS_DB_KEY` for the app.
2. An offline copy in a password manager or sealed note.

Rules:

- The key is the only thing standing between a leaked database file and
  every client detail you hold. A copy of the `.db` file without the key
  is inert.
- **Never** commit the key, paste it into an issue, or email it.
- **Losing the key is permanent, unrecoverable data loss.** There is no
  escrow, no backdoor, and no unencrypted fallback. The app refuses to
  open a database with a missing or wrong key rather than silently
  starting empty.

## 2. Deploy on Coolify

Deploy either by pasting the ready-made Compose file (recommended) or by
filling in a Docker Image resource through the UI.

### Option A — paste the Compose file (recommended)

1. **Create the resource.** New Resource → Docker Compose Empty, or a
   Git-based resource pointed at
   [`deploy/coolify-compose.yml`](../deploy/coolify-compose.yml).
2. **Paste** the contents of `deploy/coolify-compose.yml` and save. It
   declares the environment variables, the `/data` volume, and the
   health check; it publishes no `ports:` so nothing bypasses the proxy.
3. **Set the domain** on the `app` service to e.g.
   `https://clients.example.com:8080` — the `:8080` is the internal
   container port Coolify routes to — and enable Let's Encrypt. Coolify
   adds the proxy labels.
4. **Fill the environment variables** Coolify creates from the file:
   - `CCLIENTS_BASE_URL=https://clients.example.com`
   - `CCLIENTS_DB_KEY=<the base64 key from step 1>`

   `CCLIENTS_TRUST_PROXY` defaults to `true` in the file. The bootstrap
   variables are commented out for the passkey-first path; see §3.
5. **Deploy.** The health check comes from the Compose `healthcheck:`,
   a `CMD` check that runs the binary's `--healthcheck` (a decrypting
   database ping). Do **not** add an HTTP check: Compose resources
   ignore Coolify's Healthcheck page, and Coolify's HTTP checks require
   `curl`/`wget`, which the distroless image does not contain.

### Option B — Docker Image resource (UI)

1. New Resource → Docker image
   `ghcr.io/caffeinatedtech/caffeinated-clients:latest`, or deploy from
   this Git repository using its `Dockerfile`.
2. Set the domain to `https://clients.example.com` and enable Let's
   Encrypt.
3. Add a persistent volume mounted at `/data`.
4. Set `CCLIENTS_BASE_URL`, `CCLIENTS_DB_KEY`, and
   `CCLIENTS_TRUST_PROXY=true` (see the README table for the full list).
   The bootstrap variables are optional and passkey-first is preferred;
   see §3.
5. Health check: leave it disabled so the image's built-in
   `HEALTHCHECK` applies, or set Coolify's type to **CMD** with command
   `/caffeinated-clients --healthcheck`. Do **not** use an HTTP
   `GET /healthz` check — the distroless image has no `curl`/`wget`.
6. Deploy, then follow §3.

## 3. First login

### Passkey-first (recommended)

1. With no bootstrap variables set, open
   `https://clients.example.com` and follow `/register`.
2. Give the account a display name and register a passkey.
3. Add more passkeys (e.g. phone and laptop) in **Settings →
   Passkeys**, and keep the ten one-time recovery codes safe. They are
   shown once, stored only as hashes, and are the break-glass if every
   passkey is lost.

Passkeys require HTTPS and a real hostname: a bare IP does not work, and
changing `CCLIENTS_BASE_URL` to a different host invalidates existing
passkeys (password/recovery login still works).

### Password + TOTP (alternative)

To create a password account instead, uncomment (or set) both
`CCLIENTS_BOOTSTRAP_USERNAME` and `CCLIENTS_BOOTSTRAP_PASSWORD` (min 8
chars) and redeploy. Sign in with them; the first login forces TOTP
enrollment at `/setup` — add the setup key to your authenticator app,
enter the code, and save the ten one-time recovery codes. Then **delete
both bootstrap variables and redeploy.**

From then on, password login requires an authenticator code or a
single-use recovery code.

## 4. Backups

The whole application state is the encrypted SQLite file, so a backup is
a copy of that file (still encrypted). Because SQLite runs in WAL mode,
copying a **live** database by hand can capture a torn state. Use one of:

### Option A — clean stop, then copy (recommended)

A clean shutdown checkpoints and removes the WAL, leaving a consistent
single file. With Compose:

```sh
docker compose stop
# copy /data/clients.db out of the named volume
docker compose start
```

Copy the file to your backup target. It is encrypted exactly like the
live file.

### Option B — `VACUUM INTO` from a tool build

If you run a build with the `sqlite3` CLI (or add a `--backup` command),
open the live database with the key and run:

```sql
VACUUM INTO '/data/backup-20260101.db';
```

The output is a consistent, encrypted single file. This is not available
inside the shipped distroless image because it has no shell.

Do **not** copy only `clients.db` while the app is running and leave the
`-wal` / `-shm` sidecars behind: that can lose recent writes or capture a
partial transaction.

## 5. Restore

1. Stop the container.
2. Replace `/data/clients.db` (and delete any stale `clients.db-wal` /
   `clients.db-shm`) with the backup copy.
3. Start the container. `/healthz` must return 200; a wrong or missing
   `CCLIENTS_DB_KEY` fails closed and the app will not start.

Test a restore onto a throwaway instance before you ever need it.

## 6. Break-glass recovery

If you lose the authenticator (not the password), set:

```
CCLIENTS_DISABLE_2FA=true
```

and redeploy. Startup logs a loud warning; the password is still
required. Sign in, open **Settings**, and use **Re-enroll authenticator**
to enroll a new device (no code is required while 2FA is disabled). Then
remove `CCLIENTS_DISABLE_2FA` and redeploy.

This switch never weakens the password requirement and is intended only
for recovering a lost authenticator. Leaving it on permanently disables
the second factor.

If the password is also lost, there is no password-reset backdoor: restore
from a backup, or start fresh. The database key is unrelated to the
password and cannot recover it.

## 7. JSON export

**Settings → Data export** produces a plaintext JSON copy of clients,
contacts, notes, projects, jobs, and the audit log. Secret note bodies are
**excluded by default**; including them is a separate, clearly-labelled
action with its own confirmation, because the resulting file is not
encrypted. Both actions are written to the audit log. Treat an export with
secrets the same as the key: store it encrypted, then delete it.

## 8. Key rotation (not in v1)

`PRAGMA rekey` / re-encryption is **not implemented in v0.1.0**. If the
key must change, the supported path today is a fresh instance and a
re-import from a JSON export. The planned upgrade is a `rekey` command
that runs `PRAGMA rekey` with the new key and rewrites the database in
place; see PLAN.md "Later".

## 9. Upgrades and health

- Bump the image tag (`v0.1.0` → the new tag) and redeploy. Embedded
  migrations run at startup and are idempotent; back up first anyway.
- `GET /healthz` returns `200` with `ok` only when the database is
  reachable and decryptable, `503` otherwise. Point Coolify's health
  check at it.
- Sessions, rate limiting, and the database assume a **single instance**.
  Do not scale the service to multiple replicas against one database.
