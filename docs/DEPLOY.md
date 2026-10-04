# Deploying caffeinated-clients

Operational guide for a self-hosted install: Coolify, the database key,
backups, restore, and recovery. Examples use synthetic values
(`clients.example.com`, `Acme Co`) — never a real key or client detail.

- [What you are deploying](#what-you-are-deploying)
- [1. Generate and store the database key](#1-generate-and-store-the-database-key)
- [2. Deploy on Coolify](#2-deploy-on-coolify)
- [3. First login and TOTP enrollment](#3-first-login-and-totp-enrollment)
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

1. **Create the resource.** New Resource → Docker image
   `ghcr.io/caffeinatedtech/caffeinated-clients:latest`, or deploy from
   this Git repository using its `Dockerfile`.
2. **Set the domain** to e.g. `https://clients.example.com` and enable
   Let's Encrypt. Coolify terminates TLS in front of the container.
3. **Add a persistent volume** mounted at `/data`. Without it the
   database lives in the container filesystem and is lost on redeploy.
4. **Set the environment variables** (see the README table for the full
   list). The minimum:

   ```
   CCLIENTS_BASE_URL=https://clients.example.com
   CCLIENTS_DB_KEY=<the base64 key from step 1>
   CCLIENTS_TRUST_PROXY=true
   CCLIENTS_BOOTSTRAP_USERNAME=admin
   CCLIENTS_BOOTSTRAP_PASSWORD=<a long passphrase>
   ```

   `CCLIENTS_TRUST_PROXY=true` is required behind Coolify so login rate
   limiting sees the real client IP. Leave it `false` when exposing the
   app directly.

5. **Set the health check** to HTTP `GET /healthz` on port `8080`. The
   endpoint returns 200 only when the database is open and decryptable.
6. **Deploy.** Then follow step 3 to create the account and finish TOTP
   enrollment, and **delete `CCLIENTS_BOOTSTRAP_USERNAME` /
   `CCLIENTS_BOOTSTRAP_PASSWORD`** and redeploy.

## 3. First login and TOTP enrollment

1. Open `https://clients.example.com` and sign in with the bootstrap
   credentials.
2. The first login forces TOTP enrollment at `/setup`. Add the setup key
   to your authenticator app, enter the code, and save the ten one-time
   recovery codes shown. **They are displayed once and stored only as
   hashes.**
3. Remove the two bootstrap environment variables in Coolify and
   redeploy.

From then on, login is password + authenticator code, or a single-use
recovery code.

### Passkey-first alternative

Instead of the bootstrap variables, you can create the account with a
passkey: deploy with `CCLIENTS_BASE_URL` set to the real HTTPS host and no
bootstrap credentials, open the site, and follow `/register` — give it a
display name and register a passkey. Add more passkeys (e.g. phone and
laptop) in **Settings → Passkeys**; a passkey-only account has no password
and no TOTP. Keep the recovery codes safe, as they are the break-glass if
every passkey is lost. Passkeys require HTTPS and a hostname: a bare IP
does not work, and changing `CCLIENTS_BASE_URL` to a different host
invalidates existing passkeys.

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
