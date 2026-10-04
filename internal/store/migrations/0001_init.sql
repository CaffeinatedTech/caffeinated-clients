-- 0001_init.sql — initial schema.
-- Applied exactly once, tracked by PRAGMA user_version. Never edit an applied
-- migration; add a new numbered file instead.
--
-- Every row here is encrypted at rest by SQLCipher, including indexes; the
-- schema makes no distinction between secret and non-secret data. There is no
-- `secrets` table: a secret is notes.is_secret = 1.

CREATE TABLE clients (
    id           INTEGER PRIMARY KEY,
    name         TEXT    NOT NULL,
    status       TEXT    NOT NULL DEFAULT 'active'
                 CHECK (status IN ('active', 'inactive', 'archived')),
    website      TEXT    NOT NULL DEFAULT '',
    address      TEXT    NOT NULL DEFAULT '',
    phone        TEXT    NOT NULL DEFAULT '',
    phone_digits TEXT    NOT NULL DEFAULT '',
    summary      TEXT    NOT NULL DEFAULT '',
    tags         TEXT    NOT NULL DEFAULT '',
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    archived_at  TEXT
);
CREATE INDEX idx_clients_name ON clients(name);
CREATE INDEX idx_clients_status ON clients(status);
CREATE INDEX idx_clients_updated_at ON clients(updated_at);
CREATE INDEX idx_clients_phone_digits ON clients(phone_digits);

CREATE TABLE contacts (
    id           INTEGER PRIMARY KEY,
    client_id    INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    role         TEXT    NOT NULL DEFAULT '',
    phone        TEXT    NOT NULL DEFAULT '',
    phone_digits TEXT    NOT NULL DEFAULT '',
    email        TEXT    NOT NULL DEFAULT '',
    notes        TEXT    NOT NULL DEFAULT '',
    is_primary   INTEGER NOT NULL DEFAULT 0 CHECK (is_primary IN (0, 1)),
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_contacts_client ON contacts(client_id);
CREATE INDEX idx_contacts_name ON contacts(name);
CREATE INDEX idx_contacts_phone_digits ON contacts(phone_digits);
CREATE INDEX idx_contacts_email ON contacts(email);
-- At most one primary contact per client, enforced by the database.
CREATE UNIQUE INDEX idx_contacts_primary ON contacts(client_id) WHERE is_primary = 1;

CREATE TABLE notes (
    id         INTEGER PRIMARY KEY,
    client_id  INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    title      TEXT    NOT NULL DEFAULT '',
    body       TEXT    NOT NULL DEFAULT '',
    pinned     INTEGER NOT NULL DEFAULT 0 CHECK (pinned IN (0, 1)),
    is_secret  INTEGER NOT NULL DEFAULT 0 CHECK (is_secret IN (0, 1)),
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_notes_client ON notes(client_id);
CREATE INDEX idx_notes_title ON notes(title);

CREATE TABLE projects (
    id           INTEGER PRIMARY KEY,
    client_id    INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    description  TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL DEFAULT 'planning'
                 CHECK (status IN ('planning', 'active', 'waiting', 'done', 'archived')),
    due_date     TEXT,
    started_at   TEXT,
    completed_at TEXT,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_projects_client_status ON projects(client_id, status);
CREATE INDEX idx_projects_name ON projects(name);

CREATE TABLE jobs (
    id           INTEGER PRIMARY KEY,
    client_id    INTEGER NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    project_id   INTEGER REFERENCES projects(id) ON DELETE SET NULL,
    title        TEXT    NOT NULL,
    description  TEXT    NOT NULL DEFAULT '',
    status       TEXT    NOT NULL DEFAULT 'open'
                 CHECK (status IN ('open', 'in_progress', 'waiting', 'done')),
    priority     TEXT    NOT NULL DEFAULT 'normal'
                 CHECK (priority IN ('low', 'normal', 'high')),
    due_date     TEXT,
    completed_at TEXT,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_jobs_client_status_due ON jobs(client_id, status, due_date);
CREATE INDEX idx_jobs_project ON jobs(project_id);

-- Exactly one users row exists; enforced by the application (Phase 2).
CREATE TABLE users (
    id               INTEGER PRIMARY KEY,
    username         TEXT    NOT NULL UNIQUE,
    password_hash    TEXT    NOT NULL,
    totp_secret      TEXT    NOT NULL DEFAULT '',
    totp_enabled     INTEGER NOT NULL DEFAULT 0 CHECK (totp_enabled IN (0, 1)),
    totp_enrolled_at TEXT,
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE recovery_codes (
    id         INTEGER PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT    NOT NULL,
    used_at    TEXT,
    created_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);
CREATE INDEX idx_recovery_codes_user ON recovery_codes(user_id);

CREATE TABLE sessions (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT    NOT NULL UNIQUE,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_seen_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT    NOT NULL,
    user_agent   TEXT    NOT NULL DEFAULT '',
    ip           TEXT    NOT NULL DEFAULT ''
);

-- Append-only. No foreign keys: audit rows must outlive the entities they
-- reference. `detail` is JSON and never contains secret note bodies,
-- passwords, tokens, or recovery codes.
CREATE TABLE audit_log (
    id         INTEGER PRIMARY KEY,
    at         TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    event      TEXT    NOT NULL,
    entity     TEXT    NOT NULL DEFAULT '',
    entity_id  INTEGER,
    client_id  INTEGER,
    ip         TEXT    NOT NULL DEFAULT '',
    detail     TEXT    NOT NULL DEFAULT '{}'
);
CREATE INDEX idx_audit_at ON audit_log(at);
CREATE INDEX idx_audit_client ON audit_log(client_id);
