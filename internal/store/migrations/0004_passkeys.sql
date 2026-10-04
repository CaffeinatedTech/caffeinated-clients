-- 0004_passkeys.sql — passkey (WebAuthn) credentials and in-flight ceremonies.
-- Never edit an earlier migration; this is additive and applied after 0003.
--
-- A passkey is an independent, complete sign-in factor: the server stores only
-- the public key, never a shared secret. `users.password_hash = ''` means the
-- account has no password (passkey-only); such an account never renders the
-- password form and POST /login is refused before any password work. TOTP is
-- only meaningful alongside a password.
--
-- All rows are encrypted at rest by SQLCipher like the rest of the database.
-- credential_id (the WebAuthn credential ID) is a BLOB and is unique.
CREATE TABLE webauthn_credentials (
    id                INTEGER PRIMARY KEY,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id     BLOB    NOT NULL UNIQUE,
    public_key        BLOB    NOT NULL,
    attestation_type  TEXT    NOT NULL DEFAULT '',
    aaguid            BLOB    NOT NULL DEFAULT x'',
    sign_count        INTEGER NOT NULL DEFAULT 0,
    backup_eligible   INTEGER NOT NULL DEFAULT 0 CHECK (backup_eligible IN (0, 1)),
    backup_state      INTEGER NOT NULL DEFAULT 0 CHECK (backup_state IN (0, 1)),
    transports        TEXT    NOT NULL DEFAULT '',
    name              TEXT    NOT NULL DEFAULT '',
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    last_used_at      TEXT
);
CREATE INDEX idx_webauthn_credentials_user ON webauthn_credentials(user_id);

-- A WebAuthn challenge is single-use and short-lived. session_data is the
-- JSON-encoded webauthn.SessionData returned by Begin{Registration,Login};
-- the raw cookie token is never stored, only its hash.
CREATE TABLE webauthn_challenges (
    id           INTEGER PRIMARY KEY,
    token_hash   TEXT    NOT NULL UNIQUE,
    user_id      INTEGER REFERENCES users(id) ON DELETE CASCADE,
    kind         TEXT    NOT NULL,
    session_data TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    expires_at   TEXT    NOT NULL
);
CREATE INDEX idx_webauthn_challenges_expires ON webauthn_challenges(expires_at);
