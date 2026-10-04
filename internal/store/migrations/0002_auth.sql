-- 0002_auth.sql — session authentication stage and per-session CSRF token.
-- Never edit 0001; this is an additive migration applied after it.
--
-- stage is 'pending' between the password step and a completed second factor
-- (TOTP or recovery code), and 'full' once authentication is complete. Only
-- 'full' sessions may reach application routes.
--
-- csrf_token is a random per-session value; every non-GET request must present
-- it, tying state changes to the session (F1.8).
ALTER TABLE sessions ADD COLUMN stage TEXT NOT NULL DEFAULT 'full';
ALTER TABLE sessions ADD COLUMN csrf_token TEXT NOT NULL DEFAULT '';
