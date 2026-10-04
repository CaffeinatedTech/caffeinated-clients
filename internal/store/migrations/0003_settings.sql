-- 0003_settings.sql — pending TOTP secret for re-enrollment.
--
-- A 2FA re-enrollment writes a new secret here while the current authenticator
-- stays enabled, so an abandoned re-enrollment cannot lock the user out or
-- silently disable the second factor. totp_secret is only replaced once the new
-- code is confirmed from this pending value.
ALTER TABLE users ADD COLUMN totp_pending_secret TEXT NOT NULL DEFAULT '';
