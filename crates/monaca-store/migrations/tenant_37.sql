-- CAPTCHA and login-failure lockout — docs/contracts/m0.md §6.1 sign-in experience, §5.6.
--
-- CAPTCHA is a tenant-wide switch with one provider at a time. The secret is write-only: it is
-- sealed with the tenant DEK before it reaches this row, and no management response ever reads it
-- back. The three `captcha_on_*` flags decide which entrances demand a token, so a tenant can put
-- a challenge in front of registration without also putting one in front of password sign-in.
--
-- Lockout is per identifier, not per IP: the counter is keyed by the normalised identifier a
-- password attempt named, so rotating source addresses does not refill the account's budget. A
-- threshold of zero disables the check; otherwise the account is refused for the configured
-- duration after that many consecutive wrong passwords.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS captcha_enabled boolean NOT NULL DEFAULT false,
  ADD COLUMN IF NOT EXISTS captcha_provider text NOT NULL DEFAULT 'turnstile'
    CHECK (captcha_provider IN ('turnstile', 'recaptcha')),
  ADD COLUMN IF NOT EXISTS captcha_site_key text,
  ADD COLUMN IF NOT EXISTS captcha_secret_enc bytea,
  ADD COLUMN IF NOT EXISTS captcha_on_sign_in boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS captcha_on_sign_up boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS captcha_on_password_reset boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS login_lockout_threshold integer NOT NULL DEFAULT 0
    CHECK (login_lockout_threshold BETWEEN 0 AND 100),
  ADD COLUMN IF NOT EXISTS login_lockout_duration_secs integer NOT NULL DEFAULT 900
    CHECK (login_lockout_duration_secs BETWEEN 30 AND 86400);

CREATE TABLE IF NOT EXISTS login_failures (
  identifier_key text PRIMARY KEY CHECK (char_length(identifier_key) BETWEEN 1 AND 320),
  failures       integer NOT NULL DEFAULT 0 CHECK (failures >= 0),
  locked_until   timestamptz,
  updated_at     timestamptz NOT NULL DEFAULT now()
);
