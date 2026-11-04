-- Interaction, pending TOTP enrollment and WebAuthn challenge state — §6.1.
--
-- These three were process maps. The row is now the source of truth, so a restart does not lose
-- an in-flight sign-in and a second instance can finish a flow the first started. The pending TOTP
-- seed is sealed by the server with the tenant DEK before it reaches `secret_enc`; the interaction
-- payload is the same JSON the verifier needs to mint the code, and the challenge is public.
CREATE TABLE IF NOT EXISTS interactions (
  id                text PRIMARY KEY,
  payload           jsonb NOT NULL,
  consumed          boolean NOT NULL DEFAULT false,
  signed_in_account uuid,
  session_id        uuid,
  mfa_account       uuid,
  mfa_enrollment    uuid,
  mfa_satisfied     boolean NOT NULL DEFAULT false,
  mfa_attempts      integer NOT NULL DEFAULT 0,
  expires_at        timestamptz NOT NULL,
  created_at        timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS interactions_expiry_idx ON interactions (expires_at);

CREATE TABLE IF NOT EXISTS totp_enrollments (
  account_id uuid PRIMARY KEY,
  secret_enc bytea NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS totp_enrollments_expiry_idx ON totp_enrollments (expires_at);

CREATE TABLE IF NOT EXISTS passkey_challenges (
  key        text PRIMARY KEY,
  challenge  bytea NOT NULL,
  expires_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS passkey_challenges_expiry_idx ON passkey_challenges (expires_at);
