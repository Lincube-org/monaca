-- Tenant schema, version 4 — email verification codes (docs/contracts/m0.md §6.1).
-- Additive: versions 1–3 have already run and their checksums must never change.

-- One short-lived, single-use secret per (purpose, identifier). Only the SHA-256 hex of the code
-- is stored: a database read must not hand out a usable code. `attempts` is the brute-force guard
-- (six digits is small enough to guess given unlimited tries — five wrong guesses exhaust the code),
-- and `consumed_at` makes a successful verification single-use even when two requests race.
CREATE TABLE IF NOT EXISTS verification_codes (
  id          uuid PRIMARY KEY,
  purpose     text NOT NULL CHECK (purpose IN ('sign_up','sign_in','password_reset')),
  -- Normalised (trimmed, lowercase) email address, so lookups are exact and case-insensitive by
  -- construction rather than by an expression index.
  identifier  text NOT NULL,
  code_hash   text NOT NULL,
  attempts    integer NOT NULL DEFAULT 0,
  expires_at  timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS verification_codes_lookup_idx
  ON verification_codes (purpose, identifier, created_at DESC) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS verification_codes_expiry_idx
  ON verification_codes (expires_at) WHERE consumed_at IS NULL;
