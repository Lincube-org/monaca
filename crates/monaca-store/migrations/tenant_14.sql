-- The hosted sign-in switches — docs/contracts/m0.md §6.1 sign-in experience.
-- One row per tenant schema; the migration seeds it so a read never has to create it.

CREATE TABLE IF NOT EXISTS sign_in_experience (
  singleton                  boolean NOT NULL PRIMARY KEY DEFAULT true CHECK (singleton),
  sign_up_enabled            boolean NOT NULL DEFAULT true,
  password_sign_in_enabled   boolean NOT NULL DEFAULT true,
  email_code_sign_in_enabled boolean NOT NULL DEFAULT true,
  updated_at                 timestamptz NOT NULL DEFAULT now()
);

INSERT INTO sign_in_experience (singleton) VALUES (true) ON CONFLICT DO NOTHING;
