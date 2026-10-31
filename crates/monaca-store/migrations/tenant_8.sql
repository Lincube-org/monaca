-- Tenant schema, version 8 — email change codes (§6.1).
-- The purpose check predates the account centre's email change, so it has to be widened to admit
-- the fourth purpose. Postgres has no `ALTER CONSTRAINT` for CHECK constraints, so the old one is
-- dropped and the same constraint name is added back with the extra value.
ALTER TABLE verification_codes
  DROP CONSTRAINT IF EXISTS verification_codes_purpose_check;
ALTER TABLE verification_codes
  ADD CONSTRAINT verification_codes_purpose_check
  CHECK (purpose IN ('sign_up','sign_in','password_reset','email_change'));
