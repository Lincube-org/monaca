-- Tenant schema, version 12 — one-time sign-in links (§6.1).
-- A link token is a 256-bit secret keyed by the address it was mailed to; the purpose check has to
-- admit it alongside the six-digit codes.
ALTER TABLE verification_codes
  DROP CONSTRAINT IF EXISTS verification_codes_purpose_check;
ALTER TABLE verification_codes
  ADD CONSTRAINT verification_codes_purpose_check
  CHECK (purpose IN ('sign_up','sign_in','password_reset','email_change','delete_account','sign_in_link'));
