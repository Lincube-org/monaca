-- Tenant schema, version 11 — account deletion codes (§6.1).
-- The purpose check predates self-service deletion, so it has to admit the fifth purpose.
ALTER TABLE verification_codes
  DROP CONSTRAINT IF EXISTS verification_codes_purpose_check;
ALTER TABLE verification_codes
  ADD CONSTRAINT verification_codes_purpose_check
  CHECK (purpose IN ('sign_up','sign_in','password_reset','email_change','delete_account'));
