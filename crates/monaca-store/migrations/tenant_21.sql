-- Tenant password policy — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- `password_min_length` is the shortest password every entrance accepts: self-service sign-up,
-- password reset, the account centre and the management account create. The default is the
-- contract's historical minimum, so a tenant that never touches this row behaves exactly as before.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS password_min_length integer NOT NULL DEFAULT 8
    CHECK (password_min_length BETWEEN 8 AND 64);
