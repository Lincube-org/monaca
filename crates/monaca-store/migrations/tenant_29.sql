-- The tenant's passkey sign-in switch — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- Logto exposes passwordless passkey sign-in as a tenant-level method. It is on by default so a
-- tenant that already offers passkeys keeps that path; switching it off hides the hosted option
-- and refuses the passkey endpoints with 403.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS passkey_sign_in_enabled boolean NOT NULL DEFAULT true;
