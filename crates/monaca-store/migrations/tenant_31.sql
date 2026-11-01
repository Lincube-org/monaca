-- The tenant's trusted-device policy for MFA — docs/contracts/m0.md §6.1 sign-in experience.
--
-- Logto lets a tenant switch remembered browsers off and choose a trust duration from 1 to 365
-- days. The switch defaults to on here because monaca already offered remembered browsers; the
-- duration defaults to Logto's 30 days.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS mfa_trusted_devices_enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS mfa_trusted_device_ttl_days integer NOT NULL DEFAULT 30
    CHECK (mfa_trusted_device_ttl_days BETWEEN 1 AND 365);
