-- Tenant MFA policy — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
-- `mfa_enabled` keeps the current behaviour (accounts with a second factor are challenged) and
-- `mfa_policy = 'mandatory'` additionally makes a first-time sign-in enroll one. The default is
-- `user_controlled` so a tenant that never touches this row behaves exactly as before.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS mfa_enabled boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS mfa_policy text NOT NULL DEFAULT 'user_controlled'
    CHECK (mfa_policy IN ('user_controlled', 'mandatory'));
