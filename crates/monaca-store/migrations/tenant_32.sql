-- The tenant's enterprise-SSO switch — docs/contracts/m0.md §6.1 sign-in experience.
--
-- Logto exposes `singleSignOnEnabled` in the sign-in experience. Off hides the domain-based SSO
-- lookup and refuses the provider redirect, so a connector can stay configured but be unreachable.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS single_sign_on_enabled boolean NOT NULL DEFAULT true;
