-- Tenant password rejection rules — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- Two rules that Logto exposes: a password may not contain the account's own identifiers, and it
-- may not repeat a character or follow a sequence for a run of four. The user-info rule is on by
-- default; the repetition rule is off so a tenant's existing generated passwords are not refused
-- until an administrator opts in.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS password_reject_user_info boolean NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS password_reject_repetition_and_sequence boolean NOT NULL DEFAULT false;
