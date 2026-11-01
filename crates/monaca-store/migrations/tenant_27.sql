-- Tenant password word list — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- A password containing any listed word is refused. The list is stored lowercase and empty by
-- default, so a tenant opts in by naming the words its policy forbids.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS password_rejected_words text[] NOT NULL DEFAULT '{}';
