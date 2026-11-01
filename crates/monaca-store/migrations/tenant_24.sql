-- Tenant password complexity — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- The policy now also demands a minimum number of character classes among lowercase letters,
-- uppercase letters, digits and symbols. The default of 1 keeps the previous behaviour, where
-- any password at `password_min_length` was accepted.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS password_min_character_types integer NOT NULL DEFAULT 1
    CHECK (password_min_character_types BETWEEN 1 AND 4);
