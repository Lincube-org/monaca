-- Usernames as a second sign-in identifier (§5.6, §6.1).
--
-- `account_identifiers` is case-sensitive by default, but a person typing `Alice` expects to reach
-- the account that registered `alice`. The index makes the username namespace case-insensitive, and
-- partial so the email rows keep their own uniqueness rule.
CREATE UNIQUE INDEX IF NOT EXISTS account_identifiers_username_idx
    ON account_identifiers (lower(value)) WHERE kind = 'username';
