-- The account's avatar — docs/contracts/m0.md §5.6, §6.1 and §6.2.
--
-- Logto's account profile carries an avatar URL that applications read as the OIDC `picture`
-- claim. Nullable: an unset or cleared avatar leaves the page's built-in mark in place.

ALTER TABLE accounts
  ADD COLUMN IF NOT EXISTS avatar_url text;
