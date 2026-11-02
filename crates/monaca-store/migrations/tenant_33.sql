-- Branding, extended — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- Logto's branding carries a dark-mode logo, a favicon and the tenant's own contact links. All are
-- optional: an unset value keeps the built-in look. The hosted page picks the dark logo through a
-- `prefers-color-scheme` media query and writes the favicon into the document head.

ALTER TABLE branding
  ADD COLUMN IF NOT EXISTS dark_logo_url text,
  ADD COLUMN IF NOT EXISTS favicon_url text,
  ADD COLUMN IF NOT EXISTS support_email text,
  ADD COLUMN IF NOT EXISTS website_url text;
