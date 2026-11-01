-- Tenant custom CSS for the hosted page — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- The tenant's own CSS is appended after the built-in sheet, so it can override the look without a
-- rebuilt UI. The column is nullable: an unset value keeps the built-in stylesheet.

ALTER TABLE branding
  ADD COLUMN IF NOT EXISTS custom_css text;
