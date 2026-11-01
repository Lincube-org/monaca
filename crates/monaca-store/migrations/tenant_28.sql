-- Application-level custom CSS — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- An application may carry its own stylesheet; the hosted page prefers it over the tenant's, so
-- one product's sign-in page can differ from the tenant's default look. Nullable: no value falls
-- back to the tenant branding.

ALTER TABLE clients
  ADD COLUMN IF NOT EXISTS custom_css text;
