-- Remove the unused `phone` identifier kind from databases created before tenant.sql excluded it.
--
-- `account_identifiers` accepted `('email','phone','username')` from the first tenant migration, but
-- no phone identifier flow was ever implemented: nothing writes `kind='phone'` and no endpoint
-- accepts a phone number. Leaving it in the check made the schema look like it supported one. The
-- guard turns a hypothetical row into a loud migration failure instead of deleting data.

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM account_identifiers WHERE kind = 'phone') THEN
    RAISE EXCEPTION 'account_identifiers has phone rows; no phone flow exists, resolve them manually before tenant_49';
  END IF;
END $$;

ALTER TABLE account_identifiers
  DROP CONSTRAINT IF EXISTS account_identifiers_kind_check;

ALTER TABLE account_identifiers
  ADD CONSTRAINT account_identifiers_kind_check
  CHECK (kind IN ('email','username'));
