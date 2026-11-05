-- Tenant lifecycle: archive joins provisioning, active and suspended as a control-plane state.
--
-- `archived` is terminal for serving (the tenant is not addressable) but not for data: the tenant
-- database and its audit chains are retained, and `monaca-server tenant resume` may reactivate it.
-- There is no automatic deletion in this migration or in the CLI.

ALTER TABLE tenants
  DROP CONSTRAINT IF EXISTS tenants_state_check;

ALTER TABLE tenants
  ADD CONSTRAINT tenants_state_check
  CHECK (state IN ('provisioning','active','suspended','archived'));
