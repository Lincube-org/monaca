-- Tenant session and refresh-token lifetimes — docs/contracts/m0.md §6.1 sign-in experience, §6.2.
--
-- The values override the process-wide `MONACA_SESSION_TTL_SECS` / `MONACA_REFRESH_TOKEN_TTL_SECS`
-- defaults for this tenant. Bounds keep an administrator from configuring a session that expires
-- before the sign-in completes or one that outlives a year.

ALTER TABLE sign_in_experience
  ADD COLUMN IF NOT EXISTS session_ttl_secs integer NOT NULL DEFAULT 2592000
    CHECK (session_ttl_secs BETWEEN 3600 AND 7776000),
  ADD COLUMN IF NOT EXISTS refresh_token_ttl_secs integer NOT NULL DEFAULT 2592000
    CHECK (refresh_token_ttl_secs BETWEEN 3600 AND 31536000);
