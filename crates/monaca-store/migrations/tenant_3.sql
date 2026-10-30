-- Tenant schema, version 3 — sessions and RP-initiated logout (docs/architecture.md §11 M1).
-- Additive: versions 1 and 2 have already run and their checksums must never change.

-- OpenID Connect RP-Initiated Logout 1.0 §2: a `post_logout_redirect_uri` is only honoured when
-- it was registered for the client. These are deliberately separate from the OAuth redirect URIs,
-- because a logout page is not an authorization response target.
ALTER TABLE clients ADD COLUMN IF NOT EXISTS post_logout_redirect_uris text[] NOT NULL DEFAULT '{}';

-- The account-wide sign-in session behind the SSO cookie. `client_id` records the application that
-- established it (the management API shows it), and `last_seen_at` drives `max_age` checks and
-- inactivity displays. `issued_at` is the authentication instant, i.e. the id_token's `auth_time`.
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS client_id uuid REFERENCES clients(id) ON DELETE SET NULL;
ALTER TABLE sessions ADD COLUMN IF NOT EXISTS last_seen_at timestamptz NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS sessions_expiry_idx ON sessions (expires_at) WHERE revoked_at IS NULL;
