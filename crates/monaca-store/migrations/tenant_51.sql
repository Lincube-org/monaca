-- Session-bound refresh tokens and administrative account deletion — §6.1/§6.2.
--
-- A refresh token now remembers the SSO session that created it, so revoking one session can
-- revoke exactly its renewal tokens instead of either nothing (the old behaviour) or every token
-- of the account. Existing rows stay NULL: they predate session-bound revocation and expire on
-- their normal schedule.
ALTER TABLE refresh_tokens ADD COLUMN IF NOT EXISTS session_id uuid;
CREATE INDEX IF NOT EXISTS refresh_tokens_session_idx
  ON refresh_tokens (session_id) WHERE revoked_at IS NULL;
