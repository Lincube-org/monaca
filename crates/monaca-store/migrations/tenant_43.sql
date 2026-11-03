-- Remembered versus one-shot consent, and the interaction that recorded it — §6.1.
--
-- One row per (account, client, kind) now: a remembered approval covers future silent requests,
-- while a one-shot approval is listed and revocable but never covers a later authorize request.
-- `interaction_id` names the consent screen that produced the row so a later silent authorization
-- can say which interaction it inherited. Existing rows were all remembered approvals.
ALTER TABLE consents
  ADD COLUMN IF NOT EXISTS kind text NOT NULL DEFAULT 'remember'
    CHECK (kind IN ('remember', 'one_shot')),
  ADD COLUMN IF NOT EXISTS interaction_id text;

ALTER TABLE consents DROP CONSTRAINT IF EXISTS consents_pkey;
ALTER TABLE consents ADD PRIMARY KEY (account_id, client_id, kind);
