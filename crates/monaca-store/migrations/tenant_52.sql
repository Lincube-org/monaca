-- Indexes for the management audit queries — §6.2.
--
-- The action and time indexes already exist; the tenant list additionally filters by the
-- canonical subject id and by any actor in the chain. `jsonb_path_ops` is the smallest GIN
-- operator class that answers the `@>` containment check the actor filter uses.
CREATE INDEX IF NOT EXISTS audit_events_subject_idx
  ON audit_events (subject_ref, at DESC);
CREATE INDEX IF NOT EXISTS audit_events_actor_idx
  ON audit_events USING gin (actor_chain jsonb_path_ops);
