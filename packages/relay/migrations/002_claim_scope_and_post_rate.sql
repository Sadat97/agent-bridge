-- Scope a KeyPackage claim to the topic whose approval consumed it.
-- approval_id is unique per topic (membership_changes), so the claim must be too.
-- NULL claim columns are the unclaimed rows; Postgres treats those NULLs as distinct.

ALTER TABLE key_packages
  ADD COLUMN claim_topic_id UUID REFERENCES topics(id);

ALTER TABLE key_packages
  ADD CONSTRAINT key_packages_claim_pair
  CHECK ((claim_topic_id IS NULL) = (claim_approval_id IS NULL));

CREATE UNIQUE INDEX key_packages_claim_topic_approval
  ON key_packages (claim_topic_id, claim_approval_id);

-- Supports the per-device post rate limit (rolling minute).
CREATE INDEX mls_messages_sender_created ON mls_messages (sender_device, created_at);
