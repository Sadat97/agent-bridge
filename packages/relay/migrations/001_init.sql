-- Agent Bridge relay schema (DESIGN.md section 4.1).
-- Every message body is an opaque MLS message. There are no topic titles,
-- slugs, labels, or agent names anywhere in this database.

CREATE TABLE accounts (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  handle           TEXT UNIQUE NOT NULL CHECK (handle ~ '^[a-z0-9][a-z0-9_-]{1,31}$'),
  identity_pubkey  BYTEA NOT NULL CHECK (length(identity_pubkey) = 32),
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One per bridge (MVP: one per person).
CREATE TABLE devices (
  id               UUID PRIMARY KEY,                       -- chosen by the bridge; part of the signed device cert
  account_id       UUID NOT NULL REFERENCES accounts(id),
  signature_pubkey BYTEA UNIQUE NOT NULL CHECK (length(signature_pubkey) = 32),
  device_cert      BYTEA NOT NULL,                         -- self-contained, signed by the identity key (8.2)
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  revoked_at       TIMESTAMPTZ
);
CREATE INDEX devices_account ON devices (account_id);

-- Single-use login challenges for device challenge-response auth (8.4).
CREATE TABLE auth_challenges (
  nonce            BYTEA PRIMARY KEY,
  device_id        UUID NOT NULL REFERENCES devices(id),
  expires_at       TIMESTAMPTZ NOT NULL,
  used_at          TIMESTAMPTZ
);

-- One-time KeyPackages so a person can be added while their bridge is offline.
CREATE TABLE key_packages (
  id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id         UUID NOT NULL REFERENCES devices(id),
  ciphersuite       INTEGER NOT NULL,
  key_package_ref   BYTEA UNIQUE NOT NULL,                 -- RFC 9420 KeyPackageRef
  key_package       BYTEA NOT NULL,                        -- MLSMessage carrying the KeyPackage (public)
  expires_at        TIMESTAMPTZ NOT NULL,
  claimed_at        TIMESTAMPTZ,
  claimed_by        UUID REFERENCES devices(id),
  claim_approval_id TEXT,                                  -- makes a retried claim return the same KeyPackage
  created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX key_packages_unclaimed ON key_packages (device_id, created_at) WHERE claimed_at IS NULL;
CREATE INDEX key_packages_claims ON key_packages (claimed_by, claimed_at) WHERE claimed_at IS NOT NULL;

CREATE TABLE topics (
  id                 UUID PRIMARY KEY,                     -- equals the MLS group_id (16 raw bytes)
  owner_account      UUID NOT NULL REFERENCES accounts(id),
  current_epoch      BIGINT NOT NULL DEFAULT 0,            -- advanced only by an accepted commit
  last_seq           BIGINT NOT NULL DEFAULT 0,            -- per-topic, contiguous sequence counter
  pruned_through_seq BIGINT NOT NULL DEFAULT 0,            -- messages with seq <= this were deleted by retention
  created_at         TIMESTAMPTZ NOT NULL DEFAULT now(),
  closed_at          TIMESTAMPTZ
);

CREATE TYPE member_role AS ENUM ('owner', 'member');

CREATE TABLE topic_members (
  topic_id         UUID NOT NULL REFERENCES topics(id),
  device_id        UUID NOT NULL REFERENCES devices(id),
  account_id       UUID NOT NULL REFERENCES accounts(id),
  role             member_role NOT NULL DEFAULT 'member',
  joined_epoch     BIGINT NOT NULL,
  joined_seq       BIGINT NOT NULL,                        -- seq of the Add commit; the joiner reads after it
  last_fetched_seq BIGINT NOT NULL,                        -- advanced by fetches and WebSocket acks
  stale_at         TIMESTAMPTZ,                            -- fell behind retention; must be re-added
  removed_at       TIMESTAMPTZ,
  PRIMARY KEY (topic_id, device_id)
);
CREATE INDEX topic_members_device ON topic_members (device_id) WHERE removed_at IS NULL;

CREATE TYPE mls_content AS ENUM ('commit', 'application');  -- standalone proposals are rejected in MVP

CREATE TABLE mls_messages (
  topic_id         UUID NOT NULL REFERENCES topics(id),
  seq              BIGINT NOT NULL,                        -- assigned by the relay; total order for the topic
  epoch            BIGINT NOT NULL,                        -- from the MLS framing header
  content          mls_content NOT NULL,                   -- from the MLS framing header
  sender_device    UUID NOT NULL REFERENCES devices(id),   -- from relay auth
  message          BYTEA NOT NULL,                         -- MLSMessage (PrivateMessage)
  created_at       TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (topic_id, seq)
);
CREATE INDEX mls_messages_created ON mls_messages (created_at);

-- Welcome inbox: delivered to a device before it can read the topic.
CREATE TABLE welcomes (
  id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  topic_id         UUID NOT NULL REFERENCES topics(id),
  recipient_device UUID NOT NULL REFERENCES devices(id),
  commit_seq       BIGINT NOT NULL,
  welcome          BYTEA NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  expires_at       TIMESTAMPTZ NOT NULL,
  acked_at         TIMESTAMPTZ
);
CREATE INDEX welcomes_pending ON welcomes (recipient_device) WHERE acked_at IS NULL;

-- Membership changes carried by accepted commits: relay-verified, replay-protected, auditable.
CREATE TYPE membership_change AS ENUM ('add', 'remove', 'leave');

CREATE TABLE membership_changes (
  topic_id         UUID NOT NULL REFERENCES topics(id),
  approval_id      TEXT NOT NULL,
  commit_seq       BIGINT NOT NULL,
  device_id        UUID NOT NULL REFERENCES devices(id),
  change           membership_change NOT NULL,
  approval         BYTEA,                                  -- topic owner identity signature; NULL for 'leave'
  leave_seq        BIGINT,                                 -- for 'leave': seq of the member's leave message
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (topic_id, approval_id)
);

-- Metadata-only audit log. No bodies.
CREATE TABLE audit_log (
  id               BIGSERIAL PRIMARY KEY,
  account_id       UUID,
  device_id        UUID,
  topic_id         UUID,
  action           TEXT NOT NULL,
  created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
