-- Client address for the per-client outstanding-challenge cap.
-- Expired rows are deleted on the auth path; this column is metadata only.

ALTER TABLE auth_challenges
  ADD COLUMN client_ip TEXT;
