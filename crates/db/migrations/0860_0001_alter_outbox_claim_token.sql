-- set 0860_outbox_claim_token (review R7). Per-claim lease token for the outbox relay, like jobs.claim_token.
-- Forward-only: a new file, never an edit of 0800_0003 (applied migrations are immutable). One DDL per file.
ALTER TABLE outbox_events ADD COLUMN claim_token BINARY(16) NULL;
