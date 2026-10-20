-- set 0850_retention_ttl. TiDB TTL purge for an unbounded infra table: published events; unpublished (NULL) never expire.
-- PENDING OWNER DECISION D-56 (retention = deletion): shipped with TTL_ENABLE = 'OFF'. After the owner
-- approves this data class, a follow-up migration runs:  ALTER TABLE outbox_events TTL_ENABLE = 'ON'
-- The TTL clause is a TiDB executable comment: TiDB applies it, MySQL ignores it (MySQL dev/CI just
-- grows, no purge). The COMMENT option keeps the statement non-empty on MySQL. One DDL per file.
-- No TTL_JOB_INTERVAL: TiDB Serverless runs TTL jobs on its own schedule and rejects that option
-- (error 20001, v8.5.3); xtask migrate-lint forbids it.
ALTER TABLE outbox_events COMMENT = 'ttl published_at + 7d (D-56 pending)'
  /*T! TTL = `published_at` + INTERVAL 7 DAY TTL_ENABLE = 'OFF' */;
