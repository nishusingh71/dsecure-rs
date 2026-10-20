-- set 0800_audit_infra (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE audit_events (                          -- append-only (no UPDATE/DELETE grants for app/worker)
  id BINARY(16) NOT NULL, occurred_at DATETIME(6) NOT NULL,
  tenant_id BINARY(16) NULL,
  actor_kind VARCHAR(16) NOT NULL,                   -- member|device|staff|cleaner|system|anonymous
  actor_id BINARY(16) NULL, staff_grant_id BINARY(16) NULL,
  action VARCHAR(64) NOT NULL, outcome VARCHAR(16) NOT NULL,       -- success|denied|failed
  target_type VARCHAR(32) NULL, target_id BINARY(16) NULL,
  request_id BINARY(16) NULL, ip_hmac BINARY(32) NULL,
  metadata JSON NULL,                                -- typed, no PII, app cap 2 KB
  row_hash BINARY(32) NOT NULL,                      -- SHA-256(canonical row); chained in audit_chain_blocks
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  KEY ix_ae_tenant (tenant_id, id),
  KEY ix_ae_target (tenant_id, target_type, target_id, id),
  KEY ix_ae_time (occurred_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;
