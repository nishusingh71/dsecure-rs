-- set 0800_audit_infra (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE outbox_events (
  id BINARY(16) NOT NULL, tenant_id BINARY(16) NULL, event_type VARCHAR(64) NOT NULL,
  aggregate_type VARCHAR(32) NOT NULL, aggregate_id BINARY(16) NOT NULL,
  payload JSON NOT NULL,                             -- ids only, no PII, app cap 4 KB
  created_at DATETIME(6) NOT NULL, published_at DATETIME(6) NULL, attempts INT NOT NULL DEFAULT 0,
  claimed_by VARCHAR(64) NULL, lease_until DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  KEY ix_outbox_pending (published_at, created_at),  -- published_at IS NULL range first
  KEY ix_outbox_tenant_pending (tenant_id, published_at)  -- per-tenant backlog cap (F12; not in DATABASE.md v3)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;
