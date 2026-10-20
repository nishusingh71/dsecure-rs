-- set 0800_audit_infra (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE jobs (
  id BINARY(16) NOT NULL, kind VARCHAR(48) NOT NULL, job_key VARCHAR(160) NOT NULL,
  tenant_id BINARY(16) NULL, payload JSON NOT NULL,  -- app cap 4 KB
  status VARCHAR(16) NOT NULL,                       -- queued|running|succeeded|failed|dead
  run_after DATETIME(6) NOT NULL,
  claimed_by VARCHAR(64) NULL, claim_token BINARY(16) NULL, lease_until DATETIME(6) NULL,
  attempts INT NOT NULL DEFAULT 0, max_attempts INT NOT NULL DEFAULT 8,
  last_error_code VARCHAR(48) NULL, created_at DATETIME(6) NOT NULL, finished_at DATETIME(6) NULL,
  PRIMARY KEY (id) /*T![clustered_index] NONCLUSTERED */,
  UNIQUE KEY ux_jobs_key (job_key),
  KEY ix_jobs_due (status, kind, run_after),
  KEY ix_jobs_lease (status, lease_until),
  KEY ix_jobs_tenant (tenant_id, kind, status)       -- per-tenant max_pending checks
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin /*T! SHARD_ROW_ID_BITS=4 */;
