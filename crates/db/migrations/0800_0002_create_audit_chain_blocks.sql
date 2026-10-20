-- set 0800_audit_infra (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE audit_chain_blocks (                    -- hash chain without a hot row: worker seals hourly blocks
  block_start DATETIME(6) NOT NULL, block_end DATETIME(6) NOT NULL,
  first_id BINARY(16) NULL, last_id BINARY(16) NULL, event_count BIGINT NOT NULL,
  merkle_root BINARY(32) NOT NULL, prev_block_hash BINARY(32) NOT NULL, block_hash BINARY(32) NOT NULL,
  -- blob reference = BlobRef { key, write_id, digest } (storage API, 20 Oct 2026 review); DATABASE.md had only the key
  anchored_blob_key VARCHAR(512) NULL, anchored_blob_write_id BINARY(16) NULL, anchored_blob_digest BINARY(32) NULL,
  sealed_at DATETIME(6) NOT NULL,
  PRIMARY KEY (block_start)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
