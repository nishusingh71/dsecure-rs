-- set 0870_epoch_poll_index (ru-report: changed_since was a TableFullScan on TiDB). Compound index for
-- the poller's keyset (updated_at, tenant_id); a new forward file, existing migrations untouched.
-- One DDL per file.
ALTER TABLE authz_epochs ADD INDEX ix_authz_epochs_poll (updated_at, tenant_id);
