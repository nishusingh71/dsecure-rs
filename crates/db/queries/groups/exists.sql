-- class: tenant (parent check; locking read = latest committed row, parent cannot be archived mid-tx). params: tenant_id, id
SELECT 1 FROM `groups` WHERE tenant_id = ? AND id = ? AND archived_at IS NULL FOR UPDATE
