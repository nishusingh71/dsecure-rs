-- class: infra. params: updated_at, tenant_id
UPDATE authz_epochs SET epoch = epoch + 1, updated_at = ? WHERE tenant_id = ?
