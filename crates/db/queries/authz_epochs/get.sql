-- class: infra. params: tenant_id
SELECT tenant_id, epoch, updated_at FROM authz_epochs WHERE tenant_id = ?
