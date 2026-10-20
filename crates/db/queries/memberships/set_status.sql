-- class: tenant. params: status, disabled_at, updated_at, tenant_id, id
UPDATE memberships SET status = ?, disabled_at = ?, authz_version = authz_version + 1, version = version + 1,
  updated_at = ?
WHERE tenant_id = ? AND id = ?
