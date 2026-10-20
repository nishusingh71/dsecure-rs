-- class: tenant. authz_version bump in the same statement (4.3). params: role, role_rank, updated_at,
--   tenant_id, id
UPDATE memberships SET role = ?, role_rank = ?, authz_version = authz_version + 1, version = version + 1,
  updated_at = ?
WHERE tenant_id = ? AND id = ?
