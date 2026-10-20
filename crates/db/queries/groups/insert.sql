-- class: tenant. params: tenant_id, id, parent_group_id, name, name_norm, name_active, created_by_membership,
--   created_at
INSERT INTO `groups` (tenant_id, id, parent_group_id, name, name_norm, name_active, created_by_membership,
  created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
