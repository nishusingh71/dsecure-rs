-- class: tenant. params: tenant_id, id, user_id, role, role_rank, kind, status, parent_membership_id,
--   department_id, display_name_enc, created_by, created_at, updated_at
INSERT INTO memberships (tenant_id, id, user_id, role, role_rank, kind, status, parent_membership_id,
  department_id, display_name_enc, created_by, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
