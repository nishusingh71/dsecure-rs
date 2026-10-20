-- class: directory (same tx as memberships write). params: user_id, tenant_id, membership_id, status, role,
--   updated_at
INSERT INTO membership_directory (user_id, tenant_id, membership_id, status, role, updated_at)
VALUES (?, ?, ?, ?, ?, ?)
