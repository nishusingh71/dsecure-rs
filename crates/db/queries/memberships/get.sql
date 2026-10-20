-- class: tenant. params: tenant_id, id
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT m.tenant_id, m.id, m.user_id, m.role, m.role_rank, m.kind, m.status, m.parent_membership_id,
       m.department_id, m.authz_version, m.version, m.created_at, m.updated_at
FROM memberships m WHERE m.tenant_id = ? AND m.id = ?
