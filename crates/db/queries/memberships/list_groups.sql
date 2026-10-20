-- class: tenant (Visibility::Groups, rank < 60). The GROUP_IDS marker is expanded to `?, ?, ...`
-- (placeholders only, never values; 1..=200). params: tenant_id, after_id, group_id..., limit
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT m.tenant_id, m.id, m.user_id, m.role, m.role_rank, m.kind, m.status, m.parent_membership_id,
       m.department_id, m.authz_version, m.version, m.created_at, m.updated_at
FROM memberships m
WHERE m.tenant_id = ? AND m.id < ? AND m.role_rank < 60
  AND EXISTS (SELECT 1 FROM group_memberships gm
              WHERE gm.tenant_id = m.tenant_id AND gm.membership_id = m.id AND gm.group_id IN (/*GROUP_IDS*/))
ORDER BY m.id DESC LIMIT ?
