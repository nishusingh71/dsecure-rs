-- class: tenant (Visibility::Groups point check). GROUP_IDS marker expanded as above.
-- params: tenant_id, membership_id, group_id...
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT 1 FROM memberships m
WHERE m.tenant_id = ? AND m.id = ? AND m.role_rank < 60
  AND EXISTS (SELECT 1 FROM group_memberships gm
              WHERE gm.tenant_id = m.tenant_id AND gm.membership_id = m.id AND gm.group_id IN (/*GROUP_IDS*/))
