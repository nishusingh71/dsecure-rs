-- class: identity (principal state loader, ONE statement: sessions PK point get plus tenant-leading point gets
--   on memberships, membership_capabilities, group_memberships, group_admin_grants, tenant_features; tenants and
--   authz_epochs by PK). Tenant and membership come from a verified access token (auth crate only).
-- params: tenant_id (gm), tenant_id (gm count), tenant_id (ga), tenant_id (ga count), tenant_id (tf),
--   tenant_id (m), tenant_id (c), session_id, user_id, tenant_id (s), membership_id
SELECT s.id AS session_id, s.principal_kind, s.client_kind, s.expires_at AS session_expires_at,
       s.revoked_at AS session_revoked_at, s.mfa_at,
       s.created_at AS session_created_at, s.last_seen_at AS session_last_seen_at,
       u.status AS user_status, u.email_verified_at, u.authz_version AS user_authz_version, u.tokens_valid_after,
       m.tenant_id, m.id AS membership_id, m.role, m.status AS membership_status,
       m.authz_version AS membership_authz_version,
       t.status AS tenant_status,
       e.epoch,
       c.can_view_reports, c.can_manage_machines, c.can_assign_licenses, c.max_machines,
       (SELECT GROUP_CONCAT(HEX(gm.group_id) ORDER BY gm.group_id SEPARATOR ',') FROM group_memberships gm
          WHERE gm.tenant_id = ? AND gm.membership_id = m.id) AS group_ids,
       (SELECT COUNT(*) FROM group_memberships gm2
          WHERE gm2.tenant_id = ? AND gm2.membership_id = m.id) AS group_count,
       (SELECT GROUP_CONCAT(HEX(ga.group_id) ORDER BY ga.group_id SEPARATOR ',') FROM group_admin_grants ga
          WHERE ga.tenant_id = ? AND ga.membership_id = m.id) AS ga_group_ids,
       (SELECT COUNT(*) FROM group_admin_grants ga2
          WHERE ga2.tenant_id = ? AND ga2.membership_id = m.id) AS ga_group_count,
       (SELECT GROUP_CONCAT(tf.feature ORDER BY tf.feature SEPARATOR ',') FROM tenant_features tf
          WHERE tf.tenant_id = ? AND tf.enabled = TRUE) AS features
FROM sessions s
JOIN users u ON u.id = s.user_id
JOIN memberships m ON m.tenant_id = ? AND m.id = s.membership_id AND m.user_id = s.user_id
JOIN tenants t ON t.id = m.tenant_id
LEFT JOIN authz_epochs e ON e.tenant_id = m.tenant_id
LEFT JOIN membership_capabilities c ON c.tenant_id = ? AND c.membership_id = m.id
WHERE s.id = ? AND s.user_id = ? AND s.tenant_id = ? AND s.membership_id = ?
