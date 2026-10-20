-- class: tenant (device principal state, ONE statement: device_credentials tenant-leading PK point get,
--   operator membership, capabilities and groups by tenant-leading keys; tenants, authz_epochs, users by PK).
-- params: tenant_id (gm), tenant_id (gm count), tenant_id (ga), tenant_id (ga count), tenant_id (tf),
--   tenant_id (m), tenant_id (c), tenant_id (dc), credential_id, device_id
SELECT dc.tenant_id, dc.id AS credential_id, dc.device_id, dc.operator_membership_id, dc.product_code, dc.scopes,
       dc.revoked_at AS credential_revoked_at,
       t.status AS tenant_status,
       e.epoch,
       m.role, m.status AS membership_status, m.authz_version AS membership_authz_version,
       u.status AS user_status, u.email_verified_at,
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
FROM device_credentials dc
JOIN tenants t ON t.id = dc.tenant_id
JOIN memberships m ON m.tenant_id = ? AND m.id = dc.operator_membership_id
JOIN users u ON u.id = m.user_id
LEFT JOIN authz_epochs e ON e.tenant_id = dc.tenant_id
LEFT JOIN membership_capabilities c ON c.tenant_id = ? AND c.membership_id = m.id
WHERE dc.tenant_id = ? AND dc.id = ? AND dc.device_id = ?
