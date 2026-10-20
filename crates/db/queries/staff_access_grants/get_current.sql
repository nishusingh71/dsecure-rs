-- class: platform. NON-locking read (review: the app user has SELECT only on staff tables; FOR UPDATE
-- needs UPDATE, FOR SHARE is a no-op/error on TiDB per DATABASE.md 1.1). As the first read of the tx it
-- sees the latest committed row; validity is re-checked by verify_inner. params: id
SELECT g.id, g.staff_user_id, g.tenant_id, g.scope, g.expires_at, g.closed_at, p.role, p.revoked_at
FROM staff_access_grants g JOIN platform_staff p ON p.user_id = g.staff_user_id
WHERE g.id = ?
