-- class: infra (session revoke is authz-affecting, DATABASE.md 4.4; staff sessions have no tenant = 0 rows).
-- params: updated_at, session_id
UPDATE authz_epochs SET epoch = epoch + 1, updated_at = ?
WHERE tenant_id = (SELECT s.tenant_id FROM sessions s WHERE s.id = ?)
