-- class: tenant. Read under the tenant mutex (DATABASE.md 4.3). params: tenant_id
SELECT id FROM memberships WHERE tenant_id = ? AND status = 'active' AND role_rank = 100 LIMIT 2 FOR UPDATE
