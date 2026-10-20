-- class: tenant (duplicate-key disambiguation, engine independent). params: tenant_id, user_id
SELECT 1 FROM memberships WHERE tenant_id = ? AND user_id = ?
