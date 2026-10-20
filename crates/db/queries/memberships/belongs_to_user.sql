-- class: tenant (session parent check). params: tenant_id, id, user_id
SELECT 1 FROM memberships WHERE tenant_id = ? AND id = ? AND user_id = ? AND status = 'active' FOR UPDATE
