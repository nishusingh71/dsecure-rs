-- class: platform. params: id, staff_user_id, tenant_id, reason, ticket_ref, scope, opened_at, expires_at
INSERT INTO staff_access_grants (id, staff_user_id, tenant_id, reason, ticket_ref, scope, opened_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
