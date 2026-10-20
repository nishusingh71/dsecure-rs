-- class: infra (append-only; app user has no UPDATE/DELETE on audit tables in prod grants). params: id, occurred_at,
--   tenant_id, actor_kind, actor_id, staff_grant_id, action, outcome, target_type, target_id, request_id,
--   ip_hmac, metadata, row_hash
INSERT INTO audit_events (id, occurred_at, tenant_id, actor_kind, actor_id, staff_grant_id, action, outcome,
  target_type, target_id, request_id, ip_hmac, metadata, row_hash)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
