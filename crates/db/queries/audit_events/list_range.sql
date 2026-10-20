-- class: infra (ix_ae_time range, keyset on (occurred_at, id); chain order). params: range_start, range_end,
--   after_occurred_at, after_id, limit
SELECT id, occurred_at, tenant_id, actor_kind, actor_id, staff_grant_id, action, outcome, target_type, target_id,
       request_id, ip_hmac, metadata, row_hash
FROM audit_events
WHERE occurred_at >= ? AND occurred_at < ? AND (occurred_at, id) > (?, ?)
ORDER BY occurred_at, id LIMIT ?
