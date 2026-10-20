-- class: infra. params: id, claim_token
SELECT id, tenant_id, event_type, aggregate_type, aggregate_id, payload, created_at, attempts, lease_until
FROM outbox_events WHERE id = ? AND claim_token = ? AND published_at IS NULL
