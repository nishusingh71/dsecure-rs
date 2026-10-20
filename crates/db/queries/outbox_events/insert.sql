-- class: infra. params: id, tenant_id, event_type, aggregate_type, aggregate_id, payload, created_at
INSERT INTO outbox_events (id, tenant_id, event_type, aggregate_type, aggregate_id, payload, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?)
