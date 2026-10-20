-- class: infra (ix_ae_time). params: before
SELECT id FROM audit_events WHERE occurred_at < ? LIMIT 1
