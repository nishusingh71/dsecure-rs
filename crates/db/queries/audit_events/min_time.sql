-- class: infra (ix_ae_time). params: none
SELECT MIN(occurred_at) AS t FROM audit_events
