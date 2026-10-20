-- class: identity. params: id, user_id, tenant_id, membership_id, principal_kind, client_kind, product_code,
--   device_label, created_at, last_seen_at, expires_at
INSERT INTO sessions (id, user_id, tenant_id, membership_id, principal_kind, client_kind, product_code,
  device_label, created_at, last_seen_at, expires_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
