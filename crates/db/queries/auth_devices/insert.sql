-- class: tenant (device enrolment). params: tenant_id, id, device_id, operator_membership_id, product_code, scopes,
--   secret_hash, created_at
INSERT INTO device_credentials (tenant_id, id, device_id, operator_membership_id, product_code, scopes,
  secret_hash, created_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)
