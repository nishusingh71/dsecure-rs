-- class: platform. ux_dk_active (purpose, scope_key, active_marker) = one active key per purpose+scope.
-- params: kid, purpose, tenant_id, scope_key, kek_ref, wrapped_dek, created_at
INSERT INTO data_keys (kid, purpose, tenant_id, scope_key, kek_ref, wrapped_dek, status, active_marker,
  created_at)
VALUES (?, ?, ?, ?, ?, ?, 'active', 'Y', ?)
