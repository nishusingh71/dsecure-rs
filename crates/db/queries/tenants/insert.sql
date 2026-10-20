-- class: platform. params: tenant_id, kind, display_name_enc, created_at, updated_at
INSERT INTO tenants (id, kind, display_name_enc, status, data_region, created_at, updated_at, version)
VALUES (?, ?, ?, 'active', 'default', ?, ?, 1)
