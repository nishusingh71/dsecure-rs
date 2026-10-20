-- class: platform. params: kid
SELECT kid, purpose, tenant_id, kek_ref, wrapped_dek, status FROM data_keys WHERE kid = ?
