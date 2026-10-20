-- class: platform. params: purpose, scope_key
SELECT kid, kek_ref, wrapped_dek FROM data_keys WHERE purpose = ? AND scope_key = ? AND active_marker = 'Y'
