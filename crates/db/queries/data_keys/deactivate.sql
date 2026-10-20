-- class: platform (rotation: active -> decrypt_only). params: rotated_at, kid
UPDATE data_keys SET status = 'decrypt_only', active_marker = NULL, rotated_at = ?
WHERE kid = ? AND status = 'active'
