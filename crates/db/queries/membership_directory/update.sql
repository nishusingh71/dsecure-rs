-- class: directory. params: status, role, updated_at, user_id, tenant_id
UPDATE membership_directory SET status = ?, role = ?, updated_at = ? WHERE user_id = ? AND tenant_id = ?
