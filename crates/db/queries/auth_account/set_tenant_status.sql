-- class: platform (tenant suspend or reactivate; caller bumps the epoch in the same tx). params: status, updated_at, id
UPDATE tenants SET status = ?, updated_at = ?, version = version + 1 WHERE id = ?
