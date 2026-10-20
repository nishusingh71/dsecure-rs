-- class: identity (parent check; locking read = latest committed row, parent cannot be archived mid-tx). params: id
SELECT 1 FROM users WHERE id = ? AND erased_at IS NULL FOR UPDATE
