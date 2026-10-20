-- class: platform (grant target check). params: id
SELECT 1 FROM tenants WHERE id = ? AND status = 'active'
