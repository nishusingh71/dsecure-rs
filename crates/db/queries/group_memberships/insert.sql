-- class: tenant. params: tenant_id, group_id, membership_id, added_by, added_at
INSERT INTO group_memberships (tenant_id, group_id, membership_id, added_by, added_at) VALUES (?, ?, ?, ?, ?)
