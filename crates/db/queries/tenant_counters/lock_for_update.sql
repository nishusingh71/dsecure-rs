-- class: tenant (locked after the quota row: lock order 1.2). params: tenant_id
SELECT tenant_id, members_active, groups_active, departments_active
FROM tenant_counters WHERE tenant_id = ? FOR UPDATE
