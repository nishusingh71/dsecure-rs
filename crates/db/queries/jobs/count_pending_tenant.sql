-- class: infra (ix_jobs_tenant; locking read under the tenant_counters mutex). params: tenant_id, kind
SELECT COUNT(*) AS n FROM jobs WHERE tenant_id = ? AND kind = ? AND status IN ('queued', 'running') FOR UPDATE
