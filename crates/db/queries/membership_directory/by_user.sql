-- class: directory (login: user -> tenants). params: user_id
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT user_id, tenant_id, membership_id, status, role FROM membership_directory
WHERE user_id = ? ORDER BY tenant_id LIMIT 200
