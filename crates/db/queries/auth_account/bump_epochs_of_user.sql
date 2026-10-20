-- class: infra (a user status change affects every tenant of the user; membership_directory PK prefix user_id).
-- params: updated_at, user_id
UPDATE authz_epochs SET epoch = epoch + 1, updated_at = ?
WHERE tenant_id IN (SELECT d.tenant_id FROM membership_directory d WHERE d.user_id = ?)
