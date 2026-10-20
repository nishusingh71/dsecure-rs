-- class: platform (approver check, latest row, locked). params: user_id
SELECT user_id, role, revoked_at FROM platform_staff WHERE user_id = ? FOR UPDATE
