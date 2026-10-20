-- class: platform (platform admin only; column grant closed_at). params: closed_at, id
UPDATE staff_access_grants SET closed_at = ? WHERE id = ? AND closed_at IS NULL
