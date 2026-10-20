-- class: identity (authz-affecting: authz_version + 1; tokens_valid_after only moves forward).
-- params: status, tokens_valid_after, updated_at, id
UPDATE users SET status = ?, authz_version = authz_version + 1,
  tokens_valid_after = COALESCE(?, tokens_valid_after), updated_at = ?, version = version + 1
WHERE id = ? AND erased_at IS NULL
