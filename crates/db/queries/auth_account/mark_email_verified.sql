-- class: identity (email verification flow). params: email_verified_at, verification_source, updated_at, id
UPDATE users SET email_verified_at = ?, verification_source = ?, updated_at = ?, version = version + 1
WHERE id = ? AND erased_at IS NULL
