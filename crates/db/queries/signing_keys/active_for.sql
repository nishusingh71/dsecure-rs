-- class: platform (ix_sk_purpose; newest valid active key of a realm). params: purpose, now, now
-- hot: DATABASE.md 9.1 (xtask explain-check, ru-report)
SELECT kid, purpose, alg, public_key, wrapped_private_key, status, not_before, not_after FROM signing_keys
WHERE purpose = ? AND status = 'active' AND not_before <= ? AND (not_after IS NULL OR not_after > ?)
ORDER BY not_before DESC LIMIT 1
