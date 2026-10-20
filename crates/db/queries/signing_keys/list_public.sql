-- class: platform (JWKS; catalogue table < 1k rows). params: now
SELECT kid, purpose, alg, public_key, status, not_before, not_after FROM signing_keys
WHERE status IN ('active', 'verify_only') AND (not_after IS NULL OR not_after > ?)
ORDER BY purpose, not_before LIMIT 200
