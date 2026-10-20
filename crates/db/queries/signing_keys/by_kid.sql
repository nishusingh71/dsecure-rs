-- class: platform (verification during rotation needs old keys). params: kid
SELECT kid, purpose, alg, public_key, wrapped_private_key, status, not_before, not_after FROM signing_keys
WHERE kid = ?
