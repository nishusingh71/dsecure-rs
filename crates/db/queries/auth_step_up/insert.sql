-- class: identity (step-up proof: single use, bound to session + action + target; ux_sut_hash).
-- params: id, session_id, action, target_id, token_hash, expires_at
INSERT INTO step_up_tokens (id, session_id, action, target_id, token_hash, expires_at)
VALUES (?, ?, ?, ?, ?, ?)
