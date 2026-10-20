-- class: infra. params: lease_until, id, claim_token
UPDATE jobs SET lease_until = ? WHERE id = ? AND claim_token = ? AND status = 'running'
