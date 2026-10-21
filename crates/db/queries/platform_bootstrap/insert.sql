-- class: platform (first-run singleton marker, review N2; duplicate PRIMARY = already bootstrapped).
-- params: user_id, created_at
INSERT INTO platform_bootstrap (id, user_id, created_at) VALUES (1, ?, ?)
