-- class: identity (staff principal state; sessions PK, users PK, platform_staff PK).
-- params: session_id, user_id
SELECT s.id AS session_id, s.principal_kind, s.client_kind, s.expires_at AS session_expires_at,
       s.revoked_at AS session_revoked_at, s.mfa_at,
       s.created_at AS session_created_at, s.last_seen_at AS session_last_seen_at,
       u.status AS user_status, u.email_verified_at, u.authz_version AS user_authz_version, u.tokens_valid_after,
       p.role AS staff_role, p.revoked_at AS staff_revoked_at
FROM sessions s
JOIN users u ON u.id = s.user_id
JOIN platform_staff p ON p.user_id = s.user_id
WHERE s.id = ? AND s.user_id = ? AND s.tenant_id IS NULL AND s.membership_id IS NULL
