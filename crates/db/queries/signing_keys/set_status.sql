-- class: platform (platform-admin; column grant status). params: status, kid
UPDATE signing_keys SET status = ? WHERE kid = ? AND status <> 'retired'
