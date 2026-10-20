-- set 0150_keys (docs/DATABASE.md). One DDL per file (§11.1).
CREATE TABLE signing_keys (
  kid VARCHAR(48) NOT NULL,
  purpose VARCHAR(24) NOT NULL,                      -- report_certificate|jwt_member|jwt_device|jwt_staff|jwt_cleaner|offline_license|legacy_rsa_verify
  alg VARCHAR(16) NOT NULL,                          -- Ed25519|ES256|RS256 (legacy verify only)
  public_key VARBINARY(1024) NOT NULL,
  private_key_ref VARCHAR(255) NULL, wrapped_private_key VARBINARY(1024) NULL,
  status VARCHAR(16) NOT NULL,                       -- active|verify_only|retired
  not_before DATETIME(6) NOT NULL, not_after DATETIME(6) NULL, created_at DATETIME(6) NOT NULL,
  PRIMARY KEY (kid),
  KEY ix_sk_purpose (purpose, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin;
