//! JWT keys from `signing_keys` (db::repo::signing_keys): signer for the configured kids
//! (`JWT_SIGNING_KID_MEMBER` / `JWT_SIGNING_KID_STAFF`), verify set = every public JWT key that is
//! active or verify-only (rotation overlap), and the JWKS document.
//!
//! - Fail closed: a configured kid that is missing, not `active`, of the wrong realm, not ES256, or
//!   whose private key does not decrypt = startup error.
//! - Dev/test only: missing keys are created first (`dev_bootstrap`, migrator pool, audited).
//! - Keys are loaded once at startup; a rotation becomes visible after a restart (Phase 0).

use std::sync::Arc;

use auth::{Es256Issuer, KeySet, Realm};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use crypto::{Es256Signer, FieldEncryptor, SigAlg, Signer};
use db::repo::signing_keys::{self, NewSigningKey, PublicKeyInfo, SigningKeyStatus, SigningRealm};
use time::OffsetDateTime;
use zeroize::Zeroizing;

/// Value-free startup problem.
#[derive(Debug, thiserror::Error)]
pub enum JwtKeyError {
    #[error("signing key `{0}` not found")]
    Missing(&'static str),
    #[error("signing key `{0}` is not usable (status / realm / algorithm)")]
    Unusable(&'static str),
    #[error("signing key `{0}` private key could not be decrypted")]
    Decrypt(&'static str),
    #[error("jwt key set refused: {0}")]
    KeySet(&'static str),
    #[error("database: {0}")]
    Db(#[from] db::DbError),
}

const fn auth_realm(r: SigningRealm) -> Option<Realm> {
    match r {
        SigningRealm::JwtMember | SigningRealm::JwtDevice => Some(Realm::Member),
        SigningRealm::JwtStaff => Some(Realm::Staff),
        SigningRealm::JwtCleaner => Some(Realm::Cleaner),
        SigningRealm::ReportCertificate | SigningRealm::OfflineLicense => None,
    }
}

fn now_micros() -> OffsetDateTime {
    let t = OffsetDateTime::now_utc();
    t.replace_nanosecond(t.nanosecond() / 1000 * 1000)
        .unwrap_or(t)
}

/// DEV/TEST: create ES256 member + staff keys with the configured kids if their realm has none.
///
/// # Errors
/// Key generation, audit hashing, db errors (`Config` outside dev/test).
pub async fn dev_bootstrap(
    db: &db::Db,
    env: config::Environment,
    enc: &dyn FieldEncryptor,
    member_kid: &str,
    staff_kid: &str,
) -> Result<usize, JwtKeyError> {
    let now = now_micros();
    let mut keys = Vec::with_capacity(2);
    for (kid, realm) in [
        (member_kid, SigningRealm::JwtMember),
        (staff_kid, SigningRealm::JwtStaff),
    ] {
        let pk = Es256Signer::generate_pkcs8().map_err(|_| JwtKeyError::KeySet("keygen"))?;
        let signer =
            Es256Signer::from_pkcs8(kid, &pk).map_err(|_| JwtKeyError::KeySet("keygen"))?;
        keys.push(NewSigningKey {
            kid: kid.to_owned(),
            alg: SigAlg::Es256,
            realm,
            private_key: Zeroizing::new(pk.to_vec()),
            public_key: signer.public_key().to_vec(),
            not_before: now - time::Duration::minutes(1),
            expires_at: None,
        });
    }
    let mut audit = db::repo::audit::AuditRowRecord {
        id: uuid::Uuid::now_v7(),
        occurred_at: now,
        tenant_id: None,
        actor_kind: "system".into(),
        actor_id: None,
        staff_grant_id: None,
        action: "keys.dev_bootstrap".into(),
        outcome: "success".into(),
        target_type: Some("signing_keys".into()),
        target_id: None,
        request_id: None,
        ip_hmac: None,
        metadata: None,
        row_hash: Vec::new(),
    };
    audit.row_hash = audit::chain::compute_row_hash(&audit)
        .map_err(|_| JwtKeyError::KeySet("audit hash"))?
        .to_vec();
    Ok(signing_keys::dev_bootstrap(db, env, enc, &keys, &audit, now).await?)
}

async fn signer_for(
    tx: &mut db::SystemTx,
    enc: &dyn FieldEncryptor,
    kid: &str,
    want: SigningRealm,
    label: &'static str,
) -> Result<Arc<dyn Signer>, JwtKeyError> {
    let row = signing_keys::by_kid(tx, kid)
        .await?
        .ok_or(JwtKeyError::Missing(label))?;
    if row.status != SigningKeyStatus::Active || row.realm != want || row.alg != SigAlg::Es256 {
        return Err(JwtKeyError::Unusable(label));
    }
    let pk = row
        .private_key(enc)
        .await
        .map_err(|_| JwtKeyError::Decrypt(label))?;
    let s = Es256Signer::from_pkcs8(kid, &pk).map_err(|_| JwtKeyError::Decrypt(label))?;
    Ok(Arc::new(s))
}

/// Issuer (configured kids) + verify set (all public JWT keys) from the DB.
///
/// # Errors
/// [`JwtKeyError`] (fail closed).
pub async fn load_jwt(
    db: &db::Db,
    enc: &dyn FieldEncryptor,
    member_kid: &str,
    staff_kid: &str,
) -> Result<(Es256Issuer, KeySet), JwtKeyError> {
    let mut tx = db.system_tx().await?;
    let r = async {
        let member = signer_for(
            &mut tx,
            enc,
            member_kid,
            SigningRealm::JwtMember,
            "JWT_SIGNING_KID_MEMBER",
        )
        .await?;
        let staff = signer_for(
            &mut tx,
            enc,
            staff_kid,
            SigningRealm::JwtStaff,
            "JWT_SIGNING_KID_STAFF",
        )
        .await?;
        let public = signing_keys::list_public(&mut tx, OffsetDateTime::now_utc()).await?;
        Ok::<_, JwtKeyError>((member, staff, public))
    }
    .await;
    tx.rollback().await;
    let (member, staff, public) = r?;
    let mut set = KeySet::new();
    for k in &public {
        if k.alg != SigAlg::Es256 {
            continue;
        }
        if let Some(realm) = auth_realm(k.realm) {
            set.insert(&k.kid, realm, &k.public_key)
                .map_err(|_| JwtKeyError::KeySet("public key"))?;
        }
    }
    let issuer =
        Es256Issuer::new(member, staff, None).map_err(|_| JwtKeyError::KeySet("issuer"))?;
    Ok((issuer, set))
}

/// RFC 7517 JWKS for the JWT realms (report / licence keys are published elsewhere).
#[must_use]
pub fn jwks(keys: &[PublicKeyInfo]) -> serde_json::Value {
    let list: Vec<serde_json::Value> = keys
        .iter()
        .filter(|k| auth_realm(k.realm).is_some() && k.alg == SigAlg::Es256)
        .filter_map(|k| {
            // Uncompressed SEC1 point: 0x04 || X(32) || Y(32).
            let (x, y) = match k.public_key.as_slice() {
                [0x04, rest @ ..] if rest.len() == 64 => rest.split_at(32),
                _ => return None,
            };
            Some(serde_json::json!({
                "kty": "EC",
                "crv": "P-256",
                "alg": "ES256",
                "use": "sig",
                "kid": k.kid,
                "x": URL_SAFE_NO_PAD.encode(x),
                "y": URL_SAFE_NO_PAD.encode(y),
            }))
        })
        .collect();
    serde_json::json!({ "keys": list })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwks_shape_and_filter() {
        let mut pk = vec![0x04];
        pk.extend([1u8; 32]);
        pk.extend([2u8; 32]);
        let now = OffsetDateTime::now_utc();
        let k = |kid: &str, realm, alg, public_key: Vec<u8>| PublicKeyInfo {
            kid: kid.into(),
            alg,
            realm,
            public_key,
            status: SigningKeyStatus::Active,
            not_before: now,
            expires_at: None,
        };
        let v = jwks(&[
            k("m1", SigningRealm::JwtMember, SigAlg::Es256, pk.clone()),
            k(
                "r1",
                SigningRealm::ReportCertificate,
                SigAlg::Ed25519,
                vec![3; 32],
            ),
            k("bad", SigningRealm::JwtStaff, SigAlg::Es256, vec![4; 10]),
        ]);
        let keys = v["keys"].as_array().expect("arr");
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0]["kid"], "m1");
        assert_eq!(keys[0]["x"], URL_SAFE_NO_PAD.encode([1u8; 32]));
        assert!(keys[0].get("d").is_none(), "no private part");
    }
}
