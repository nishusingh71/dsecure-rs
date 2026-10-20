//! `DbDekStore`: active-key Conflict (unique-when-active), rotation, and a KeyRing round trip on the
//! real DB with `EnvKeyProvider` + a KEK generated in-test (never written anywhere).

use super::fixtures::{new_tenant, now};
use super::harness::with_db;
use crate::repo::keys::DbDekStore;
use crypto::devkeys::generate_kek_b64;
use crypto::{
    AesGcmFieldEncryptor, CryptoError, DekStore, EnvKeyProvider, FieldContext, FieldEncryptor,
    KeyPurpose, KeyRing, Kid, WrappedDek,
};
use std::sync::Arc;

fn w(b: u8) -> WrappedDek {
    WrappedDek {
        kek_ref: "env:test".into(),
        bytes: vec![b; 61],
    }
}

#[tokio::test]
async fn one_active_key_per_purpose_and_tenant() {
    with_db("dek_conflict", |db, _| async move {
        let a = new_tenant(&db).await;
        let b = new_tenant(&db).await;
        let store = DbDekStore::new(db.clone());
        let k1 = Kid::generate(KeyPurpose::Pii, Some(a.tenant)).expect("kid");
        let k2 = Kid::generate(KeyPurpose::Pii, Some(a.tenant)).expect("kid");
        store
            .insert(&k1, KeyPurpose::Pii, Some(a.tenant), &w(1))
            .await
            .expect("first");
        assert!(matches!(
            store
                .insert(&k2, KeyPurpose::Pii, Some(a.tenant), &w(2))
                .await,
            Err(CryptoError::Conflict)
        ));
        // Same kid again = Conflict too.
        let kb = Kid::generate(KeyPurpose::Pii, Some(b.tenant)).expect("kid");
        store
            .insert(&kb, KeyPurpose::Pii, Some(b.tenant), &w(3))
            .await
            .expect("other tenant ok");
        assert!(matches!(
            store
                .insert(&kb, KeyPurpose::Reports, Some(b.tenant), &w(3))
                .await,
            Err(CryptoError::Conflict)
        ));
        // Other purpose, same tenant: fine. Scope mismatch refused.
        let kr = Kid::generate(KeyPurpose::Reports, Some(a.tenant)).expect("kid");
        store
            .insert(&kr, KeyPurpose::Reports, Some(a.tenant), &w(4))
            .await
            .expect("reports");
        let kp = Kid::generate(KeyPurpose::Identity, None).expect("kid");
        assert!(
            store
                .insert(&kp, KeyPurpose::Identity, Some(a.tenant), &w(5))
                .await
                .is_err()
        );
        // Lookups
        let (kid, wd) = store
            .active(KeyPurpose::Pii, Some(a.tenant))
            .await
            .expect("active")
            .expect("some");
        assert_eq!((kid, wd), (k1.clone(), w(1)));
        assert!(
            store
                .active(KeyPurpose::Pii, None)
                .await
                .expect("a")
                .is_none()
        );
        let (p, t, _) = store.by_kid(&k1).await.expect("by kid").expect("some");
        assert_eq!((p, t), (KeyPurpose::Pii, Some(a.tenant)));
        // Rotation frees the active slot; old kid stays readable (decrypt_only).
        store.deactivate(&k1, now()).await.expect("deactivate");
        store
            .insert(&k2, KeyPurpose::Pii, Some(a.tenant), &w(2))
            .await
            .expect("new active");
        assert_eq!(
            store
                .active(KeyPurpose::Pii, Some(a.tenant))
                .await
                .expect("a")
                .expect("s")
                .0,
            k2
        );
        assert!(store.by_kid(&k1).await.expect("old").is_some());
    })
    .await;
}

#[tokio::test]
async fn keyring_round_trip_on_real_db() {
    if super::harness::tidb_skip(
        "keyring_round_trip_on_real_db",
        "platform DEKs persist in the shared DB; a per-run test KEK cannot unwrap them",
    ) {
        return;
    }
    with_db("keyring", |db, _| async move {
        let a = new_tenant(&db).await;
        let kek = generate_kek_b64().expect("kek");
        let provider =
            Arc::new(EnvKeyProvider::new("t1", [("t1", kek.to_string())]).expect("provider"));
        let store = Arc::new(DbDekStore::new(db.clone()));
        let created = KeyRing::ensure_platform_keys(&*provider, &*store)
            .await
            .expect("ensure");
        assert_eq!(created, KeyPurpose::PLATFORM.len());
        assert_eq!(
            KeyRing::ensure_platform_keys(&*provider, &*store)
                .await
                .expect("again"),
            0
        );

        let ring1 = Arc::new(
            KeyRing::load_platform(provider.clone(), store.clone())
                .await
                .expect("load1"),
        );
        let enc1 = AesGcmFieldEncryptor::new(Arc::clone(&ring1));
        let row = uuid::Uuid::now_v7();
        let pctx = FieldContext::new("users", "email_enc", None, row, KeyPurpose::Identity);
        let tctx = FieldContext::new(
            "memberships",
            "display_name_enc",
            Some(a.tenant),
            row,
            KeyPurpose::Pii,
        );
        let c_platform = enc1
            .encrypt(b"platform secret", &pctx)
            .await
            .expect("enc p");
        let c_tenant = enc1.encrypt(b"tenant secret", &tctx).await.expect("enc t"); // lazy tenant DEK

        // A fresh ring (another instance) reads every key back from the DB.
        let ring2 = Arc::new(
            KeyRing::load_platform(provider.clone(), store.clone())
                .await
                .expect("load2"),
        );
        let enc2 = AesGcmFieldEncryptor::new(ring2);
        assert_eq!(
            &enc2.decrypt(&c_platform, &pctx).await.expect("dec p")[..],
            b"platform secret"
        );
        assert_eq!(
            &enc2.decrypt(&c_tenant, &tctx).await.expect("dec t")[..],
            b"tenant secret"
        );
        // Same tenant DEK reused (no second active key created).
        let (k1, _) = ring1
            .active(KeyPurpose::Pii, Some(a.tenant))
            .await
            .expect("k1");
        assert_eq!(
            store
                .active(KeyPurpose::Pii, Some(a.tenant))
                .await
                .expect("a")
                .expect("s")
                .0,
            k1
        );
        // Wrong KEK cannot unwrap the stored DEKs (fail closed).
        let other = Arc::new(
            EnvKeyProvider::new("t1", [("t1", generate_kek_b64().expect("kek").to_string())])
                .expect("p"),
        );
        assert!(KeyRing::load_platform(other, store.clone()).await.is_err());
    })
    .await;
}
