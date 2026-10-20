//! FsBlobStore + EncryptedBlobStore integration tests.
// Integration test helpers ko #[test] ke bahar unwrap chahiye; sirf test crates par allow.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::print_stdout
)]

mod support;

use bytes::Bytes;
use common::TenantId;
use crypto::CryptoError;
use futures_util::StreamExt as _;
use futures_util::stream;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
use storage::{
    BlobKey, BlobRef, BlobStore, CHUNK_SIZE, EncryptedBlobStore, FsBlobStore, StorageError,
    TAG_LEN, WriteId,
};
use support::{all_files, body_of, collect, pattern, ring_with_kek};

const SIZES: [usize; 5] = [0, 1, CHUNK_SIZE, CHUNK_SIZE + 1, 5 * 1024 * 1024];

fn key(t: TenantId, name: &str) -> BlobKey {
    BlobKey::new(t, &format!("reports/{name}")).unwrap()
}

fn stored_path(root: &Path, k: &BlobKey) -> PathBuf {
    let mut p = root.join(k.tenant().as_uuid().hyphenated().to_string());
    for s in k.segments() {
        p.push(s);
    }
    p
}

/// Poora get: (verified bytes, error agar aaya).
async fn read_result<S: BlobStore>(s: &S, r: &BlobRef) -> (Vec<u8>, Option<StorageError>) {
    let mut st = match s.get_stream(r).await {
        Ok(st) => st,
        Err(e) => return (vec![], Some(e)),
    };
    let mut out = vec![];
    while let Some(item) = st.next().await {
        match item {
            Ok(b) => out.extend_from_slice(&b),
            Err(e) => return (out, Some(StorageError::from_io(e))),
        }
    }
    (out, None)
}

#[tokio::test]
async fn plain_fs_roundtrip_sizes_and_meta() {
    let dir = tempfile::tempdir().unwrap();
    let fs = FsBlobStore::new(dir.path()).unwrap();
    let t = TenantId::new();
    for n in SIZES {
        let p = pattern(n);
        let k = key(t, &format!("plain-{n}.bin"));
        let meta = fs
            .put_stream(&k, body_of(p.clone(), 10_000), u64::MAX)
            .await
            .unwrap();
        assert_eq!(meta.size, n as u64);
        assert_eq!(
            (meta.kid.clone(), meta.write_id, meta.digest),
            (None, None, None)
        );
        let got = collect(fs.get_stream(&BlobRef::from_key(k)).await.unwrap())
            .await
            .unwrap();
        assert_eq!(got, p, "size {n}");
    }
    assert!(
        all_files(&fs.root().join(".tmp")).is_empty(),
        "temp leftovers"
    );
}

#[tokio::test]
async fn encrypted_roundtrip_sizes_meta_and_keyed_digest() {
    let dir = tempfile::tempdir().unwrap();
    let ring = ring_with_kek(1).await;
    let store = EncryptedBlobStore::new(FsBlobStore::new(dir.path()).unwrap(), ring);
    let t = TenantId::new();
    for n in SIZES {
        let p = pattern(n);
        let k = key(t, &format!("enc-{n}.bin"));
        let meta = store
            .put_stream(&k, body_of(p.clone(), 33_333), u64::MAX)
            .await
            .unwrap();
        assert_eq!(meta.size, n as u64, "meta.size is plaintext size");
        assert!(meta.kid.is_some() && meta.write_id.is_some() && meta.digest.is_some());
        // keyed digest: same plaintext, doosri write => alag digest (known-plaintext confirmation nahi)
        let meta2 = store
            .put_stream(&k, body_of(p.clone(), 1000), u64::MAX)
            .await
            .unwrap();
        assert_ne!(meta.digest, meta2.digest);
        assert_ne!(meta.write_id, meta2.write_id);
        let on_disk = std::fs::read(stored_path(store.inner().root(), &k)).unwrap();
        assert!(on_disk.len() > n);
        if n >= 64 {
            assert!(!on_disk.windows(64).any(|w| w == &p[..64]));
        }
        let (out, err) = read_result(&store, &meta2.blob_ref(&k)).await;
        assert!(err.is_none(), "size {n}: {err:?}");
        assert_eq!(out, p, "size {n}");
    }
}

#[tokio::test]
async fn max_bytes_exceeded_errors_and_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let ring = ring_with_kek(1).await;
    let t = TenantId::new();
    let fs = FsBlobStore::new(dir.path()).unwrap();
    let enc = EncryptedBlobStore::new(FsBlobStore::new(dir.path()).unwrap(), ring);
    let data = pattern(3 * CHUNK_SIZE + 5);
    let max = (3 * CHUNK_SIZE) as u64;

    let e = fs
        .put_stream(&key(t, "a.bin"), body_of(data.clone(), 50_000), max)
        .await
        .unwrap_err();
    assert!(
        matches!(e, StorageError::TooLarge { max: m } if m == max),
        "{e:?}"
    );
    let e = enc
        .put_stream(&key(t, "b.bin"), body_of(data.clone(), 50_000), max)
        .await
        .unwrap_err();
    assert!(
        matches!(e, StorageError::TooLarge { max: m } if m == max),
        "{e:?}"
    );
    assert!(
        all_files(dir.path()).is_empty(),
        "{:?}",
        all_files(dir.path())
    );

    let ok = enc
        .put_stream(
            &key(t, "c.bin"),
            body_of(data[..3 * CHUNK_SIZE].to_vec(), 50_000),
            max,
        )
        .await
        .unwrap();
    assert_eq!(ok.size, max);
    // overwrite fail hone par purana blob safe rehta hai
    let e = enc
        .put_stream(&key(t, "c.bin"), body_of(data, 50_000), max)
        .await
        .unwrap_err();
    assert!(matches!(e, StorageError::TooLarge { .. }));
    let (out, err) = read_result(&enc, &ok.blob_ref(&key(t, "c.bin"))).await;
    assert!(err.is_none());
    assert_eq!(out.len(), 3 * CHUNK_SIZE);
    assert_eq!(all_files(dir.path()).len(), 1);
}

#[tokio::test]
async fn body_error_midstream_leaves_no_file() {
    let dir = tempfile::tempdir().unwrap();
    let fs = FsBlobStore::new(dir.path()).unwrap();
    let t = TenantId::new();
    let items: Vec<io::Result<Bytes>> = vec![
        Ok(Bytes::from(vec![1u8; 1000])),
        Err(io::Error::other("client went away")),
    ];
    let e = fs
        .put_stream(&key(t, "x.bin"), stream::iter(items).boxed(), 1 << 20)
        .await
        .unwrap_err();
    assert!(matches!(e, StorageError::Io(_)), "{e:?}");
    assert!(all_files(dir.path()).is_empty());
}

#[tokio::test]
async fn overwrite_is_atomic_replace_and_missing_is_not_found() {
    let dir = tempfile::tempdir().unwrap();
    let fs = FsBlobStore::new(dir.path()).unwrap();
    let t = TenantId::new();
    let k = key(t, "o.bin");
    let r = BlobRef::from_key(k.clone());
    assert!(matches!(
        fs.get_stream(&r).await,
        Err(StorageError::NotFound)
    ));
    fs.put_stream(&k, body_of(vec![1; 10], 4), 100)
        .await
        .unwrap();
    fs.put_stream(&k, body_of(vec![2; 20], 4), 100)
        .await
        .unwrap();
    let got = collect(fs.get_stream(&r).await.unwrap()).await.unwrap();
    assert_eq!(got, vec![2; 20]);
    assert!(matches!(
        fs.get_stream(&BlobRef::from_key(key(t, "nope.bin"))).await,
        Err(StorageError::NotFound)
    ));
}

#[test]
fn traversal_keys_cannot_even_be_constructed() {
    let t = TenantId::new();
    for bad in [
        "../../etc/passwd",
        "/etc/passwd",
        "C:\\Windows\\x",
        "C:/Windows/x",
        "reports/../../x",
        "a\0b",
        "..\\x",
    ] {
        assert!(BlobKey::new(t, bad).is_err(), "{bad:?}");
        assert!(BlobKey::parse(bad).is_err(), "{bad:?}");
    }
}

#[tokio::test]
async fn symlinked_directory_inside_root_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    let fs = FsBlobStore::new(dir.path()).unwrap();
    let t = TenantId::new();
    let tenant_dir = fs.root().join(t.as_uuid().hyphenated().to_string());
    std::fs::create_dir_all(&tenant_dir).unwrap();
    let link = tenant_dir.join("reports");
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(outside.path(), &link).is_ok();
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(outside.path(), &link).is_ok();
    if !made {
        println!("SKIPPED: cannot create symlink on this machine");
        return;
    }
    let k = key(t, "evil.bin");
    let e = fs
        .put_stream(&k, body_of(vec![9; 100], 50), 1000)
        .await
        .unwrap_err();
    assert!(matches!(e, StorageError::UnsafePath), "{e:?}");
    assert!(all_files(outside.path()).is_empty());
    assert!(matches!(
        fs.get_stream(&BlobRef::from_key(k)).await,
        Err(StorageError::UnsafePath)
    ));
}

#[tokio::test]
async fn sweep_stale_temp_removes_only_old_part_files() {
    let dir = tempfile::tempdir().unwrap();
    let fs = FsBlobStore::new(dir.path()).unwrap();
    let tmp = fs.root().join(".tmp");
    let old_t = SystemTime::now() - Duration::from_secs(3 * 3600);
    let mk = |name: &str, old: bool| {
        let f = std::fs::File::create(tmp.join(name)).unwrap();
        if old {
            f.set_modified(old_t).unwrap();
        }
    };
    mk("old1.part", true);
    mk("old2.part", true);
    mk("fresh.part", false);
    mk("old-but-not-part.txt", true);
    let n = fs
        .sweep_stale_temp(Duration::from_secs(3600))
        .await
        .unwrap();
    assert_eq!(n, 2);
    let mut left: Vec<String> = all_files(&tmp)
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    left.sort();
    assert_eq!(left, ["fresh.part", "old-but-not-part.txt"]);
    assert_eq!(
        fs.sweep_stale_temp(Duration::from_secs(3600))
            .await
            .unwrap(),
        0
    );
    // bahut bada max_age (cutoff underflow) kuch nahi hatata
    assert_eq!(fs.sweep_stale_temp(Duration::MAX).await.unwrap(), 0);
    // minimum se kam max_age refuse (fresh/live temp files na hatein)
    assert!(fs.sweep_stale_temp(Duration::from_secs(10)).await.is_err());
    assert!(fs.sweep_stale_temp(Duration::ZERO).await.is_err());
    assert!(tmp.join("fresh.part").exists());
}

#[tokio::test]
async fn stored_tampering_is_detected_and_bad_chunk_is_never_emitted() {
    let dir = tempfile::tempdir().unwrap();
    let ring = ring_with_kek(1).await;
    let store = EncryptedBlobStore::new(FsBlobStore::new(dir.path()).unwrap(), ring);
    let t = TenantId::new();
    let p = pattern(3 * CHUNK_SIZE + 10);
    let k = key(t, "t.bin");
    let meta = store
        .put_stream(&k, body_of(p.clone(), 20_000), u64::MAX)
        .await
        .unwrap();
    let r = meta.blob_ref(&k);
    let path = stored_path(store.inner().root(), &k);
    let orig = std::fs::read(&path).unwrap();
    let full = CHUNK_SIZE + TAG_LEN;
    let hl = orig.len() - (3 * full + 10 + TAG_LEN);
    let chunk = |i: usize| orig[hl + i * full..hl + (i + 1) * full].to_vec();
    let last = orig[hl + 3 * full..].to_vec();
    let mk = |parts: Vec<&[u8]>| {
        let mut v = orig[..hl].to_vec();
        for q in parts {
            v.extend_from_slice(q);
        }
        v
    };
    let (c0, c1, c2) = (chunk(0), chunk(1), chunk(2));
    let mut flipped = orig.clone();
    flipped[hl + full + 17] ^= 0x40;
    let mut flipped_last = orig.clone();
    *flipped_last.last_mut().unwrap() ^= 1;
    let cases: Vec<(&str, Vec<u8>, usize)> = vec![
        (
            "truncate on boundary",
            orig[..hl + 3 * full].to_vec(),
            2 * CHUNK_SIZE,
        ),
        (
            "truncate mid chunk",
            orig[..hl + 2 * full + 100].to_vec(),
            2 * CHUNK_SIZE,
        ),
        ("truncate to header", orig[..hl].to_vec(), 0),
        ("reorder", mk(vec![&c1, &c0, &c2, &last]), 0),
        ("duplicate", mk(vec![&c0, &c0, &c1, &c2, &last]), CHUNK_SIZE),
        ("bit flip chunk1", flipped, CHUNK_SIZE),
        ("bit flip final tag", flipped_last, 3 * CHUNK_SIZE),
    ];
    for (name, bytes, ok_prefix) in cases {
        std::fs::write(&path, &bytes).unwrap();
        let (out, err) = read_result(&store, &r).await;
        assert!(
            matches!(err, Some(StorageError::Integrity)),
            "{name}: {err:?}"
        );
        assert_eq!(out.len(), ok_prefix, "{name}");
        assert_eq!(out, p[..ok_prefix], "{name}");
    }
    std::fs::write(&path, &orig).unwrap();
    let (out, err) = read_result(&store, &r).await;
    assert!(err.is_none());
    assert_eq!(out, p);
}

#[tokio::test]
async fn rollback_to_older_object_at_same_key_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let store = EncryptedBlobStore::new(
        FsBlobStore::new(dir.path()).unwrap(),
        ring_with_kek(1).await,
    );
    let k = key(TenantId::new(), "rb.bin");
    let path = stored_path(store.inner().root(), &k);

    let v1 = pattern(70_000);
    let m1 = store
        .put_stream(&k, body_of(v1.clone(), 9_999), u64::MAX)
        .await
        .unwrap();
    let v1_bytes = std::fs::read(&path).unwrap();
    let v2: Vec<u8> = v1.iter().map(|b| b ^ 0x5a).collect();
    let m2 = store
        .put_stream(&k, body_of(v2.clone(), 9_999), u64::MAX)
        .await
        .unwrap();
    assert_ne!(m1.write_id, m2.write_id);
    let (out, err) = read_result(&store, &m2.blob_ref(&k)).await;
    assert!(err.is_none());
    assert_eq!(out, v2);

    // attacker/storage v1 bytes wapas rakh deta hai
    std::fs::write(&path, &v1_bytes).unwrap();
    let (out, err) = read_result(&store, &m2.blob_ref(&k)).await;
    assert!(out.is_empty());
    assert!(
        matches!(err, Some(StorageError::WriteIdMismatch)),
        "{err:?}"
    );
    // v1 ka apna reference ab bhi consistent hai (DB row sahi write_id rakhta hai)
    let (out, err) = read_result(&store, &m1.blob_ref(&k)).await;
    assert!(err.is_none());
    assert_eq!(out, v1);

    // write_id missing / random => refuse
    let none = BlobRef::from_key(k.clone());
    assert!(matches!(
        store.get_stream(&none).await,
        Err(StorageError::MissingWriteId)
    ));
    let random = BlobRef::new(k.clone(), WriteId::generate().unwrap(), None);
    assert!(matches!(
        store.get_stream(&random).await,
        Err(StorageError::WriteIdMismatch)
    ));
}

#[tokio::test]
async fn expected_digest_is_verified_before_stream_end() {
    let dir = tempfile::tempdir().unwrap();
    let store = EncryptedBlobStore::new(
        FsBlobStore::new(dir.path()).unwrap(),
        ring_with_kek(1).await,
    );
    let k = key(TenantId::new(), "dg.bin");
    let p = pattern(2 * CHUNK_SIZE + 9);
    let meta = store
        .put_stream(&k, body_of(p.clone(), 9_999), u64::MAX)
        .await
        .unwrap();
    let (out, err) = read_result(&store, &meta.blob_ref(&k)).await;
    assert!(err.is_none());
    assert_eq!(out, p);
    let mut bad = meta.blob_ref(&k);
    bad.digest.as_mut().unwrap()[5] ^= 1;
    let (out, err) = read_result(&store, &bad).await;
    assert!(matches!(err, Some(StorageError::Integrity)), "{err:?}");
    // aakhri chunk emit nahi hua
    assert_eq!(out.len(), 2 * CHUNK_SIZE);
    // digest na diya ho to check skip (write_id check phir bhi hai)
    let mut nodigest = meta.blob_ref(&k);
    nodigest.digest = None;
    assert!(read_result(&store, &nodigest).await.1.is_none());
}

#[tokio::test]
async fn wrong_tenant_wrong_blob_and_wrong_key_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let ring = ring_with_kek(1).await;
    let plain = FsBlobStore::new(dir.path()).unwrap();
    let store = EncryptedBlobStore::new(FsBlobStore::new(dir.path()).unwrap(), ring);
    let (ta, tb) = (TenantId::new(), TenantId::new());
    let p = pattern(100_000);
    let ka = key(ta, "r.bin");
    let ma = store
        .put_stream(&ka, body_of(p.clone(), 9999), u64::MAX)
        .await
        .unwrap();
    let raw = std::fs::read(stored_path(plain.root(), &ka)).unwrap();
    let wid = ma.write_id.unwrap();

    // Tenant B ke path par A ka ciphertext (write_id sahi bata bhi de): B ki DEK/scope se nahi khulta
    let kb = key(tb, "r.bin");
    plain
        .put_stream(&kb, body_of(raw.clone(), 9999), u64::MAX)
        .await
        .unwrap();
    let (out, err) = read_result(&store, &BlobRef::new(kb, wid, None)).await;
    assert!(out.is_empty());
    assert!(
        matches!(
            err,
            Some(StorageError::Crypto(CryptoError::KeyScopeMismatch))
        ),
        "{err:?}"
    );

    // Same tenant, doosri blob key par replay
    let ka2 = key(ta, "other.bin");
    plain
        .put_stream(&ka2, body_of(raw.clone(), 9999), u64::MAX)
        .await
        .unwrap();
    let (out, err) = read_result(&store, &BlobRef::new(ka2, wid, None)).await;
    assert!(out.is_empty());
    assert!(matches!(err, Some(StorageError::Crypto(_))), "{err:?}");

    // Poora alag KeyRing (alag KEK + store): kid hi nahi milti
    let other = EncryptedBlobStore::new(
        FsBlobStore::new(dir.path()).unwrap(),
        ring_with_kek(9).await,
    );
    let (out, err) = read_result(&other, &ma.blob_ref(&ka)).await;
    assert!(out.is_empty());
    assert!(
        matches!(err, Some(StorageError::Crypto(CryptoError::KeyNotFound(_)))),
        "{err:?}"
    );

    let (out, err) = read_result(&store, &ma.blob_ref(&ka)).await;
    assert!(err.is_none());
    assert_eq!(out, p);
}

#[tokio::test]
async fn plaintext_file_is_not_accepted_by_encrypted_store() {
    let dir = tempfile::tempdir().unwrap();
    let plain = FsBlobStore::new(dir.path()).unwrap();
    let store = EncryptedBlobStore::new(
        FsBlobStore::new(dir.path()).unwrap(),
        ring_with_kek(1).await,
    );
    let k = key(TenantId::new(), "p.bin");
    plain
        .put_stream(&k, body_of(b"{\"not\":\"encrypted\"}".to_vec(), 5), 1000)
        .await
        .unwrap();
    let r = BlobRef::new(k, WriteId::generate().unwrap(), None);
    let (_, err) = read_result(&store, &r).await;
    assert!(matches!(err, Some(StorageError::BadHeader)), "{err:?}");
}
