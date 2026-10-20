//! T-A1: every token rejection case (no DB).

use std::sync::Arc;

use aws_lc_rs::hmac;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use common::{FixedClock, MembershipId, SessionId, TenantId};
use crypto::{Es256Signer, Signer};
use time::OffsetDateTime;

use crate::claims::{AccessClaims, Amr, Audience, PrincipalKind, Realm, VerifiedClaims};
use crate::error::{AuthError, Rejection};
use crate::jws;
use crate::tokens::{Es256Issuer, Es256Verifier, KeySet, TokenIssuer, TokenVerifier};

const ISS: &str = "https://api.dsecure.test";
const NOW: i64 = 1_800_000_000;

fn signer(kid: &str) -> Arc<Es256Signer> {
    let pk = Es256Signer::generate_pkcs8().expect("gen");
    Arc::new(Es256Signer::from_pkcs8(kid, &pk).expect("load"))
}

struct World {
    member: Arc<Es256Signer>,
    staff: Arc<Es256Signer>,
    issuer: Es256Issuer,
    verifier: Es256Verifier,
}

fn world() -> World {
    let member = signer("member-1");
    let staff = signer("staff-1");
    let issuer = Es256Issuer::new(member.clone(), staff.clone(), None).expect("issuer");
    let mut keys = KeySet::new();
    keys.insert_signer(member.as_ref(), Realm::Member)
        .expect("k");
    keys.insert_signer(staff.as_ref(), Realm::Staff).expect("k");
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(NOW).expect("ts"),
    ));
    let verifier = Es256Verifier::new(keys, ISS, clock, 30);
    World {
        member,
        staff,
        issuer,
        verifier,
    }
}

fn member_claims() -> AccessClaims {
    AccessClaims {
        iss: ISS.to_owned(),
        sub: uuid::Uuid::now_v7(),
        aud: Audience::Web,
        exp: NOW + 900,
        nbf: NOW,
        iat: NOW,
        jti: uuid::Uuid::now_v7(),
        typ: PrincipalKind::Member,
        tid: Some(TenantId::new()),
        mid: Some(MembershipId::new()),
        sid: Some(SessionId::new()),
        dcid: None,
        av: 1,
        amr: vec![Amr::Pwd],
        auth_time: NOW,
    }
}

fn staff_claims() -> AccessClaims {
    AccessClaims {
        aud: Audience::Platform,
        typ: PrincipalKind::Staff,
        tid: None,
        mid: None,
        ..member_claims()
    }
}

/// Sign arbitrary claims with any signer (bypasses the issuer's realm selection).
fn raw_sign(s: &Es256Signer, c: &AccessClaims) -> String {
    let payload = serde_json::to_vec(c).expect("json");
    let input = jws::signing_input(s.kid(), &payload).expect("input");
    let sig = s.sign_sync(input.as_bytes()).expect("sign");
    jws::assemble(&input, &sig)
}

fn rejection(r: Result<VerifiedClaims, AuthError>) -> Rejection {
    r.expect_err("must be rejected")
        .rejection()
        .expect("unauthenticated")
}

#[tokio::test]
async fn valid_member_and_staff_tokens_verify() {
    let w = world();
    let t = w
        .issuer
        .issue_access(&member_claims())
        .await
        .expect("issue");
    let c = w.verifier.verify(&t, &[Audience::Web]).expect("verify");
    assert_eq!(c.kid(), "member-1");
    let s = w.issuer.issue_access(&staff_claims()).await.expect("issue");
    let c = w
        .verifier
        .verify(&s, &[Audience::Platform])
        .expect("verify");
    assert_eq!(c.kid(), "staff-1");
}

#[tokio::test]
async fn wrong_audience_rejected() {
    let w = world();
    let t = w
        .issuer
        .issue_access(&member_claims())
        .await
        .expect("issue");
    assert_eq!(
        rejection(w.verifier.verify(&t, &[Audience::App])),
        Rejection::WrongAudience
    );
    assert_eq!(
        rejection(w.verifier.verify(&t, &[])),
        Rejection::WrongAudience
    );
}

#[tokio::test]
async fn staff_token_on_member_audience_and_vice_versa() {
    let w = world();
    let s = w.issuer.issue_access(&staff_claims()).await.expect("issue");
    assert_eq!(
        rejection(w.verifier.verify(&s, &[Audience::Web])),
        Rejection::WrongAudience
    );
    let m = w
        .issuer
        .issue_access(&member_claims())
        .await
        .expect("issue");
    assert_eq!(
        rejection(w.verifier.verify(&m, &[Audience::Platform])),
        Rejection::WrongAudience
    );
    // Staff KEY minting a member-audience token (or member key minting a staff token): realm check.
    let forged = raw_sign(&w.staff, &member_claims());
    assert_eq!(
        rejection(w.verifier.verify(&forged, &[Audience::Web])),
        Rejection::RealmMismatch
    );
    let forged = raw_sign(&w.member, &staff_claims());
    assert_eq!(
        rejection(w.verifier.verify(&forged, &[Audience::Platform])),
        Rejection::RealmMismatch
    );
    // typ must match aud
    let mut c = member_claims();
    c.typ = PrincipalKind::Staff;
    assert_eq!(
        rejection(
            w.verifier
                .verify(&raw_sign(&w.member, &c), &[Audience::Web])
        ),
        Rejection::KindMismatch
    );
    // issuer refuses to mint a mis-shaped token
    assert!(w.issuer.issue_access(&c).await.is_err());
}

#[tokio::test]
async fn wrong_or_unknown_kid_rejected() {
    let w = world();
    // same kid, different key (attacker key)
    let attacker = signer("member-1");
    let forged = raw_sign(&attacker, &member_claims());
    assert_eq!(
        rejection(w.verifier.verify(&forged, &[Audience::Web])),
        Rejection::BadSignature
    );
    // kid not in the key set
    let rogue = signer("rotated-out-9");
    let t = raw_sign(&rogue, &member_claims());
    assert_eq!(
        rejection(w.verifier.verify(&t, &[Audience::Web])),
        Rejection::UnknownKid
    );
}

#[tokio::test]
async fn alg_none_and_hs256_forgeries_rejected() {
    let w = world();
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&member_claims()).expect("json"));
    // alg:none with empty signature
    let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"none","kid":"member-1"}"#);
    assert_eq!(
        rejection(
            w.verifier
                .verify(&format!("{h}.{payload}."), &[Audience::Web])
        ),
        Rejection::BadAlgorithm
    );
    // HS256 "signed" with the member PUBLIC key bytes as HMAC secret (classic alg confusion)
    let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256","kid":"member-1","typ":"JWT"}"#);
    let input = format!("{h}.{payload}");
    let key = hmac::Key::new(hmac::HMAC_SHA256, w.member.public_key());
    let mac = URL_SAFE_NO_PAD.encode(hmac::sign(&key, input.as_bytes()).as_ref());
    assert_eq!(
        rejection(
            w.verifier
                .verify(&format!("{input}.{mac}"), &[Audience::Web])
        ),
        Rejection::BadAlgorithm
    );
    // Same HMAC but header claims ES256: no MAC path exists, signature check fails.
    let h = URL_SAFE_NO_PAD.encode(br#"{"alg":"ES256","kid":"member-1","typ":"JWT"}"#);
    let input = format!("{h}.{payload}");
    let mac = hmac::sign(&key, input.as_bytes());
    let mut sig = mac.as_ref().to_vec();
    sig.extend_from_slice(mac.as_ref()); // 64 bytes so it passes the length check
    let t = format!("{input}.{}", URL_SAFE_NO_PAD.encode(&sig));
    assert_eq!(
        rejection(w.verifier.verify(&t, &[Audience::Web])),
        Rejection::BadSignature
    );
    // RS256 / ES384 headers
    for alg in ["RS256", "ES384", "PS256"] {
        let h = URL_SAFE_NO_PAD.encode(format!(r#"{{"alg":"{alg}","kid":"member-1"}}"#));
        let t = format!("{h}.{payload}.{}", URL_SAFE_NO_PAD.encode([1u8; 64]));
        assert_eq!(
            rejection(w.verifier.verify(&t, &[Audience::Web])),
            Rejection::BadAlgorithm,
            "{alg}"
        );
    }
}

#[tokio::test]
async fn expired_and_future_tokens_rejected() {
    let w = world();
    let mut c = member_claims();
    c.iat = NOW - 1000;
    c.nbf = NOW - 1000;
    c.exp = NOW - 60;
    assert_eq!(
        rejection(
            w.verifier
                .verify(&raw_sign(&w.member, &c), &[Audience::Web])
        ),
        Rejection::Expired
    );
    // within the 30 s leeway: accepted
    c.exp = NOW - 10;
    assert!(
        w.verifier
            .verify(&raw_sign(&w.member, &c), &[Audience::Web])
            .is_ok()
    );
    // nbf in the future
    let mut c = member_claims();
    c.nbf = NOW + 120;
    c.exp = NOW + 900;
    assert_eq!(
        rejection(
            w.verifier
                .verify(&raw_sign(&w.member, &c), &[Audience::Web])
        ),
        Rejection::NotYetValid
    );
    // iat in the future
    let mut c = member_claims();
    c.iat = NOW + 120;
    c.exp = NOW + 900;
    assert_eq!(
        rejection(
            w.verifier
                .verify(&raw_sign(&w.member, &c), &[Audience::Web])
        ),
        Rejection::IssuedInFuture
    );
    // lifetime longer than any access token may live
    let mut c = member_claims();
    c.exp = NOW + 86_400;
    assert_eq!(
        rejection(
            w.verifier
                .verify(&raw_sign(&w.member, &c), &[Audience::Web])
        ),
        Rejection::LifetimeTooLong
    );
}

#[tokio::test]
async fn tampering_issuer_and_shape_rejected() {
    let w = world();
    let t = w
        .issuer
        .issue_access(&member_claims())
        .await
        .expect("issue");
    let parts: Vec<&str> = t.split('.').collect();
    // payload swapped (role escalation attempt via another tenant id)
    let mut c = member_claims();
    c.tid = Some(TenantId::new());
    let other = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&c).expect("json"));
    let tampered = format!("{}.{}.{}", parts[0], other, parts[2]);
    assert_eq!(
        rejection(w.verifier.verify(&tampered, &[Audience::Web])),
        Rejection::BadSignature
    );
    // high-S (malleated) signature
    let sig = URL_SAFE_NO_PAD.decode(parts[2]).expect("b64");
    let mut hi = sig.clone();
    let n: [u8; 32] = [
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63,
        0x25, 0x51,
    ];
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let mut d = i16::from(n[i]) - i16::from(sig[32 + i]) - borrow;
        borrow = i16::from(d < 0);
        if d < 0 {
            d += 256;
        }
        hi[32 + i] = u8::try_from(d).expect("byte");
    }
    let mall = format!("{}.{}.{}", parts[0], parts[1], URL_SAFE_NO_PAD.encode(&hi));
    assert_eq!(
        rejection(w.verifier.verify(&mall, &[Audience::Web])),
        Rejection::BadSignature
    );
    // wrong issuer
    let mut c = member_claims();
    c.iss = "https://evil".to_owned();
    assert_eq!(
        rejection(
            w.verifier
                .verify(&raw_sign(&w.member, &c), &[Audience::Web])
        ),
        Rejection::WrongIssuer
    );
    // missing tenant on a member token
    let mut c = member_claims();
    c.tid = None;
    assert_eq!(
        rejection(
            w.verifier
                .verify(&raw_sign(&w.member, &c), &[Audience::Web])
        ),
        Rejection::MissingClaim
    );
    // unknown claim in payload (deny_unknown_fields)
    let mut v = serde_json::to_value(member_claims()).expect("json");
    v["role"] = serde_json::json!("owner");
    let payload = serde_json::to_vec(&v).expect("json");
    let input = jws::signing_input("member-1", &payload).expect("input");
    let t = jws::assemble(&input, &w.member.sign_sync(input.as_bytes()).expect("sign"));
    assert_eq!(
        rejection(w.verifier.verify(&t, &[Audience::Web])),
        Rejection::Malformed
    );
}

#[test]
fn key_rotation_and_keyset_hygiene() {
    let a = signer("member-1");
    let b = signer("member-2");
    let mut keys = KeySet::new();
    keys.insert_signer(a.as_ref(), Realm::Member).expect("a");
    keys.insert_signer(b.as_ref(), Realm::Member).expect("b");
    assert!(
        keys.insert_signer(a.as_ref(), Realm::Member).is_err(),
        "duplicate kid"
    );
    assert!(
        keys.insert("bad/kid", Realm::Member, a.public_key())
            .is_err()
    );
    assert!(keys.insert("short", Realm::Member, &[4u8; 10]).is_err());
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(NOW).expect("ts"),
    ));
    let v = Es256Verifier::new(keys, ISS, clock, 30);
    assert!(
        v.verify(&raw_sign(&a, &member_claims()), &[Audience::Web])
            .is_ok()
    );
    assert!(
        v.verify(&raw_sign(&b, &member_claims()), &[Audience::Web])
            .is_ok()
    );
    // issuer refuses shared keys between realms
    assert!(Es256Issuer::new(a.clone(), a, None).is_err());
}
