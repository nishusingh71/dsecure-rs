//! `authorize`: a wrong-audience / wrong-kind token is refused before ANY loader (DB) call.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::{FixedClock, MembershipId, SessionId, TenantId};
use crypto::Es256Signer;
use domain::rbac::{Perm, PlatformPerm, TenantRole};
use time::OffsetDateTime;

use crate::authorize::authorize;
use crate::claims::{AccessClaims, Amr, Audience, PrincipalKind, Realm, VerifiedClaims};
use crate::error::{AuthError, Rejection};
use crate::loader::{Freshness, PrincipalStateLoader};
use crate::policy::{DenyCode, EvalContext, Policy};
use crate::principal::{DevicePrincipal, MemberPrincipal, StaffPrincipal};
use crate::tokens::{Es256Issuer, Es256Verifier, KeySet, TokenIssuer};

const ISS: &str = "https://api.dsecure.test";
const NOW: i64 = 1_800_000_000;

/// Counts every load; member loads succeed with an owner fixture, the rest fail.
#[derive(Default)]
struct CountingLoader(AtomicUsize);

#[async_trait::async_trait]
impl PrincipalStateLoader for CountingLoader {
    async fn load_member(
        &self,
        claims: &VerifiedClaims,
        _fresh: Freshness,
    ) -> Result<MemberPrincipal, AuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        let t = claims.tenant().ok_or(AuthError::Internal("tenant"))?;
        Ok(crate::loader::test_support::member(
            t,
            TenantRole::Owner,
            domain::rbac::FeatureSet::all(),
        ))
    }
    async fn load_device(
        &self,
        _claims: &VerifiedClaims,
        _fresh: Freshness,
    ) -> Result<DevicePrincipal, AuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::Unauthenticated(Rejection::CredentialRevoked))
    }
    async fn load_staff(&self, _claims: &VerifiedClaims) -> Result<StaffPrincipal, AuthError> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(AuthError::Unavailable)
    }
}

fn signer(kid: &str) -> Arc<Es256Signer> {
    let pk = Es256Signer::generate_pkcs8().expect("gen");
    Arc::new(Es256Signer::from_pkcs8(kid, &pk).expect("load"))
}

fn claims(aud: Audience) -> AccessClaims {
    let member = aud.kind() == PrincipalKind::Member;
    let device = aud.kind() == PrincipalKind::Device;
    AccessClaims {
        iss: ISS.to_owned(),
        sub: uuid::Uuid::now_v7(),
        aud,
        exp: NOW + 900,
        nbf: NOW,
        iat: NOW,
        jti: uuid::Uuid::now_v7(),
        typ: aud.kind(),
        tid: (member || device).then(TenantId::new),
        mid: (member || device).then(MembershipId::new),
        sid: (!device).then(SessionId::new),
        dcid: device.then(uuid::Uuid::now_v7),
        av: 1,
        amr: vec![Amr::Pwd],
        auth_time: NOW,
    }
}

#[tokio::test]
async fn wrong_audience_refused_without_loader_call() {
    let member = signer("m1");
    let staff = signer("s1");
    let issuer = Es256Issuer::new(member.clone(), staff.clone(), None).expect("issuer");
    let mut keys = KeySet::new();
    keys.insert_signer(member.as_ref(), Realm::Member)
        .expect("k");
    keys.insert_signer(staff.as_ref(), Realm::Staff).expect("k");
    let clock = Arc::new(FixedClock::new(
        OffsetDateTime::from_unix_timestamp(NOW).expect("ts"),
    ));
    let verifier = Es256Verifier::new(keys, ISS, clock, 30);
    let loader = CountingLoader::default();
    let ctx = EvalContext::at(OffsetDateTime::from_unix_timestamp(NOW).expect("ts"));

    let member_policy = Policy::member().permission(Perm::ProfileReadSelf);
    assert_eq!(
        member_policy.audiences(),
        vec![Audience::Web, Audience::App]
    );
    assert_eq!(member_policy.principal_kinds(), vec![PrincipalKind::Member]);
    let staff_policy = Policy::staff().platform(PlatformPerm::TenantsRead);
    assert_eq!(staff_policy.audiences(), vec![Audience::Platform]);
    let device_policy = Policy::device().permission(Perm::ReportsDriveCreate);
    assert_eq!(device_policy.audiences(), vec![Audience::Device]);
    assert!(Policy::public("liveness").audiences().is_empty());

    let staff_tok = issuer
        .issue_access(&claims(Audience::Platform))
        .await
        .expect("t");
    let device_tok = issuer
        .issue_access(&claims(Audience::Device))
        .await
        .expect("t");
    let web_tok = issuer
        .issue_access(&claims(Audience::Web))
        .await
        .expect("t");

    for (policy, token) in [
        (&member_policy, &staff_tok),
        (&member_policy, &device_tok),
        (&staff_policy, &web_tok),
        (&device_policy, &web_tok),
        (&device_policy, &staff_tok),
    ] {
        let d = authorize(policy, &verifier, &loader, Some(token), None, &ctx)
            .await
            .expect_err("wrong audience");
        assert_eq!(d.code, DenyCode::Unauthenticated);
        assert_eq!(d.status(), 401);
    }
    // no token / garbage token: also no load
    assert!(
        authorize(&member_policy, &verifier, &loader, None, None, &ctx)
            .await
            .is_err()
    );
    assert!(
        authorize(
            &member_policy,
            &verifier,
            &loader,
            Some("x.y.z"),
            None,
            &ctx
        )
        .await
        .is_err()
    );
    assert_eq!(
        loader.0.load(Ordering::SeqCst),
        0,
        "no DB load for refused tokens"
    );

    // matching audience: exactly one load, then the policy decides
    let ok = authorize(
        &member_policy,
        &verifier,
        &loader,
        Some(&web_tok),
        None,
        &ctx,
    )
    .await
    .expect("allowed");
    assert!(ok.claims.is_some());
    assert_eq!(loader.0.load(Ordering::SeqCst), 1);
    // live-state errors map to fail-closed statuses
    let d = authorize(
        &staff_policy,
        &verifier,
        &loader,
        Some(&staff_tok),
        None,
        &ctx,
    )
    .await
    .expect_err("unavailable");
    assert_eq!(d.status(), 503);
    // public routes never touch the loader
    let before = loader.0.load(Ordering::SeqCst);
    assert!(
        authorize(
            &Policy::public("liveness"),
            &verifier,
            &loader,
            None,
            None,
            &ctx
        )
        .await
        .is_ok()
    );
    assert_eq!(loader.0.load(Ordering::SeqCst), before);
}
