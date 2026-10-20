//! `DevKeyCheck`: staging/production startup par dev KEK aur dev signing keys refuse karta hai (`config::ConfigCheck`).
//!
//! Use: `AppConfig::load_with(&env, &[&crypto::DevKeyCheck])`. Messages mein sirf key name aur static text
//! (values kabhi nahi). `crypto -> config` dependency cycle nahi banati (config sirf `common` par depend karta hai).

use crate::devkeys::is_dev_fingerprint;
use config::{AppConfig, ConfigCheck, ConfigProblem};

#[derive(Clone, Copy, Debug, Default)]
pub struct DevKeyCheck;

impl ConfigCheck for DevKeyCheck {
    fn check(&self, cfg: &AppConfig, out: &mut Vec<ConfigProblem>) {
        if cfg.environment.is_local() {
            return;
        }
        if cfg
            .kek
            .env_active_id
            .as_deref()
            .is_some_and(is_dev_fingerprint)
        {
            out.push(ConfigProblem::new(
                "KEK_ENV_ACTIVE_ID",
                "dev KEK fingerprint is not allowed in staging/production",
            ));
        }
        for (key, kid) in [
            ("JWT_SIGNING_KID_MEMBER", &cfg.jwt.signing_kid_member),
            ("JWT_SIGNING_KID_STAFF", &cfg.jwt.signing_kid_staff),
        ] {
            if is_dev_fingerprint(kid) {
                out.push(ConfigProblem::new(
                    key,
                    "dev signing key is not allowed in staging/production",
                ));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::devkeys::{dev_kek_id, dev_signing_kid, generate_kek_b64};
    use common::config_util::Env;

    fn pairs(env: &str, kek_id: &str, kek: &str, member: &str, staff: &str) -> Env {
        let mut p: Vec<(String, String)> = [
            ("DSECURE_ENV", env),
            (
                "DATABASE_URL",
                "mysql://app:pw@db.example.com:4000/x?ssl-mode=VERIFY_IDENTITY",
            ),
            ("DB_TLS_CA", "/etc/ssl/ca.pem"),
            ("KEK_PROVIDER", "env"),
            ("KEK_ENV_ACTIVE_ID", kek_id),
            ("JWT_ISSUER", "https://dsecure.test"),
            ("JWT_SIGNING_KID_MEMBER", member),
            ("JWT_SIGNING_KID_STAFF", staff),
            ("TRUSTED_PROXY_HOPS", "1"),
            ("TRUSTED_PROXY_CIDRS", "10.0.0.0/8"),
            ("BLOB_BACKEND", "fs"),
            ("BLOB_FS_ROOT", "/tmp/blobs"),
        ]
        .into_iter()
        .map(|(k, v)| (k.to_owned(), v.to_owned()))
        .collect();
        p.push((format!("KEK_ENV_{kek_id}"), kek.to_owned()));
        Env::from_pairs(p)
    }

    #[test]
    fn staging_with_dev_kek_fails() {
        let id = dev_kek_id().expect("id");
        let kek = generate_kek_b64().expect("kek");
        let env = pairs("staging", &id, &kek, "m-2026a", "s-2026a");
        let e = AppConfig::load_with(&env, &[&DevKeyCheck]).expect_err("dev kek in staging");
        assert!(e.has_key("KEK_ENV_ACTIVE_ID"), "{e}");
        assert!(!format!("{e} {e:?}").contains(&*kek));
    }

    #[test]
    fn staging_and_production_with_dev_signing_kid_fail() {
        for env_name in ["staging", "production"] {
            let env = pairs(
                env_name,
                "real_2026a",
                &generate_kek_b64().expect("kek"),
                &dev_signing_kid("member"),
                &dev_signing_kid("staff"),
            );
            let e = AppConfig::load_with(&env, &[&DevKeyCheck]).expect_err(env_name);
            assert!(e.has_key("JWT_SIGNING_KID_MEMBER"), "{env_name}: {e}");
            assert!(e.has_key("JWT_SIGNING_KID_STAFF"), "{env_name}: {e}");
        }
    }

    #[test]
    fn production_with_dev_kek_flagged_by_check_itself() {
        // production mein env provider waise bhi refuse hota hai; check khud bhi dev KEK pakadta hai.
        let id = dev_kek_id().expect("id");
        let env = pairs(
            "production",
            &id,
            &generate_kek_b64().expect("kek"),
            "m1",
            "s1",
        );
        let e = AppConfig::load_with(&env, &[&DevKeyCheck]).expect_err("rejected");
        assert!(e.has_key("KEK_ENV_ACTIVE_ID"));
    }

    #[test]
    fn dev_environment_allows_dev_keys_and_clean_staging_passes() {
        let id = dev_kek_id().expect("id");
        let env = pairs(
            "dev",
            &id,
            &generate_kek_b64().expect("kek"),
            &dev_signing_kid("member"),
            &dev_signing_kid("staff"),
        );
        AppConfig::load_with(&env, &[&DevKeyCheck]).expect("dev keys ok in dev");
        let env = pairs(
            "staging",
            "real_2026a",
            &generate_kek_b64().expect("kek"),
            "member-2026a",
            "staff-2026a",
        );
        AppConfig::load_with(&env, &[&DevKeyCheck]).expect("non-dev keys ok in staging");
    }
}
