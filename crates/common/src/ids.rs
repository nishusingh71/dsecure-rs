//! Strongly typed ids over UUID v7 (time-ordered, index friendly).

macro_rules! id {
    ($n:ident, $doc:literal) => {
        #[doc = $doc]
        #[derive(
            Clone,
            Copy,
            Debug,
            PartialEq,
            Eq,
            Hash,
            PartialOrd,
            Ord,
            serde::Serialize,
            serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $n(pub uuid::Uuid);

        impl $n {
            /// Fresh time-ordered (UUID v7) id.
            // `Default` jaan-boojh kar nahi: random id ko "default value" banana galat hai.
            #[allow(clippy::new_without_default)]
            #[must_use]
            pub fn new() -> Self {
                Self(uuid::Uuid::now_v7())
            }

            #[must_use]
            pub const fn from_uuid(u: uuid::Uuid) -> Self {
                Self(u)
            }

            #[must_use]
            pub const fn as_uuid(&self) -> uuid::Uuid {
                self.0
            }
        }

        impl std::fmt::Display for $n {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl std::str::FromStr for $n {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                uuid::Uuid::parse_str(s).map(Self)
            }
        }

        impl From<uuid::Uuid> for $n {
            fn from(u: uuid::Uuid) -> Self {
                Self(u)
            }
        }
    };
}

id!(TenantId, "Tenant (customer organisation) id.");
id!(UserId, "Platform user id.");
id!(MembershipId, "Membership of a user in a tenant.");
id!(SessionId, "Login session id.");
id!(GroupId, "Group id.");
id!(DeviceId, "Enrolled device id.");
id!(GrantId, "Staff access grant id.");
id!(RequestId, "Per-request correlation id.");

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_is_v7_and_unique() {
        let a = TenantId::new();
        let b = TenantId::new();
        assert_ne!(a, b);
        assert_eq!(a.0.get_version_num(), 7);
    }

    #[test]
    fn display_parse_round_trip() {
        let id = UserId::new();
        let parsed: UserId = id.to_string().parse().expect("parse");
        assert_eq!(id, parsed);
        assert!("not-a-uuid".parse::<UserId>().is_err());
    }

    #[test]
    fn serde_is_transparent_string() {
        let id = SessionId::new();
        let json = serde_json::to_string(&id).expect("ser");
        assert_eq!(json, format!("\"{id}\""));
        let back: SessionId = serde_json::from_str(&json).expect("de");
        assert_eq!(back, id);
    }

    #[test]
    fn ids_are_roughly_time_ordered() {
        let a = RequestId::new();
        std::thread::sleep(std::time::Duration::from_millis(3));
        let b = RequestId::new();
        assert!(a < b);
    }
}
