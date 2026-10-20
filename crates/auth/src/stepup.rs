//! Step-up (RBAC.md §6.6, SECURITY.md §5, E19): after password re-entry the client gets a SEPARATE
//! opaque token `su1_...` (5 min). Its row in `step_up_tokens` binds it to session + action + target
//! (the row id is the `jti`); only an HMAC of the token is stored.
//!
//! Use: the handler calls [`crate::AuthService::consume_step_up`] for the request's exact action and
//! target BEFORE doing the protected action. The consume is ONE atomic `UPDATE ... used_at IS NULL`
//! under the unique token hash, so a replay, another session, another action or another target gets
//! nothing (no proof). If the action then fails, the proof is burned: fail closed, the user steps up
//! again. The resulting [`StepUpProof`] goes into `EvalContext`, and `Policy` checks it once more
//! (session, action, target) before allowing.

use common::SessionId;
use domain::rbac::{Subject, Target};
use zeroize::Zeroizing;

pub const STEP_UP_PREFIX: &str = "su1_";

/// The step-up token handed to the client once. `Debug` never shows it.
pub struct StepUpSecret(pub(crate) Zeroizing<String>);

impl StepUpSecret {
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Debug for StepUpSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("StepUpSecret([redacted])")
    }
}

/// A step-up token that was consumed in the DB for exactly this session, action and target.
/// Only `AuthService::consume_step_up` creates it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpProof {
    session: SessionId,
    action: String,
    target: Option<uuid::Uuid>,
}

impl StepUpProof {
    pub(crate) const fn new(
        session: SessionId,
        action: String,
        target: Option<uuid::Uuid>,
    ) -> Self {
        Self {
            session,
            action,
            target,
        }
    }

    #[must_use]
    pub const fn session(&self) -> SessionId {
        self.session
    }

    #[must_use]
    pub fn action(&self) -> &str {
        &self.action
    }

    #[must_use]
    pub const fn target(&self) -> Option<uuid::Uuid> {
        self.target
    }
}

/// The id a step-up is bound to for a policy target (device / member / group; `None` for list or
/// tenant-level actions).
#[must_use]
pub fn target_id(t: Option<&Target>) -> Option<uuid::Uuid> {
    match t.map(|t| &t.subject) {
        Some(Subject::Device(d)) => Some(d.0),
        Some(Subject::Member(m)) => Some(m.membership.0),
        Some(Subject::Group(g)) => Some(g.0),
        _ => None,
    }
}
