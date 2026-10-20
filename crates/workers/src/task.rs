//! `bounded_spawn`: the only way workers start tasks (`tokio::spawn` is a disallowed method).
//! A task can only be spawned while holding a semaphore permit, so the number of live tasks is
//! bounded by the semaphore size. (Lives here, not in `common`, because `common` is IO-free.)

use std::future::Future;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::task::JoinSet;

/// Try to take a permit without waiting. `None` = pool is full.
#[must_use]
pub fn try_permit(sem: &Arc<Semaphore>) -> Option<OwnedSemaphorePermit> {
    Arc::clone(sem).try_acquire_owned().ok()
}

/// Spawn `fut` into `set`; the permit is held until the future finishes.
pub fn bounded_spawn<F>(set: &mut JoinSet<()>, permit: OwnedSemaphorePermit, fut: F)
where
    F: Future<Output = ()> + Send + 'static,
{
    set.spawn(async move {
        let _permit = permit;
        fut.await;
    });
}
