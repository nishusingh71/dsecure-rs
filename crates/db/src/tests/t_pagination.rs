//! T-DB6: keyset pagination is stable under concurrent inserts; tampered cursor -> error.

use super::fixtures::{CURSOR_KEY, add_member, new_tenant};
use super::harness::with_db;
use crate::repo::memberships;
use common::{AppErrorKind, Page};
use domain::rbac::TenantRole;
use std::collections::HashSet;

#[tokio::test]
async fn keyset_stable_under_inserts_and_cursor_tamper_rejected() {
    with_db("pagination", |db, _| async move {
        let a = new_tenant(&db).await;
        let mut original = HashSet::from([a.owner]);
        for _ in 0..24 {
            original.insert(add_member(&db, &a, TenantRole::Member).await);
        }
        assert_eq!(original.len(), 25);

        let mut seen = Vec::new();
        let mut after: Option<String> = None;
        let mut pages = 0;
        loop {
            let page = Page::parse(Some(10), after.as_deref(), CURSOR_KEY).expect("page");
            let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
            let out = memberships::list(&mut tx, &page, CURSOR_KEY)
                .await
                .expect("list");
            tx.commit().await.expect("c");
            // Strictly descending ids inside a page.
            assert!(out.data.windows(2).all(|w| w[0].id.0 > w[1].id.0));
            seen.extend(out.data.iter().map(|m| m.id));
            pages += 1;
            if pages == 1 {
                // Inserts between pages land "before" the cursor (newer ids) and never shift pages.
                for _ in 0..5 {
                    add_member(&db, &a, TenantRole::Member).await;
                }
            }
            match out.next_cursor {
                Some(c) => after = Some(c),
                None => break,
            }
        }
        assert_eq!(pages, 3);
        let uniq: HashSet<_> = seen.iter().copied().collect();
        assert_eq!(uniq.len(), seen.len(), "no duplicates");
        assert_eq!(uniq, original, "exactly the rows that existed at page 1");

        // Tampered cursor: any flipped char -> cursor_invalid (400).
        let page = Page::parse(Some(10), None, CURSOR_KEY).expect("p");
        let mut tx = db.tenant_tx(&a.scope()).await.expect("tx");
        let out = memberships::list(&mut tx, &page, CURSOR_KEY)
            .await
            .expect("l");
        tx.rollback().await;
        let c = out.next_cursor.expect("next");
        let mut bytes = c.into_bytes();
        bytes[5] = if bytes[5] == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(bytes).expect("utf8");
        let e = Page::parse(Some(10), Some(&tampered), CURSOR_KEY).expect_err("tampered");
        assert_eq!(
            (e.kind, e.code),
            (AppErrorKind::BadRequest, "cursor_invalid")
        );
        let e = Page::parse(Some(10), Some(&tampered), b"another-key-0123456789abcdef!!")
            .expect_err("x");
        assert_eq!(e.code, "cursor_invalid");
    })
    .await;
}
