# dsecure-rs

Rust rewrite of the DSecure backend (Phase 0: foundation). Design docs are in `docs/`.

## Build and test

Toolchain is pinned in `rust-toolchain.toml` (Rust 1.99.1, rustfmt + clippy).

```
cargo build --workspace
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test -p common
cargo xtask <dev-keys|db-reset|route-policies|sqlx-prepare|loadtest>   # stubs for now
```

Local database (TiDB-compatible stand-in): `docker compose -f docker/compose.dev.yml up -d`.

## Secrets

No production secret, key, connection string or customer data is ever committed to this repo.
Dev keys are generated locally into `.dev/` (git-ignored); `.env*`, `*.pem` and `*.key` are ignored too.
