# syntax=docker/dockerfile:1
# Multi-stage: build (rust) -> runtime (distroless/cc, non-root).
# - Rust image tag = exact `rust-toolchain.toml` channel (1.99.1), so rustup does not fetch another toolchain.
# - Linux build: `crates/api/Cargo.toml` turns on tikv-jemallocator + telemetry `jemalloc` automatically
#   (target cfg), no extra feature flag needed. Tuning via `_RJEM_MALLOC_CONF` (render.yaml).
# - Port: the api listens on `HTTP_ADDR` (default 0.0.0.0:8080, `config` crate); Render gets PORT=8080.
# - Build context: `.dockerignore` keeps `target/` and `.dev/` (local keys and DB credentials) out.
# - Not verified locally (no Docker on the dev machine, 20 Oct 2026): image tags, build, image size.
FROM rust:1.99.1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p api -p workers

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
# distroless/cc ships the Debian CA bundle at /etc/ssl/certs/ca-certificates.crt (DB_TLS_CA for TiDB Cloud).
COPY --from=build /src/target/release/dsecure-api /usr/local/bin/dsecure-api
COPY --from=build /src/target/release/dsecure-workers /usr/local/bin/dsecure-workers
ENV HTTP_ADDR=0.0.0.0:8080
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dsecure-api"]
