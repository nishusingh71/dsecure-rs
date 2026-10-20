# syntax=docker/dockerfile:1
# Multi-stage: build (rust) -> runtime (distroless/cc, non-root). Image tags not verified here.
FROM rust:1.99-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p api -p workers

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime
COPY --from=build /src/target/release/dsecure-api /usr/local/bin/dsecure-api
COPY --from=build /src/target/release/dsecure-workers /usr/local/bin/dsecure-workers
USER nonroot:nonroot
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/dsecure-api"]
