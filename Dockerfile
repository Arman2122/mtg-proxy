# Multi-stage pure-Rust Linux container build for mtg-proxy (amd64 & arm64)
FROM rust:1-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config make gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tests ./tests

RUN cargo build --release --locked --bin mtg-proxy \
    && strip target/release/mtg-proxy

FROM gcr.io/distroless/cc-debian12:nonroot

COPY --from=builder /src/target/release/mtg-proxy /usr/local/bin/mtg-proxy

EXPOSE 443/tcp
ENTRYPOINT ["/usr/local/bin/mtg-proxy"]
CMD ["--version"]
