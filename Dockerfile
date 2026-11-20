# Multi-stage pure-Rust Linux container build for mtg-proxy (linux/amd64 & linux/arm64)
FROM rust:1-slim-bookworm AS builder

ARG VERSION=""
ENV MTG_BUILD_VERSION=${VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates pkg-config make gcc libc6-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tests ./tests
COPY example.config.toml ./

RUN cargo build --release --locked --bin mtg-proxy \
    && mkdir -p /rootfs/config /rootfs/usr/local/bin \
    && cp target/release/mtg-proxy /rootfs/usr/local/bin/mtg-proxy \
    && ln -s /usr/local/bin/mtg-proxy /rootfs/mtg \
    && cp example.config.toml /rootfs/config.toml \
    && ln -s /config.toml /rootfs/config/config.toml

# Distroless glibc runtime (~20 MiB total image, includes CA certs & libgcc_s)
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /rootfs/ /

# Bundled /config/config.toml works out of the box with env-var overrides:
#   docker run -d -p 443:443 -e SECRET=... -e SECRET_HOST=... ghcr.io/arman2122/mtg-proxy
# For hardened non-root execution, pass: --user 65534:65534
EXPOSE 443/tcp
ENTRYPOINT ["/usr/local/bin/mtg-proxy"]
CMD ["run", "/config/config.toml"]
