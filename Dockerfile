# Multi-stage pure-Rust Linux container build for mtg-proxy (linux/amd64 & linux/arm64)
# Runs the Rust compiler natively on $BUILDPLATFORM (zero slow QEMU emulation!)
# and cross-compiles to $TARGETARCH when building multi-arch manifests.
FROM --platform=$BUILDPLATFORM rust:1-slim-bookworm AS builder

ARG BUILDARCH
ARG TARGETARCH
ARG VERSION=""
ENV MTG_BUILD_VERSION=${VERSION}

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates pkg-config make gcc libc6-dev \
    && if [ "$BUILDARCH" != "$TARGETARCH" ] && [ "$TARGETARCH" = "arm64" ]; then \
         apt-get install -y --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
         && rustup target add aarch64-unknown-linux-gnu; \
       elif [ "$BUILDARCH" != "$TARGETARCH" ] && [ "$TARGETARCH" = "amd64" ]; then \
         apt-get install -y --no-install-recommends gcc-x86-64-linux-gnu libc6-dev-amd64-cross \
         && rustup target add x86_64-unknown-linux-gnu; \
       fi \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY tests ./tests
COPY example.config.toml ./

RUN set -eu; \
    if [ "$BUILDARCH" = "$TARGETARCH" ]; then \
      cargo build --release --locked --bin mtg-proxy; \
      BIN_PATH="target/release/mtg-proxy"; \
    elif [ "$TARGETARCH" = "arm64" ]; then \
      export CC_aarch64_unknown_linux_gnu=aarch64-linux-gnu-gcc; \
      export CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-linux-gnu-gcc; \
      cargo build --release --locked --target aarch64-unknown-linux-gnu --bin mtg-proxy; \
      BIN_PATH="target/aarch64-unknown-linux-gnu/release/mtg-proxy"; \
    elif [ "$TARGETARCH" = "amd64" ]; then \
      export CC_x86_64_unknown_linux_gnu=x86_64-linux-gnu-gcc; \
      export CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=x86_64-linux-gnu-gcc; \
      cargo build --release --locked --target x86_64-unknown-linux-gnu --bin mtg-proxy; \
      BIN_PATH="target/x86_64-unknown-linux-gnu/release/mtg-proxy"; \
    else \
      echo "Unsupported TARGETARCH=$TARGETARCH" >&2; exit 1; \
    fi; \
    mkdir -p /rootfs/config /rootfs/usr/local/bin; \
    cp "$BIN_PATH" /rootfs/usr/local/bin/mtg-proxy; \
    ln -s /usr/local/bin/mtg-proxy /rootfs/mtg; \
    cp example.config.toml /rootfs/config.toml; \
    ln -s /config.toml /rootfs/config/config.toml

# Distroless glibc runtime (~20 MiB total image, includes CA certs & libgcc_s)
FROM gcr.io/distroless/cc-debian12

COPY --from=builder /rootfs/ /

# Bundled /config/config.toml works out of the box with env-var overrides:
#   docker run -d -p 443:443 -e SECRET=... -e SECRET_HOST=... ghcr.io/arman2122/mtg-proxy
# For hardened non-root execution, pass: --user 65534:65534
EXPOSE 443/tcp
ENTRYPOINT ["/usr/local/bin/mtg-proxy"]
CMD ["run", "/config/config.toml"]
