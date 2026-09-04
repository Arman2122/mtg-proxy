###############################################################################
# BUILD STAGE

# Pinned to the exact Go release named in go.mod, by multi-arch index digest.
# Two reasons, both about the binary people actually run:
#   - the tag `1.26-alpine` floats to a newer patch release than the tagged
#     release binaries are built with, so the image and the tarball silently
#     stop being the same program;
#   - a tag is mutable, a digest is not.
# This is the manifest *index* digest, not a per-architecture manifest: the
# image is built for linux/amd64 and linux/arm64 and a single-arch digest would
# break one of them. Dependabot keeps it fresh (.github/dependabot.yml).
FROM golang:1.26.6-alpine@sha256:3889b425f035be855a72fb4755265311293b6d414521f0a519d819df32222d83 AS build

ENV CGO_ENABLED=0

# this is done for backward compatibility: before that we mounted a config
# into /config.toml. Some application allow mounting directories only,
# so it makes problems. So, instead we are going to do 2 steps:
#  1. Create /config/config.toml as a symlink to /config.toml
#  2. Force /mtg to use /config/config.toml
#
# it helps in both ways: users with directories could use /config directory
# and overlap a symlink by their bind mount. Old users could continue using
# /config.toml as a real config.
RUN set -x \
  && mkdir -p /config \
  && ln -sv /config.toml /config/config.toml

# ca-certificates for the bundle copied into the final image, git for the
# version string below. Nothing else: bash was installed and never used.
RUN --mount=type=cache,target=/var/cache/apk \
    set -x \
    && apk --update add \
      ca-certificates \
      git

COPY go.mod go.sum /app/
WORKDIR /app

RUN go mod download

COPY . /app

# The flags are deliberately identical to the ones .github/workflows/go.yml
# uses for the linux release binaries, so that this image ships the same
# program the tarballs do. What was dropped and why:
#   -a                      forced a rebuild of every dependency, costing
#                           minutes and changing nothing.
#   -tags netgo             CGO_ENABLED=0 already selects the pure Go resolver.
#   -extldflags '-static'   there is no external linker to pass it to.
# The `v` is stripped from the tag so the version string matches the release
# build, which embeds the tag without it.
RUN set -x \
  && version="$(git describe --exact-match HEAD 2>/dev/null || git describe --tags --always 2>/dev/null || echo dev)" \
  && version="${version#v}" \
  && go build \
      -o mtg \
      -trimpath \
      -mod=readonly \
      -ldflags="-s -w -X 'main.version=$version'"


###############################################################################
# PACKAGE STAGE

FROM scratch

# The bundled /config/config.toml is a working default; for a config-file-free
# setup (official telegrammessenger/proxy style) override it with environment
# variables: SECRET (full ee-secret, or a bare 16-byte hex key + SECRET_HOST),
# TAG (ad-tag from @MTProxybot) and MTG_BIND_TO (e.g. 0.0.0.0:443). See README.
#
# This runs as root. Recommended hardening is `docker run --user 65534:65534`;
# it is not baked in because it would break, on the next `docker pull`, every
# operator who bind-mounts a root-owned 0600 config or who runs on a runtime
# that does not set net.ipv4.ip_unprivileged_port_start=0. See the README's
# "Running with Docker" section.
ENTRYPOINT ["/mtg"]
CMD ["run", "/config/config.toml"]

COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /app/mtg /mtg
COPY --from=build /app/example.config.toml /config.toml
COPY --from=build /config /config
