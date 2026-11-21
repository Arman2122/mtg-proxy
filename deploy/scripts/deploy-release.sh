#!/usr/bin/env bash
# Atomic, SHA-256 verified release deployer with automatic healthcheck rollback.
# Usage:
#   ./deploy/scripts/deploy-release.sh <ssh-host> [vX.Y.Z|latest]
# Example:
#   ./deploy/scripts/deploy-release.sh mtg-prod v2.0.1
set -euo pipefail

HOST="${1:?Usage: $0 <ssh-host> [vX.Y.Z|latest]}"
VERSION="${2:-latest}"
REPO="Arman2122/mtg-proxy"

if [[ "$VERSION" == "latest" ]]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  if [[ -z "$VERSION" ]]; then
    echo "ERROR: could not resolve latest release tag from GitHub" >&2
    exit 1
  fi
fi

echo "==> Deploying ${REPO} ${VERSION} to ${HOST}..."
ssh -o BatchMode=yes -o ConnectTimeout=10 "$HOST" bash -s -- "$VERSION" "$REPO" <<'REMOTE'
set -euo pipefail
VERSION="$1"
REPO="$2"
VER_NUM="${VERSION#v}"

case "$(uname -m)" in
  x86_64)  ASSET_ARCH="linux-amd64" ;;
  aarch64) ASSET_ARCH="linux-arm64" ;;
  *) echo "Unsupported arch: $(uname -m)" >&2; exit 1 ;;
esac

TARBALL="mtg-proxy-${VER_NUM}-${ASSET_ARCH}.tar.gz"
CHECKSUMS="mtg-proxy-${VER_NUM}-checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "  [1/5] Downloading & verifying SHA-256 checksum..."
curl -fsSL "${BASE_URL}/${TARBALL}" -o "${TMPDIR}/${TARBALL}"
curl -fsSL "${BASE_URL}/${CHECKSUMS}" -o "${TMPDIR}/${CHECKSUMS}"
(cd "$TMPDIR" && grep -F "${TARBALL}" "${CHECKSUMS}" | sha256sum -c -)
tar -C "$TMPDIR" -xzf "${TMPDIR}/${TARBALL}"

PKG_DIR="${TMPDIR}/mtg-proxy-${VER_NUM}-${ASSET_ARCH}"
install -m 0755 "${PKG_DIR}/mtg-proxy" /usr/local/bin/mtg-proxy.new

echo "  [2/5] Pre-flight validating /etc/mtg-proxy/config.toml with new binary..."
/usr/local/bin/mtg-proxy.new doctor --skip-native-check /etc/mtg-proxy/config.toml >/dev/null

echo "  [3/5] Preserving rollback copy & atomically swapping binary..."
if [[ -x /usr/local/bin/mtg-proxy ]]; then
  cp -f /usr/local/bin/mtg-proxy /usr/local/bin/mtg-proxy.prev
fi
mv -f /usr/local/bin/mtg-proxy.new /usr/local/bin/mtg-proxy

echo "  [4/5] Restarting mtg-proxy.service..."
systemctl restart mtg-proxy.service
sleep 2

if ! systemctl is-active --quiet mtg-proxy.service; then
  echo "  [ERROR] New binary failed to stay active! Rolling back..." >&2
  if [[ -x /usr/local/bin/mtg-proxy.prev ]]; then
    mv -f /usr/local/bin/mtg-proxy.prev /usr/local/bin/mtg-proxy
    systemctl restart mtg-proxy.service
  fi
  journalctl -u mtg-proxy.service -n 30 --no-pager >&2
  exit 1
fi

echo "  [5/5] Active: $(/usr/local/bin/mtg-proxy --version)"
API_BIND="$(sed -n 's/^api-bind-to = "\(.*\)"/\1/p' /etc/mtg-proxy/config.toml | head -n 1 || true)"
API_TOKEN="$(sed -n 's/^api-token = "\(.*\)"/\1/p' /etc/mtg-proxy/config.toml | head -n 1 || true)"
if [[ -n "$API_BIND" ]]; then
  if [[ -n "$API_TOKEN" ]]; then
    curl -fsS -H "Authorization: Bearer ${API_TOKEN}" "http://${API_BIND}/healthz" && echo ""
  else
    curl -fsS "http://${API_BIND}/healthz" && echo ""
  fi
fi
REMOTE
