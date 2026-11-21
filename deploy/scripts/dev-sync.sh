#!/usr/bin/env bash
# Fast developer sync, remote Linux release build, test & live deploy on dev droplet.
# Usage:
#   ./deploy/scripts/dev-sync.sh [ssh-host] [--test] [--restart]
set -euo pipefail

HOST="${1:-mtg-dev}"
shift || true
RUN_TESTS=0
DO_RESTART=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --test) RUN_TESTS=1; shift ;;
    --restart) DO_RESTART=1; shift ;;
    *) echo "Unknown flag: $1" >&2; exit 2 ;;
  esac
done

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
echo "==> Syncing ${ROOT_DIR} -> ${HOST}:/opt/mtg-proxy-src ..."
rsync -az --delete \
  --exclude '/target/' \
  --exclude '/fuzz/target/' \
  --exclude '/.git/' \
  --exclude '/.deploy-local/' \
  --exclude '/graphify-out/' \
  --exclude '/dist/' \
  "${ROOT_DIR}/" "${HOST}:/opt/mtg-proxy-src/"

ssh -o BatchMode=yes "$HOST" bash -s -- "$RUN_TESTS" "$DO_RESTART" <<'REMOTE'
set -euo pipefail
export PATH="$HOME/.cargo/bin:$PATH"
cd /opt/mtg-proxy-src
RUN_TESTS="$1"
DO_RESTART="$2"

if [[ "$RUN_TESTS" -eq 1 ]]; then
  echo "==> Running cargo test --workspace on dev droplet..."
  cargo test --workspace
fi

echo "==> Building release mtg-proxy & mtg-bench on dev droplet..."
cargo build --release --locked --bin mtg-proxy --bin mtg-bench

if [[ "$DO_RESTART" -eq 1 ]]; then
  echo "==> Installing newly built binary & restarting dev service..."
  install -m 0755 target/release/mtg-proxy /usr/local/bin/mtg-proxy.new
  /usr/local/bin/mtg-proxy.new doctor --skip-native-check /etc/mtg-proxy/config.toml >/dev/null
  cp -f /usr/local/bin/mtg-proxy /usr/local/bin/mtg-proxy.prev 2>/dev/null || true
  mv -f /usr/local/bin/mtg-proxy.new /usr/local/bin/mtg-proxy
  systemctl restart mtg-proxy.service
  sleep 1
  systemctl is-active --quiet mtg-proxy.service
  echo "==> Dev running: $(/usr/local/bin/mtg-proxy --version)"
fi
REMOTE
