#!/usr/bin/env bash
# Universal Linux installer for mtg-proxy (x86_64 & aarch64).
# Downloads the latest (or pinned) GitHub Release, verifies its SHA-256 checksum,
# installs /usr/local/bin/mtg-proxy, creates the dedicated 'mtg' system user,
# installs hardened systemd units, and applies Linux BBR + FQ kernel tuning.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/Arman2122/mtg-proxy/main/deploy/scripts/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/Arman2122/mtg-proxy/main/deploy/scripts/install.sh | sudo bash -s -- --version v2.6.0
#   sudo ./deploy/scripts/install.sh --uninstall
set -euo pipefail

REPO="Arman2122/mtg-proxy"
VERSION="${MTG_VERSION:-latest}"
INSTALL_BIN="/usr/local/bin/mtg-proxy"
CONFIG_DIR="/etc/mtg-proxy"
STATE_DIR="/var/lib/mtg-proxy"
SKIP_SYSTEMD=0
SKIP_SYSCTL=0
UNINSTALL=0

usage() {
  cat <<'EOF'
Usage: install.sh [OPTIONS]

Options:
  --version <tag>   Install a specific release tag (e.g. v2.6.0). Default: latest
  --no-systemd      Skip installing/reloading systemd service files
  --no-sysctl       Skip applying Linux BBR + FQ kernel tuning
  --uninstall       Remove binary and systemd units (keeps /etc/mtg-proxy & /var/lib/mtg-proxy)
  -h, --help        Show this help message
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || { echo "ERROR: --version requires a value" >&2; exit 2; }
      VERSION="$2"
      shift 2
      ;;
    --no-systemd) SKIP_SYSTEMD=1; shift ;;
    --no-sysctl)  SKIP_SYSCTL=1; shift ;;
    --uninstall)  UNINSTALL=1; shift ;;
    -h|--help)    usage; exit 0 ;;
    *)            echo "ERROR: Unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ "$(uname -s)" != "Linux" ]]; then
  echo "ERROR: mtg-proxy targets Linux exclusively (detected: $(uname -s))." >&2
  exit 1
fi

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "ERROR: Please run as root (e.g. via sudo)." >&2
  exit 1
fi

if [[ "$UNINSTALL" -eq 1 ]]; then
  echo "==> Uninstalling mtg-proxy..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now mtg-proxy.service 2>/dev/null || true
    systemctl disable --now mtg-web-relay.service 2>/dev/null || true
    rm -f /etc/systemd/system/mtg-proxy.service /etc/systemd/system/mtg-web-relay.service
    systemctl daemon-reload 2>/dev/null || true
  fi
  rm -f "$INSTALL_BIN" "${INSTALL_BIN}.prev" /etc/sysctl.d/99-mtg-proxy.conf
  echo "==> Removed binary and systemd units."
  echo "    Config and state preserved at ${CONFIG_DIR} and ${STATE_DIR} (remove manually if desired)."
  exit 0
fi

for cmd in curl tar sha256sum; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "ERROR: Required command '${cmd}' is not installed." >&2
    exit 1
  fi
done

ARCH="$(uname -m)"
case "$ARCH" in
  x86_64|amd64)   ASSET_ARCH="linux-amd64" ;;
  aarch64|arm64)  ASSET_ARCH="linux-arm64" ;;
  *)
    echo "ERROR: Unsupported architecture '${ARCH}' (supported: x86_64, aarch64)." >&2
    exit 1
    ;;
esac

if [[ "$VERSION" == "latest" ]]; then
  echo "==> Resolving latest release tag from GitHub..."
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" \
    | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  if [[ -z "$VERSION" ]]; then
    echo "ERROR: Could not resolve latest release tag from GitHub API." >&2
    exit 1
  fi
fi

VER_NUM="${VERSION#v}"
TARBALL="mtg-proxy-${VER_NUM}-${ASSET_ARCH}.tar.gz"
CHECKSUMS="mtg-proxy-${VER_NUM}-checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT

echo "==> [1/4] Downloading mtg-proxy ${VERSION} (${ASSET_ARCH})..."
curl -fsSL "${BASE_URL}/${TARBALL}" -o "${TMPDIR}/${TARBALL}"
curl -fsSL "${BASE_URL}/${CHECKSUMS}" -o "${TMPDIR}/${CHECKSUMS}"

echo "==> [2/4] Verifying SHA-256 checksum..."
(cd "$TMPDIR" && grep -F "  ${TARBALL}" "${CHECKSUMS}" | sha256sum -c -)
tar -C "$TMPDIR" -xzf "${TMPDIR}/${TARBALL}"

PKG_DIR="${TMPDIR}/mtg-proxy-${VER_NUM}-${ASSET_ARCH}"
if [[ -x "$INSTALL_BIN" ]]; then
  cp -f "$INSTALL_BIN" "${INSTALL_BIN}.prev"
fi
install -m 0755 "${PKG_DIR}/mtg-proxy" "$INSTALL_BIN"

echo "==> [3/4] Setting up dedicated 'mtg' system user & directories..."
if ! id -u mtg >/dev/null 2>&1; then
  NOLOGIN="$(command -v nologin || echo /usr/sbin/nologin)"
  useradd --system --no-create-home --shell "$NOLOGIN" --user-group mtg 2>/dev/null \
    || adduser --system --no-create-home --shell "$NOLOGIN" --group mtg
fi
install -d -o mtg -g mtg -m 0750 "$CONFIG_DIR" "$STATE_DIR"

if [[ ! -f "${CONFIG_DIR}/example.config.toml" ]] && [[ -f "${PKG_DIR}/example.config.toml" ]]; then
  install -o root -g mtg -m 0640 "${PKG_DIR}/example.config.toml" "${CONFIG_DIR}/example.config.toml"
fi

echo "==> [4/4] Installing systemd units & Linux kernel BBR/FQ tuning..."
if [[ "$SKIP_SYSTEMD" -eq 0 ]] && command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
  install -m 0644 "${PKG_DIR}/deploy/systemd/mtg-proxy.service" /etc/systemd/system/mtg-proxy.service
  install -m 0644 "${PKG_DIR}/deploy/systemd/mtg-web-relay.service" /etc/systemd/system/mtg-web-relay.service
  systemctl daemon-reload
fi

if [[ "$SKIP_SYSCTL" -eq 0 ]] && [[ -d /etc/sysctl.d ]]; then
  modprobe tcp_bbr 2>/dev/null || true
  install -m 0644 "${PKG_DIR}/deploy/sysctl.d/99-mtg-proxy.conf" /etc/sysctl.d/99-mtg-proxy.conf
  sysctl --system >/dev/null 2>&1 || true
  # Apply fq pacing immediately on the default egress interface (default_qdisc only affects new NICs).
  if command -v tc >/dev/null 2>&1 && command -v ip >/dev/null 2>&1; then
    DEF_IFACE="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
    if [[ -n "$DEF_IFACE" ]]; then
      tc qdisc replace dev "$DEF_IFACE" root fq 2>/dev/null || true
    fi
  fi
fi

echo ""
echo "Installed: $("${INSTALL_BIN}" --version)"
echo ""
if [[ -f "${CONFIG_DIR}/config.toml" ]]; then
  echo "Existing config found at ${CONFIG_DIR}/config.toml (left untouched)."
  echo "Validate & restart with:"
  echo "  sudo mtg-proxy run --check ${CONFIG_DIR}/config.toml"
  echo "  sudo systemctl restart mtg-proxy"
else
  echo "Next steps (takes ~60 seconds):"
  echo "  1. Generate a FakeTLS secret (use your own domain or a real TLS 1.3 cover host):"
  echo "       mtg-proxy generate-secret --hex example.com"
  echo "  2. Create ${CONFIG_DIR}/config.toml (see ${CONFIG_DIR}/example.config.toml or README.md)"
  echo "       sudo chown root:mtg ${CONFIG_DIR}/config.toml && sudo chmod 0640 ${CONFIG_DIR}/config.toml"
  echo "  3. Validate & diagnose:"
  echo "       sudo mtg-proxy doctor ${CONFIG_DIR}/config.toml"
  echo "  4. Start on boot & print your tg:// proxy links:"
  echo "       sudo systemctl enable --now mtg-proxy"
  echo "       sudo mtg-proxy access ${CONFIG_DIR}/config.toml"
fi
