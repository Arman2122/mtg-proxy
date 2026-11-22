#!/usr/bin/env bash
# Idempotent Ubuntu 24.04 LTS host bootstrap for mtg-proxy (dev & prod).
# Usage:
#   bootstrap-ubuntu.sh [--dev] [--version latest|v2.6.0]
set -euo pipefail

IS_DEV=0
VERSION="${MTG_VERSION:-latest}"
REPO="Arman2122/mtg-proxy"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dev) IS_DEV=1; shift ;;
    --version) VERSION="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

export DEBIAN_FRONTEND=noninteractive

echo "==> [1/6] Installing base packages, NTP (chrony), security updates & monitoring tools..."
apt-get update -qq
BASE_PKGS=(ca-certificates curl tar jq chrony unattended-upgrades htop iproute2 procps)
if [[ "$IS_DEV" -eq 1 ]]; then
  BASE_PKGS+=(git build-essential pkg-config libssl-dev rsync gdb strace)
fi
apt-get install -y -qq --no-install-recommends "${BASE_PKGS[@]}"
systemctl enable --now chrony

echo "==> [2/6] Hardening SSH (key-only authentication)..."
mkdir -p /etc/ssh/sshd_config.d
cat >/etc/ssh/sshd_config.d/99-mtg-hardening.conf <<'EOF'
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitRootLogin prohibit-password
PubkeyAuthentication yes
MaxAuthTries 4
ClientAliveInterval 60
ClientAliveCountMax 3
EOF
sshd -t && systemctl reload ssh || true

echo "==> [3/6] Creating dedicated non-root 'mtg' service account & directories..."
if ! id -u mtg >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin --user-group mtg
fi
install -d -o mtg -g mtg -m 0750 /etc/mtg-proxy /var/lib/mtg-proxy

echo "==> [4/6] Applying Linux kernel BBR + high-concurrency sysctl profile..."
modprobe tcp_bbr 2>/dev/null || true
cat >/etc/sysctl.d/99-mtg-proxy.conf <<'EOF'
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 10240 65535
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_notsent_lowat = 16384
fs.file-max = 2097152
EOF
sysctl --system >/dev/null

echo "==> [5/6] Downloading & SHA-256 verifying mtg-proxy ${VERSION} release binary..."
if [[ "$VERSION" == "latest" ]]; then
  VERSION="$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)"
  if [[ -z "$VERSION" ]]; then
    echo "ERROR: could not resolve latest release tag from GitHub" >&2
    exit 1
  fi
fi
ARCH="$(uname -m)"
case "$ARCH" in
  x86_64)  ASSET_ARCH="linux-amd64" ;;
  aarch64) ASSET_ARCH="linux-arm64" ;;
  *) echo "Unsupported arch: $ARCH" >&2; exit 1 ;;
esac

VER_NUM="${VERSION#v}"
TARBALL="mtg-proxy-${VER_NUM}-${ASSET_ARCH}.tar.gz"
CHECKSUMS="mtg-proxy-${VER_NUM}-checksums.txt"
BASE_URL="https://github.com/${REPO}/releases/download/${VERSION}"

TMPDIR="$(mktemp -d)"
trap 'rm -rf "$TMPDIR"' EXIT
curl -fsSL "${BASE_URL}/${TARBALL}" -o "${TMPDIR}/${TARBALL}"
curl -fsSL "${BASE_URL}/${CHECKSUMS}" -o "${TMPDIR}/${CHECKSUMS}"
(cd "$TMPDIR" && grep -F "${TARBALL}" "${CHECKSUMS}" | sha256sum -c -)
tar -C "$TMPDIR" -xzf "${TMPDIR}/${TARBALL}"

PKG_DIR="${TMPDIR}/mtg-proxy-${VER_NUM}-${ASSET_ARCH}"
install -m 0755 "${PKG_DIR}/mtg-proxy" /usr/local/bin/mtg-proxy
install -m 0644 "${PKG_DIR}/deploy/systemd/mtg-proxy.service" /etc/systemd/system/mtg-proxy.service
install -m 0644 "${PKG_DIR}/deploy/sysctl.d/99-mtg-proxy.conf" /etc/sysctl.d/99-mtg-proxy.conf
sysctl --system >/dev/null
DEF_IFACE="$(ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
if [[ -n "$DEF_IFACE" ]]; then
  tc qdisc replace dev "$DEF_IFACE" root fq 2>/dev/null || true
fi
systemctl daemon-reload

echo "==> [6/6] Installed $(/usr/local/bin/mtg-proxy --version)"

if [[ "$IS_DEV" -eq 1 ]]; then
  echo "==> [DEV] Installing Rust stable toolchain & cloning repository to /opt/mtg-proxy-src..."
  if [[ ! -x /root/.cargo/bin/cargo ]]; then
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --component clippy,rustfmt
  fi
  if [[ ! -d /opt/mtg-proxy-src/.git ]]; then
    git clone "https://github.com/${REPO}.git" /opt/mtg-proxy-src
  else
    git -C /opt/mtg-proxy-src fetch --all --prune
    git -C /opt/mtg-proxy-src pull --ff-only origin main || true
  fi
  # Ensure 2 GiB swapfile exists on 2 GiB RAM dev host so full LTO release builds never OOM!
  if [[ ! -f /swapfile ]]; then
    fallocate -l 2G /swapfile
    chmod 600 /swapfile
    mkswap /swapfile >/dev/null
    swapon /swapfile
    grep -q '^/swapfile ' /etc/fstab || echo '/swapfile none swap sw 0 0' >> /etc/fstab
  fi
fi

echo "==> Bootstrap complete."
