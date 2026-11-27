#!/usr/bin/env bash
set -euo pipefail

REPO="me3i/riftlock"
INSTALL_DIR="${RIFTLOCK_INSTALL_DIR:-/usr/local/bin}"

info() { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1" >&2; }
fail() { printf '\033[1;31m[-] Error:\033[0m %s\n' "$1" >&2; exit 1; }

[[ "$(uname -s)" == Linux ]] || fail "Riftlock's release installer supports Linux only."

case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) fail "Unsupported architecture: $(uname -m). Supported: x86_64, aarch64." ;;
esac
TARGET="${ARCH}-unknown-linux-musl"
ASSET="riftlock-${TARGET}"

info "Detecting architecture... Linux ${ARCH}"

SCRIPT_SOURCE="${BASH_SOURCE[0]:-}"
if [[ -n "$SCRIPT_SOURCE" && -f "$SCRIPT_SOURCE" ]]; then
  SCRIPT_DIR="$(cd -- "$(dirname -- "$SCRIPT_SOURCE")" && pwd)"
else
  SCRIPT_DIR="$PWD"
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf -- "$WORK_DIR"' EXIT
BINARY="$WORK_DIR/$ASSET"
CHECKSUM_FILE=""

if [[ -f "$SCRIPT_DIR/$ASSET" ]]; then
  info "Using offline bundle binary..."
  cp -- "$SCRIPT_DIR/$ASSET" "$BINARY"
  if [[ -f "$SCRIPT_DIR/checksums.txt" ]]; then
    CHECKSUM_FILE="$SCRIPT_DIR/checksums.txt"
  fi
else
  info "Fetching latest release..."
  BASE_URL="https://github.com/${REPO}/releases/latest/download"
  DOWNLOAD_FAILED=0
  if command -v curl >/dev/null 2>&1; then
    curl -fL --retry 5 --retry-all-errors --connect-timeout 15 --progress-bar "$BASE_URL/$ASSET" -o "$BINARY" || DOWNLOAD_FAILED=1
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$BASE_URL/$ASSET" -O "$BINARY" || DOWNLOAD_FAILED=1
  else
    fail "curl or wget is required to download a release."
  fi

  if [[ "$DOWNLOAD_FAILED" == 1 ]]; then
    rm -f -- "$BINARY"
    if [[ -f "$SCRIPT_DIR/Cargo.toml" ]] && command -v cargo >/dev/null 2>&1; then
      info "No published release asset found; building from source with Cargo..."
      (cd -- "$SCRIPT_DIR" && cargo build --release -p riftlock-cli) \
        || fail "Source build failed. Run 'cargo build --release -p riftlock-cli' in the repository for details."
      SOURCE_BINARY="$SCRIPT_DIR/target/release/riftlock"
      [[ -s "$SOURCE_BINARY" ]] || fail "Source build completed but the Riftlock binary was not found."
      cp -- "$SOURCE_BINARY" "$BINARY"
    else
      fail "No published release asset found for $ASSET. Clone the repository, install Rust/Cargo, then run './install.sh' to build from source."
    fi
  else
    if command -v curl >/dev/null 2>&1; then
      curl -fsSL "$BASE_URL/checksums.txt" -o "$WORK_DIR/checksums.txt" || rm -f -- "$WORK_DIR/checksums.txt"
    else
      wget -q "$BASE_URL/checksums.txt" -O "$WORK_DIR/checksums.txt" || rm -f -- "$WORK_DIR/checksums.txt"
    fi
    if [[ -s "$WORK_DIR/checksums.txt" ]]; then
      CHECKSUM_FILE="$WORK_DIR/checksums.txt"
    else
      rm -f -- "$WORK_DIR/checksums.txt"
      warn "No release checksum file was available; the download could not be checksum-verified."
    fi
  fi
fi

[[ -s "$BINARY" ]] || fail "The downloaded/offline binary is missing or empty."

if [[ -n "$CHECKSUM_FILE" ]]; then
  info "Verifying SHA256 checksum..."
  EXPECTED="$(awk -v file="$ASSET" '$2 == file { print $1; count++ } END { if (count != 1) exit 1 }' "$CHECKSUM_FILE")" \
    || fail "checksums.txt must contain exactly one entry for $ASSET."
  [[ "$EXPECTED" =~ ^[[:xdigit:]]{64}$ ]] || fail "Invalid SHA256 entry for $ASSET."
  ACTUAL="$(sha256sum "$BINARY" | awk '{print $1}')"
  [[ "${ACTUAL,,}" == "${EXPECTED,,}" ]] || fail "SHA256 checksum mismatch for $ASSET."
  printf '    SHA256 verified: %.12s…\n' "$ACTUAL"
else
  warn "Proceeding without checksum verification."
fi

[[ -n "$INSTALL_DIR" ]] || fail "RIFTLOCK_INSTALL_DIR cannot be empty."
DEST="$INSTALL_DIR/riftlock"
info "Installing to ${INSTALL_DIR}..."
if [[ -d "$INSTALL_DIR" && -w "$INSTALL_DIR" ]]; then
  install -D -m 0755 -- "$BINARY" "$DEST"
else
  command -v sudo >/dev/null 2>&1 || fail "Cannot write to $INSTALL_DIR and sudo is not installed. Set RIFTLOCK_INSTALL_DIR to a writable directory."
  [[ -r /dev/tty ]] || fail "Administrator access is required, but no terminal is available for a secure sudo password prompt. Set RIFTLOCK_INSTALL_DIR to a writable directory."
  sudo -S -p '[sudo] Password: ' install -D -m 0755 -- "$BINARY" "$DEST" </dev/tty \
    || fail "Installation to $DEST failed."
fi

printf '\033[1;32m[✓]\033[0m Riftlock installed: %s\n' "$DEST"
case ":${PATH:-}:" in
  *":$INSTALL_DIR:"*) ;;
  *) warn "$INSTALL_DIR is not in PATH. Add it to your shell profile to run 'riftlock' directly." ;;
esac
