#!/usr/bin/env bash
set -euo pipefail

REPO="me3i/riftlock"
INSTALL_DIR="${RIFTLOCK_INSTALL_DIR:-/usr/local/bin}"

info() { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$1" >&2; }
fail() { printf '\033[1;31m[-] Error:\033[0m %s\n' "$1" >&2; exit 1; }

have_cargo() { command -v cargo >/dev/null 2>&1; }
have_cc() { command -v cc >/dev/null 2>&1 || command -v gcc >/dev/null 2>&1 || command -v clang >/dev/null 2>&1; }

# Download helpers shared by the release, source, and rustup fetches.
download() { # download <url> <output>
  if command -v curl >/dev/null 2>&1; then
    curl -fL --proto '=https' --tlsv1.2 --retry 5 --connect-timeout 15 "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$1" -O "$2"
  else
    fail "curl or wget is required to download files."
  fi
}

install_rust() {
  info "Installing Rust and Cargo via rustup..."
  local installer="$WORK_DIR/rustup-init.sh"
  download https://sh.rustup.rs "$installer" \
    || fail "Could not download the rustup installer from https://sh.rustup.rs."
  sh "$installer" -y --profile minimal \
    || fail "Rust installation failed. See https://rustup.rs for manual setup."
  if [[ -f "$HOME/.cargo/env" ]]; then
    # shellcheck disable=SC1091
    . "$HOME/.cargo/env"
  fi
  have_cargo || fail "Rust was installed but Cargo is not available on PATH. Open a new shell and rerun './install.sh'."
}

ensure_rust() {
  have_cargo && return 0

  case "${RIFTLOCK_INSTALL_RUST:-1}" in
    0|false|no)
      fail "Rust and Cargo are required to build from source. Install them from https://rustup.rs and rerun './install.sh', or rerun with RIFTLOCK_INSTALL_RUST=1. Prebuilt release binaries (no Rust needed) are available at https://github.com/${REPO}/releases."
      ;;
    1|true|yes|'') ;;
    *) fail "RIFTLOCK_INSTALL_RUST must be '1' or '0'." ;;
  esac

  install_rust
}

build_tools_hint() {
  if command -v apt-get >/dev/null 2>&1; then
    printf '    sudo apt-get update && sudo apt-get install -y build-essential pkg-config\n'
  elif command -v dnf >/dev/null 2>&1; then
    printf '    sudo dnf install -y gcc gcc-c++ make pkg-config\n'
  elif command -v pacman >/dev/null 2>&1; then
    printf '    sudo pacman -S --needed base-devel pkg-config\n'
  elif command -v zypper >/dev/null 2>&1; then
    printf '    sudo zypper install -y gcc gcc-c++ make pkg-config\n'
  elif command -v apk >/dev/null 2>&1; then
    printf '    sudo apk add build-base pkg-config\n'
  else
    printf '    Install a C compiler, make, and pkg-config with your package manager.\n'
  fi
}

ensure_cc() {
  have_cc && return 0
  printf '[-] Error: a C compiler is required to build Riftlock from source.\n' >&2
  printf '    Install the build tools for your distribution, then rerun the installer:\n' >&2
  build_tools_hint >&2
  exit 1
}

# When the installer is run outside a checkout, fetch the repository so the
# source fallback can still work from the curl one-liner.
fetch_source() {
  info "No source checkout found; fetching the Riftlock repository..."
  local src="$WORK_DIR/src"
  mkdir -p -- "$src"

  if command -v git >/dev/null 2>&1 && git clone --depth 1 "https://github.com/${REPO}.git" "$src" >/dev/null 2>&1; then
    SCRIPT_DIR="$src"
    return 0
  fi

  local tarball="$WORK_DIR/riftlock.tar.gz"
  if download "https://codeload.github.com/${REPO}/tar.gz/refs/heads/main" "$tarball" \
    && tar -xzf "$tarball" -C "$src" --strip-components=1; then
    SCRIPT_DIR="$src"
    return 0
  fi

  fail "Could not fetch the Riftlock source. Check your network connection, or clone https://github.com/${REPO}.git manually and run './install.sh' from the repository."
}

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
    curl -fL --retry 5 --connect-timeout 15 --progress-bar "$BASE_URL/$ASSET" -o "$BINARY" || DOWNLOAD_FAILED=1
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$BASE_URL/$ASSET" -O "$BINARY" || DOWNLOAD_FAILED=1
  else
    fail "curl or wget is required to download a release."
  fi

  if [[ "$DOWNLOAD_FAILED" == 1 ]]; then
    rm -f -- "$BINARY"

    if [[ ! -f "$SCRIPT_DIR/Cargo.toml" ]]; then
      fetch_source
    fi

    ensure_cc
    ensure_rust

    info "No published release asset found; building from source with Cargo..."
    (cd -- "$SCRIPT_DIR" && cargo build --release -p riftlock-cli) \
      || fail "Source build failed. Run 'cargo build --release -p riftlock-cli' in the repository for details."
    SOURCE_BINARY="$SCRIPT_DIR/target/release/riftlock"
    [[ -s "$SOURCE_BINARY" ]] || fail "Source build completed but the Riftlock binary was not found."
    cp -- "$SOURCE_BINARY" "$BINARY"
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
  { : >/dev/tty; } 2>/dev/null || fail "Administrator access is required, but no terminal is available for a secure sudo password prompt. Set RIFTLOCK_INSTALL_DIR to a writable directory."
  sudo -S -p '[sudo] Password: ' install -D -m 0755 -- "$BINARY" "$DEST" </dev/tty \
    || fail "Installation to $DEST failed."
fi

printf '\033[1;32m[✓]\033[0m Riftlock installed: %s\n' "$DEST"
case ":${PATH:-}:" in
  *":$INSTALL_DIR:"*) ;;
  *) warn "$INSTALL_DIR is not in PATH. Add it to your shell profile to run 'riftlock' directly." ;;
esac
