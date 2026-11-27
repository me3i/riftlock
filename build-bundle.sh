#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

fail() { printf '\033[1;31m[-] Error:\033[0m %s\n' "$1" >&2; exit 1; }
info() { printf '\033[1;32m[+]\033[0m %s\n' "$1"; }

command -v cargo >/dev/null 2>&1 || fail "Cargo is required to build release binaries."
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required to create bundle checksums."

VERSION="$(awk '
  /^\[package\]$/ { in_package=1; next }
  /^\[/ { in_package=0 }
  in_package && /^version[[:space:]]*=/ { gsub(/"/, "", $3); print $3; exit }
' crates/cli/Cargo.toml)"
[[ -n "$VERSION" ]] || fail "Could not read the CLI version from crates/cli/Cargo.toml."

HOST_ARCH="$(uname -m)"
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  case "$target" in
    x86_64-unknown-linux-musl) linker="${RIFTLOCK_X86_64_MUSL_CC:-musl-gcc}" ;;
    aarch64-unknown-linux-musl)
      if [[ "$HOST_ARCH" == aarch64 || "$HOST_ARCH" == arm64 ]]; then
        linker="${RIFTLOCK_AARCH64_MUSL_CC:-musl-gcc}"
      else
        linker="${RIFTLOCK_AARCH64_MUSL_CC:-aarch64-linux-musl-gcc}"
      fi
      ;;
  esac
  command -v "$linker" >/dev/null 2>&1 || fail "Missing musl linker '$linker' for $target. Install a matching musl cross-toolchain or set the corresponding RIFTLOCK_*_MUSL_CC variable."
done

if ! command -v rustup >/dev/null 2>&1; then
  fail "rustup is required to install/check the target standard libraries."
fi
for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  if ! rustup target list --installed | grep -Fxq "$target"; then
    info "Installing Rust target $target..."
    rustup target add "$target"
  fi
done

DIST="$ROOT/dist"
BUNDLE_NAME="riftlock-v${VERSION}-linux"
BUNDLE_DIR="$DIST/$BUNDLE_NAME"
ARCHIVE="$DIST/$BUNDLE_NAME.zip"
rm -rf -- "$BUNDLE_DIR" "$ARCHIVE"
mkdir -p -- "$BUNDLE_DIR"

for target in x86_64-unknown-linux-musl aarch64-unknown-linux-musl; do
  case "$target" in
    x86_64-unknown-linux-musl) linker="${RIFTLOCK_X86_64_MUSL_CC:-musl-gcc}" ;;
    aarch64-unknown-linux-musl)
      if [[ "$HOST_ARCH" == aarch64 || "$HOST_ARCH" == arm64 ]]; then
        linker="${RIFTLOCK_AARCH64_MUSL_CC:-musl-gcc}"
      else
        linker="${RIFTLOCK_AARCH64_MUSL_CC:-aarch64-linux-musl-gcc}"
      fi
      ;;
  esac
  info "Building $target..."
  linker_env="CARGO_TARGET_${target^^}_LINKER"
  linker_env="${linker_env//-/_}"
  env "$linker_env=$linker" cargo build --release -p riftlock-cli --target "$target"
  cp -- "target/$target/release/riftlock" "$BUNDLE_DIR/riftlock-$target"
  chmod 0755 "$BUNDLE_DIR/riftlock-$target"
done

cp -- install.sh README.md "$BUNDLE_DIR/"
(
  cd "$BUNDLE_DIR"
  sha256sum riftlock-* > checksums.txt
)

mkdir -p -- "$DIST"
if command -v zip >/dev/null 2>&1; then
  (cd "$DIST" && zip -qr "$BUNDLE_NAME.zip" "$BUNDLE_NAME")
elif command -v python3 >/dev/null 2>&1; then
  python3 - "$DIST" "$BUNDLE_NAME" <<'PY'
from pathlib import Path
import sys
import zipfile

dist = Path(sys.argv[1])
name = sys.argv[2]
folder = dist / name
with zipfile.ZipFile(dist / f"{name}.zip", "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in sorted(folder.rglob("*")):
        if path.is_file():
            archive.write(path, path.relative_to(dist))
PY
else
  fail "zip or python3 is required to create the bundle archive."
fi

info "Bundle created: dist/$BUNDLE_NAME/"
info "Archive created: dist/$BUNDLE_NAME.zip"
