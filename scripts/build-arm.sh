#!/usr/bin/env sh
#
# Cross-build for 32-bit ARM Linux (armv7) and 64-bit ARM (aarch64, musl), the
# targets this crate is aimed at. Needs zig and cargo-zigbuild on PATH.
#
#   cargo install cargo-zigbuild
#   rustup target add armv7-unknown-linux-musleabihf
#   rustup target add armv7-unknown-linux-gnueabihf
#   rustup target add aarch64-unknown-linux-musl
#
# Unlike the reference project this one has no C dependency at all — everything
# is pure Rust — so zig is only supplying the linker. That makes these builds
# quick, and means no cross-gcc package is needed.
#
# If zig and cargo-zigbuild live in a local .tools/ directory, put their
# directories first on PATH before running this script.
set -eu

TARGETS="armv7-unknown-linux-musleabihf armv7-unknown-linux-gnueabihf aarch64-unknown-linux-musl"

# Full LTO is fine natively but can stall an ARM cross-link for a very long
# time; the release size optimisation stays on.
export CARGO_PROFILE_RELEASE_LTO=off
export CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16

PROJECT_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
if [ -x "$PROJECT_ROOT/.tools/zig/zig" ]; then
    PATH="$PROJECT_ROOT/.tools/zig:$PROJECT_ROOT/.tools/cargo-zigbuild/bin:$PATH"
    export PATH
fi

command -v cargo-zigbuild >/dev/null || {
    echo "cargo-zigbuild is required: cargo install cargo-zigbuild" >&2
    exit 1
}
command -v zig >/dev/null || {
    echo "zig is required and must be on PATH" >&2
    exit 1
}

for target in $TARGETS; do
    rustup target add "$target" >/dev/null
done

cd "$PROJECT_ROOT"
for target in $TARGETS; do
    echo "==> $target"
    cargo zigbuild --release --target "$target" --bin frpc --bin rust-frpc
done

echo
echo "artifacts:"
for target in $TARGETS; do
    ls -l "target/$target/release/frpc"
done
