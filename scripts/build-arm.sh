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
# The frp protocol stack here is pure Rust, but rustls builds `ring` for the TLS
# handshake and ring needs a C compiler for the target. cargo-zigbuild points
# CC_<target> at `zig cc`, so zig supplies that compiler as well as the linker —
# which still means no cross-gcc package is needed, and these builds stay quick.
#
# If zig and cargo-zigbuild live in a local .tools/ directory, put their
# directories first on PATH before running this script.
#
#   build-arm.sh [--no-tls]
#
# `--no-tls` builds with `--no-default-features`, which drops `rustls` and `ring`
# and takes the armv7 artefact from 2.06 MB to 1.56 MB. It is opt-in rather than
# the default because frp's own default config asks for TLS, and a client built
# without it refuses to start on that config rather than connecting in the
# clear. The refusal names the way out (`transport.tls.enable = false`).
set -eu

NO_TLS=""
for arg in "$@"; do
    case "$arg" in
        --no-tls) NO_TLS="--no-default-features" ;;
        -h|--help) sed -n "2,30p" "$0"; exit 0 ;;
        *) echo "unknown argument: $arg (try --help)" >&2; exit 2 ;;
    esac
done

TARGETS="armv7-unknown-linux-musleabihf armv7-unknown-linux-gnueabihf aarch64-unknown-linux-musl"

# The release profile is used as it stands: `lto = "fat"`, `codegen-units = 1`.
#
# This script used to override both to keep the cross-link quick, on the theory
# that full LTO over an ARM link "can stall ... for a very long time". Measured,
# that is not true any more: a full armv7-unknown-linux-musleabihf build takes
# 83 seconds with fat LTO against 44 with LTO off, and the artefact is 2.06 MB
# against 2.67 MB. Thirty-nine seconds of build time for 610 kB of binary is not
# a trade worth making by default.

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
    # shellcheck disable=SC2086
    cargo zigbuild --release --target "$target" --bin frpc --bin rust-frpc $NO_TLS
done

echo
echo "artifacts:"
for target in $TARGETS; do
    ls -l "target/$target/release/frpc"
done
