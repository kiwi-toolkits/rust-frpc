# Cross-compiling for ARM Linux

The boards this crate is aimed at are ARMv7 and ARM64 Linux. The recommended
artefact is the musl build: statically linked, with no dependency on the target's
libc, so one binary runs on any rootfs.

## Prerequisites

```bash
cargo install cargo-zigbuild
rustup target add armv7-unknown-linux-musleabihf
rustup target add armv7-unknown-linux-gnueabihf
rustup target add aarch64-unknown-linux-musl
```

Zig must be on `PATH` as well. Here it supplies **both** the linker and the C
compiler: everything in the frp protocol stack — the crypto, the compression and
the yamux multiplexer — is pure Rust, but `rustls` builds `ring` for the TLS
handshake, and `ring` needs a C compiler for the target. `cargo-zigbuild` sets
`CC_<target>` to `zig cc`, so that compiler is the same zig binary that is
already doing the linking and no `gcc-arm-linux-gnueabihf` package is needed.
That is still a deliberate difference from projects that link OpenSSL or
aws-lc, and it makes these builds quick.

If `zig` and `cargo-zigbuild` live in the repository's `.tools/` directory (a
common local setup), the build scripts put them on `PATH` themselves. That is
the only thing those four lines in the script do — they are not a fallback to a
system install, so `zig is required and must be on PATH` means exactly what it
says: the script looked in `.tools/zig` and did not find a `zig.exe` there.

`.tools/` is in `.gitignore`, so it is a per-machine download rather than
something a fresh clone has. On Windows the quickest way to point it at a zig
that is already on the machine is a directory junction:

```powershell
New-Item -ItemType Junction -Path .tools\zig -Target D:\path\to\zig
```

A junction needs no administrator rights, unlike a symbolic link, and Cargo and
the script both follow it transparently.

## Build

```bash
./scripts/build-arm.sh          # Linux, macOS, WSL
.\scripts\build-arm.ps1         # Windows
```

Both scripts disable full LTO for the cross-link
(`CARGO_PROFILE_RELEASE_LTO=off`, `codegen-units=16`): fat LTO over an ARM link
can take an unbounded amount of time, and the release size optimisation stays on
either way. For a final artefact where the last few hundred kilobytes matter,
build one target at a time with `cargo zigbuild --release --target <triple>` and
LTO left on.

Artifacts land in `target/<triple>/release/`:

| triple | libc | linking | use when |
| :--- | :--- | :--- | :--- |
| `armv7-unknown-linux-musleabihf` | musl | static | default choice; works on any ARMv7 rootfs |
| `armv7-unknown-linux-gnueabihf` | glibc | dynamic (`/lib/ld-linux-armhf.so.3`) | the target already ships a compatible glibc and you want the smaller shared libc |
| `aarch64-unknown-linux-musl` | musl | static | ARM64 boards |

## Verifying on the device

The end-to-end tests need a real `frps`. The quickest check on a board is to point
the client at any reachable server and read the log:

```bash
./frpc -c frpc.toml          # expect: login to server success, then proxy ... is running
frpc status -c frpc.toml     # with webServer.port set
```

`doc/memory.md` has the measurement harness, and its budgets can be raised for a
different target with `FRPC_RSS_BUDGET_KB` / `FRPC_RSS_100_BUDGET_KB`.
