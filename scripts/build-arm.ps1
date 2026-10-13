# Windows cross-build for ARM Linux: armv7 and aarch64, both musl.
#
# Needs zig and cargo-zigbuild. The frp protocol stack here is pure Rust, but
# rustls builds `ring` for the TLS handshake and ring needs a C compiler for the
# target, so zig supplies that compiler as well as the linker.
#
#   cargo install cargo-zigbuild
#
# See doc/build-linux-arm.md for the zig setup.

$ErrorActionPreference = "Stop"

$targets = @(
    "armv7-unknown-linux-musleabihf",
    "armv7-unknown-linux-gnueabihf",
    "aarch64-unknown-linux-musl"
)

# The release profile is used as it stands: `lto = "fat"`, `codegen-units = 1`.
#
# This script used to override both to keep the cross-link quick, on the theory
# that full LTO over an ARM link "can stall ... for a very long time". Measured,
# that is not true any more: a full armv7-unknown-linux-musleabihf build takes
# 83 seconds with fat LTO against 44 with LTO off, and the artefact is 2.06 MB
# against 2.67 MB. Thirty-nine seconds of build time for 610 kB of binary is not
# a trade worth making by default.

$projectRoot = Split-Path -Parent $PSScriptRoot
$localZig = Join-Path $projectRoot ".tools\zig"
if (Test-Path (Join-Path $localZig "zig.exe")) {
    $env:PATH = "$localZig;$(Join-Path $projectRoot '.tools\cargo-zigbuild\bin');$env:PATH"
}

if (-not (Get-Command cargo-zigbuild -ErrorAction SilentlyContinue)) {
    throw "cargo-zigbuild is required: cargo install cargo-zigbuild"
}
if (-not (Get-Command zig -ErrorAction SilentlyContinue)) {
    throw "zig is required and must be on PATH"
}

foreach ($target in $targets) {
    rustup target add $target
}

Push-Location $projectRoot
try {
    foreach ($target in $targets) {
        Write-Host "==> $target"
        cargo zigbuild --release --target $target --bin frpc --bin rust-frpc
        if ($LASTEXITCODE -ne 0) { throw "build failed for $target" }
    }

    Write-Host ""
    Write-Host "artifacts:"
    foreach ($target in $targets) {
        Get-ChildItem "target\$target\release\frpc", "target\$target\release\rust-frpc" |
            Select-Object FullName, @{n = "MB"; e = { [math]::Round($_.Length / 1MB, 2) } }
    }
}
finally {
    Pop-Location
}
