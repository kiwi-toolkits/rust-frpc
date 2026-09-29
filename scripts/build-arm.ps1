# Windows cross-build for ARM Linux: armv7 and aarch64, both musl.
#
# Needs zig and cargo-zigbuild. Unlike the reference project there is no C
# dependency anywhere in this crate, so zig is only supplying the linker.
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

# Full LTO is fine natively but can stall an ARM cross-link for a very long
# time; the release size optimisation stays on.
$env:CARGO_PROFILE_RELEASE_LTO = "off"
$env:CARGO_PROFILE_RELEASE_CODEGEN_UNITS = "16"

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
