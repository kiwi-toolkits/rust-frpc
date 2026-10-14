# Windows cross-build for ARM Linux: armv7 and aarch64, both musl.
#
# Needs zig and cargo-zigbuild. The frp protocol stack here is pure Rust, but
# rustls builds `ring` for the TLS handshake and ring needs a C compiler for the
# target, so zig supplies that compiler as well as the linker.
#
#   cargo install cargo-zigbuild
#
# See doc/build-linux-arm.md for the zig setup.
#
#   build-arm.ps1 [-NoTls | --no-tls]
#
# -NoTls builds with --no-default-features, which drops rustls and ring and takes
# the armv7 artefact from 2.06 MB to 1.56 MB. It is opt-in rather than the
# default because frp's own default config asks for TLS, and a client built
# without it refuses to start on that config rather than connecting in the
# clear. The refusal names the way out (`transport.tls.enable = false`).

param(
    [switch]$NoTls,
    # PowerShell binds `-NoTls` but leaves `--no-tls` here, unbound.
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$Rest
)

$ErrorActionPreference = "Stop"

# Both spellings are accepted, and anything else is refused.
#
# This is not politeness. Earlier this script declared `[switch]$NoTls` and
# nothing else, so `.\build-arm.ps1 --no-tls` put the flag in `$args`, left
# `$NoTls` false, built *with* TLS and said nothing at all about it. A one-letter
# difference in a habit — PowerShell wants `-NoTls`, everything else on the
# machine wants `--no-tls` — produced a 2.06 MB binary while the caller believed
# they had asked for 1.56 MB. Silently ignoring an argument is the failure mode
# to design out, so the default arm throws.
foreach ($argument in @($Rest)) {
    if ([string]::IsNullOrWhiteSpace($argument)) { continue }
    switch -Regex ($argument) {
        '^--?no-?tls$' { $NoTls = $true }
        '^(--help|-h|-\?)$' {
            Get-Content $PSCommandPath | Select-Object -First 19
            exit 0
        }
        default { throw "unknown argument: $argument (try --help)" }
    }
}

# This script used to set these two, to keep the ARM cross-link quick. `$env:`
# assignments outlive the script that made them, so a shell which ran the old
# version still carries them — and they override the release profile, which is
# 610 kB of fat LTO. That is the other half of how a build here came out at 2.67
# MB while the docs said 2.06. Cleared and reported rather than left to be
# discovered as a number that does not match anything.
foreach ($name in "CARGO_PROFILE_RELEASE_LTO", "CARGO_PROFILE_RELEASE_CODEGEN_UNITS") {
    if (Test-Path "Env:\$name") {
        $stale = (Get-Item "Env:\$name").Value
        Write-Warning "ignoring stale $name=$stale from this shell; the release profile is used as it stands"
        Remove-Item "Env:\$name"
    }
}

# A `[string[]]` that is appended to, and deliberately not
# `$features = if ($NoTls) { @("--no-default-features") } else { @() }`.
#
# An `if` statement emits to the pipeline, and the pipeline enumerates what it is
# given, so a one-element array comes back as a bare **String** — `.Count` is
# still 1 and it still prints correctly, which is what makes this so quiet.
# Splatting a String with `@features` then enumerates *its characters*, and the
# first character of "--no-default-features" is `-`; cargo-zigbuild is handed a
# lone `-` as a positional argument and exits with
# "unexpected argument '-' found", which says nothing about the real cause.
$features = [string[]]@()
if ($NoTls) { $features += "--no-default-features" }

$tlsState = if ($NoTls) { "no" } else { "yes" }

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
        Write-Host "==> $target (tls: $tlsState)"
        cargo zigbuild --release --target $target --bin frpc --bin rust-frpc @features
        if ($LASTEXITCODE -ne 0) { throw "build failed for $target" }
    }

    Write-Host ""
    Write-Host "artifacts:"
    foreach ($target in $targets) {
        Get-ChildItem "target\$target\release\frpc", "target\$target\release\rust-frpc" |
            # Decimal MB, so these agree with the numbers in README.md and in the
            # comments above. PowerShell's own 1MB is 1048576, and mixing the two
            # conventions makes a 1.56 MB artefact print as 1.49.
            Select-Object FullName, @{n = "MB"; e = { [math]::Round($_.Length / 1e6, 2) } }
    }
}
finally {
    Pop-Location
}
