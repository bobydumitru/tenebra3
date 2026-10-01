$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

Write-Host "Checking cargo-fuzz availability"
$cargoFuzz = Get-Command cargo-fuzz -ErrorAction SilentlyContinue
if (-not $cargoFuzz) {
    Write-Host "cargo-fuzz is not installed. Installing it now..."
    cargo install cargo-fuzz --force --locked
    if ($LASTEXITCODE -ne 0) {
        throw "cargo-fuzz installation failed"
    }
}

Write-Host "Ensuring nightly Rust is available for cargo-fuzz ASAN builds"
$nightly = rustup toolchain list | Select-String "nightly" -Quiet
if (-not $nightly) {
    rustup toolchain install nightly --profile minimal
    if ($LASTEXITCODE -ne 0) {
        throw "nightly toolchain installation failed"
    }
}

Write-Host "Finding the Windows ASAN runtime DLL required by cargo-fuzz"
$dllDir = Get-ChildItem 'C:\Program Files (x86)\Microsoft Visual Studio' -Recurse -Filter 'clang_rt.asan_dynamic-x86_64.dll' -ErrorAction SilentlyContinue |
    Select-Object -First 1 -ExpandProperty DirectoryName
if (-not $dllDir) {
    throw "ASAN runtime DLL was not found; install the MSVC C++ Build Tools with Clang/ASAN support."
}
$env:PATH = "$dllDir;$env:PATH"

Write-Host "Running short fuzz smoke checks on the decode targets"
$targets = @(
    "transaction_decode",
    "block_decode",
    "authorization_decode"
)

foreach ($target in $targets) {
    Write-Host "--- $target ---"
    cargo +nightly fuzz run $target -- -max_total_time=20
    if ($LASTEXITCODE -ne 0) {
        throw "fuzz smoke run failed for $target"
    }
}

Write-Host "Fuzz smoke runs completed."
