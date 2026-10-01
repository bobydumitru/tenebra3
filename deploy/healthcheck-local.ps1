$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

Write-Host "[1/3] cargo check --all-targets"
cargo check --all-targets --quiet
if ($LASTEXITCODE -ne 0) { throw "cargo check failed" }

$port = 39453
Write-Host "[2/3] checking local port $port"
$tcp = Test-NetConnection -ComputerName 127.0.0.1 -Port $port -WarningAction SilentlyContinue
if ($tcp.TcpTestSucceeded) {
    Write-Host "PORT_OPEN"
} else {
    Write-Host "PORT_CLOSED"
}

Write-Host "[3/3] status probe"
try {
    cargo run --bin tsc1-devnet-v3 -- status
} catch {
    Write-Host "STATUS_PROBE_FAILED: $($_.Exception.Message)"
}

Write-Host "Local health check complete."
