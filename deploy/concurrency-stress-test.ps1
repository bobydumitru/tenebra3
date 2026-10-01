$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

$iterations = 5
Write-Host "Running $iterations concurrency stress iterations"

for ($i = 1; $i -le $iterations; $i++) {
    Write-Host "Iteration $i/$iterations"
    cargo test --lib tsc1_peer_v3::tests::localhost_sync_validates_and_persists_v3_block -- --nocapture
    if ($LASTEXITCODE -ne 0) {
        throw "concurrency stress iteration $i failed"
    }
}

Write-Host "Concurrency stress test completed."
