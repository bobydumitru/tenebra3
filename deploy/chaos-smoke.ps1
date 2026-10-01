$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

$temp = Join-Path $env:TEMP "tenebra-chaos-$([guid]::NewGuid())"
New-Item -ItemType Directory -Path $temp | Out-Null
try {
    $env:TSC1_DEVNET_V3_BLOCKS_DIR = $temp
    cargo run --quiet --bin tsc1-devnet-v3 -- status | Out-File (Join-Path $temp 'status-before.txt')
    $jobs = 1..4 | ForEach-Object {
        Start-Job -ScriptBlock {
            param($path, $projectRoot)
            Set-Location $projectRoot
            $env:TSC1_DEVNET_V3_BLOCKS_DIR = $path
            cargo run --quiet --bin tsc1-devnet-v3 -- status
        } -ArgumentList $temp, $root
    }
    $jobs | Wait-Job | Receive-Job | Out-File (Join-Path $temp 'concurrent-status.txt')
    $jobs | Remove-Job -Force
    $raw = [IO.File]::ReadAllBytes((Join-Path $temp 'status-before.txt'))
    [IO.File]::WriteAllBytes((Join-Path $temp 'corrupt.bin'), $raw + [byte]0xff)
    cargo test --lib tsc1_chain_v3 --quiet
    Write-Host "CHAOS_SMOKE=PASS temp=$temp"
} finally {
    Remove-Item $temp -Recurse -Force -ErrorAction SilentlyContinue
}