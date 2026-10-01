$ErrorActionPreference = 'Stop'

$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

$env:TSC1_DEVNET_V3_BLOCKS_DIR = if ($env:TSC1_DEVNET_V3_BLOCKS_DIR) { $env:TSC1_DEVNET_V3_BLOCKS_DIR } else { (Join-Path $root 'data/devnet-v3f/blocks') }

Write-Host "Starting TENEBRA devnet v3 node on 0.0.0.0:39453"
Write-Host "Blocks dir: $env:TSC1_DEVNET_V3_BLOCKS_DIR"

cargo run --bin tsc1-devnet-v3 -- serve 0.0.0.0:39453
