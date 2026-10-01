$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$outDir = Join-Path $root "audit-evidence-$stamp"
New-Item -ItemType Directory -Path $outDir | Out-Null

function Run-Step([string]$Name, [string]$Command, [string]$OutputFile) {
    Write-Host "[audit] $Name"
    & cmd.exe /d /c "$Command > `"$OutputFile`" 2>&1"
    if ($LASTEXITCODE -ne 0) { throw "$Name failed" }
}

Run-Step 'format' 'cargo fmt --all -- --check' (Join-Path $outDir 'format.txt')
Run-Step 'all target tests' 'cargo test --all-targets --quiet' (Join-Path $outDir 'tests-all-targets.txt')
Run-Step 'library clippy' 'cargo clippy --lib -- -D warnings' (Join-Path $outDir 'clippy-lib.txt')
Run-Step 'fuzz target build' 'cargo check --manifest-path .\fuzz\Cargo.toml --bins --quiet' (Join-Path $outDir 'fuzz-build.txt')
Run-Step 'focused proof tests' 'cargo test --lib tsc1_tx_v2 --quiet' (Join-Path $outDir 'proof-tests.txt')

cargo metadata --format-version 1 --no-deps | Out-File (Join-Path $outDir 'cargo-metadata.json') -Encoding utf8
Get-ChildItem -File -Recurse src, fuzz, config, docs | Get-FileHash -Algorithm SHA256 |
    Select-Object Path, Hash | ConvertTo-Json | Out-File (Join-Path $outDir 'sha256-manifest.json') -Encoding utf8
Copy-Item .\docs\external-audit-submission.md $outDir\scope.md
Write-Host "AUDIT_EVIDENCE=$outDir"
