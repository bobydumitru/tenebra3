$ErrorActionPreference = 'Stop'

$hostPort = 39453
$nodeBinary = "cargo"

Write-Host "[1/3] Build validation"
& $nodeBinary check --all-targets --quiet
if ($LASTEXITCODE -ne 0) { throw "cargo check failed" }

Write-Host "[2/3] Core test validation"
& $nodeBinary test --lib --quiet
if ($LASTEXITCODE -ne 0) { throw "cargo test failed" }

Write-Host "[3/3] Network health probe"
$tcp = Test-NetConnection -ComputerName 127.0.0.1 -Port $hostPort -WarningAction SilentlyContinue
if ($tcp.TcpTestSucceeded) {
    Write-Host "PORT_OPEN"
} else {
    Write-Host "PORT_CLOSED"
}

Write-Host "Probe complete. Check the node logs for status output."
