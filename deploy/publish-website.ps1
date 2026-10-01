param(
    [Parameter(Mandatory = $true)]
    [string]$HostName,
    [Parameter(Mandatory = $true)]
    [string]$User,
    [string]$RemotePath = '/var/www/tenebra',
    [switch]$SkipNodeBuild
)

$ErrorActionPreference = 'Stop'
$root = Resolve-Path (Join-Path $PSScriptRoot '..')
Set-Location $root

$pages = @(
    'index.html',
    'tenebra-network.html',
    'tenebra-dex.html',
    'tenebra-scan.html',
    'tenebra-create-token.html',
    'tenebra-wallet.html',
    'web-wallet.html',
    'tenebra-marketplace.html',
    'tenebra-my-nfts.html',
    'multichain-wallet.html',
    'wallet-preview.html'
)
$documents = @(
    '.\docs\ROADMAP.html',
    '.\docs\internal-audit-2026-09-20.html',
    '.\docs\TENEBRA-whitepaper.html',
    '.\docs\release-evidence.html',
    '.\docs\CERTOaudit-external-independent-assessment.html',
    '.\docs\CERTOaudit-mainnet-operational-addendum-2026-09-23.html',
    '.\docs\tenebra-wallet-native.html'
)

$staging = Join-Path ([System.IO.Path]::GetTempPath()) ("tenebra-publish-" + [guid]::NewGuid().ToString('N'))
$archive = "$staging.tar"
$remote = "${User}@${HostName}"
$remoteStage = "/tmp/tenebra-publish-$([guid]::NewGuid().ToString('N'))"

try {
    New-Item -ItemType Directory -Path "$staging\html\docs", "$staging\html\assets\wallet-wasm", "$staging\html\wallet", "$staging\opt\tenebra\mainnet-candidate", "$staging\etc\systemd\system", "$staging\source\src", "$staging\source\config" -Force | Out-Null

    foreach ($page in $pages) { Copy-Item $page "$staging\html\$([System.IO.Path]::GetFileName($page))" -Force }
    foreach ($document in $documents) { Copy-Item $document "$staging\html\docs\$([System.IO.Path]::GetFileName($document))" -Force }
    Copy-Item '.\docs\internal-audit-2026-09-20.html' "$staging\html\internal-audit-2026-09-20.html" -Force
    Copy-Item '.\docs\CERTOaudit-external-independent-assessment.html' "$staging\html\CERTOaudit-external-independent-assessment.html" -Force
    Copy-Item '.\wallet\tenebra_wallet_wasm.wasm' "$staging\html\wallet\tenebra_wallet_wasm.wasm" -Force
    Copy-Item '.\assets\wallet-wasm\tenebra_wallet_wasm.js', '.\assets\wallet-wasm\tenebra_wallet_wasm_bg.wasm', '.\assets\wallet-wasm\env.js' "$staging\html\assets\wallet-wasm" -Force
    Copy-Item '.\assets\founder-artwork' "$staging\html\assets\founder-artwork" -Recurse -Force
    foreach ($asset in @('.\assets\qrcode.min.js', '.\assets\tnb-emblem-v2.png', '.\assets\tenebra-founder-gallery.svg', '.\assets\CERTOaudit-external-audit-emblem.svg')) {
        if (Test-Path $asset) { Copy-Item $asset "$staging\html\assets\$([System.IO.Path]::GetFileName($asset))" -Force }
    }
    Copy-Item '.\deploy\public-api.py' "$staging\opt\tenebra\mainnet-candidate\public-api.py" -Force
    Copy-Item '.\deploy\tenebra-public-api.service' "$staging\etc\systemd\system\tenebra-public-api.service" -Force
    Copy-Item '.\Cargo.toml', '.\Cargo.lock' "$staging\source" -Force
    Copy-Item '.\src\*' "$staging\source\src" -Recurse -Force
    foreach ($config in @('founder-address.txt', 'treasury-address.txt', 'mainnet-genesis.hex', 'devnet-v2-genesis.hex')) {
        Copy-Item ".\config\$config" "$staging\source\config\$config" -Force
    }

    & tar -cf $archive -C $staging .
    if ($LASTEXITCODE -ne 0) { throw 'Local deployment archive creation failed' }

    Write-Host "Publishing with one SSH authentication to ${remote}"
    if ($SkipNodeBuild) {
        $nodeDeployCommand = 'test -x /opt/tenebra/bin/tenebra-node'
    } else {
        $nodeDeployCommand = "if ! command -v rustup >/dev/null 2>&1; then command -v curl >/dev/null 2>&1 || { echo 'curl is required to install a current Rust toolchain' >&2; exit 1; }; curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o '$remoteStage/rustup-init.sh'; sh '$remoteStage/rustup-init.sh' -y --profile minimal --default-toolchain stable --no-modify-path; fi; export PATH=`$HOME/.cargo/bin:`$PATH; rustup toolchain install stable --profile minimal; cd '$remoteStage/source'; mkdir -p /var/cache/tenebra/mainnet-candidate-target; cargo +stable build --locked --release --features mainnet-candidate --target-dir /var/cache/tenebra/mainnet-candidate-target --bin tenebra-node; mkdir -p /opt/tenebra/bin; if [ -x /opt/tenebra/bin/tenebra-node ]; then cp -p /opt/tenebra/bin/tenebra-node '$remoteStage/tenebra-node.previous'; fi; install -m 0755 /var/cache/tenebra/mainnet-candidate-target/release/tenebra-node '$remoteStage/tenebra-node.next'; install -m 0755 '$remoteStage/tenebra-node.next' /opt/tenebra/bin/tenebra-node; if ! systemctl restart tenebra-mainnet || ! systemctl is-active --quiet tenebra-mainnet; then if [ -f '$remoteStage/tenebra-node.previous' ]; then install -m 0755 '$remoteStage/tenebra-node.previous' /opt/tenebra/bin/tenebra-node; systemctl restart tenebra-mainnet || true; fi; exit 1; fi"
    }
    $remoteCommand = "set -e; rm -rf '$remoteStage'; mkdir -p '$remoteStage'; tar -xf - -C '$remoteStage'; $nodeDeployCommand; mkdir -p '$RemotePath' /opt/tenebra/mainnet-candidate /etc/systemd/system; cp -a '$remoteStage/html/.' '$RemotePath/'; cp '$remoteStage/opt/tenebra/mainnet-candidate/public-api.py' /opt/tenebra/mainnet-candidate/public-api.py; cp '$remoteStage/etc/systemd/system/tenebra-public-api.service' /etc/systemd/system/tenebra-public-api.service; systemctl daemon-reload; systemctl restart tenebra-public-api; rm -rf '$remoteStage'; echo Website and mainnet node publication complete."
    & cmd /c "tar -cf - -C `"$staging`" . | ssh -o ConnectTimeout=10 $remote `"$remoteCommand`""
    if ($LASTEXITCODE -ne 0) { throw 'Website publication failed' }
}
finally {
    Remove-Item $staging -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item $archive -Force -ErrorAction SilentlyContinue
}
