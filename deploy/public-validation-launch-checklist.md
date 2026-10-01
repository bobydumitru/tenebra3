# Public validation launch checklist

## 1. Code-side validation
- [ ] `cargo check --all-targets` passes
- [ ] `cargo test --lib --quiet` passes
- [ ] `cargo run --bin tsc1-devnet-v3 -- status` works
- [ ] `cargo run --bin tsc1-devnet-v3 -- serve 0.0.0.0:39453` starts cleanly

## 2. Node and network config
- [ ] `TSC1_DEVNET_V3_PEER_KEY` set to a private 32-byte key
- [ ] `TSC1_DEVNET_V3_PEER_KEYS` contains the allowed public keys
- [ ] `TSC1_DEVNET_V3_SEEDS` set to validated bootstrap addresses
- [ ] `TSC1_DEVNET_V3_BLOCKS_DIR` points to a writable directory
- [ ] block directory exists and is writable
- [ ] firewall allows only the required ports

## 3. Health checks
- [ ] local port check succeeds on the node port
- [ ] status command returns height and tip hash
- [ ] no critical messages in logs
- [ ] node process remains alive after a short startup test

## 4. Public-facing boundaries
- [ ] site states `Controlled validation` or `Preview`
- [ ] no public mainnet claim
- [ ] no public wallet claim
- [ ] no public asset launch claim
- [ ] no live market price claim
- [ ] no private keys or seed phrases in public files

## 5. Deployment gate
- [ ] all checks above pass on the target host
- [ ] site and node are tested together
- [ ] rollback plan exists
- [ ] logs and backups are enabled

## 6. Launch posture
This is a controlled validation launch, not a public mainnet launch and not a live asset claim.
