TENEBRA - CODEX HANDOFF
Actualizat: 2026-09-29

## Sold wallet: output-uri din taxele asset

- Cauză găsită la 2026-09-30: `ChainV3::wallet_balance_nox` marca input-urile tranzacțiilor `creation_fee` drept cheltuite, dar nu adăuga output-urile lor (în special change-ul) la scanarea balanței. `wallet_seed_history_v2` ignora aceleași tranzacții, ceea ce putea raporta greșit change-ul ca `Received`.
- Corecție locală: `src/tsc1_chain_v3.rs` scanează output-urile TNB din `asset_transactions[*].creation_fee`; `wasm-wallet/src/lib.rs` include tranzacțiile fee în istoricul local, cu key-image și output-uri; `web-wallet.html` forțează refresh-ul balanței la restaurare și folosește versiunea WASM `20260930-asset-fee-history-v1`.
- Regresie: `examples/wallet_regression_fixture.rs` și `tests/wallet-wasm-regression.mjs` construiesc un fee real de creare asset cu change, verifică soldul WASM contra ledgerului Rust și clasificarea `Sent`/`Received`.
- Verificări locale: `cargo test --lib wallet_balance_includes_change_from_asset_creation_fee --features mainnet-candidate` trecut; build WASM release trecut; WASM `sign`, `confirm` și `asset-fee-history` trecute; `node --test tests/web-wallet.test.cjs` 28/28 trecut; sintaxa JavaScript și diagnosticele editorului fără erori.
- Publicat la 2026-09-30: corecția balanței și scannerul WASM au fost instalate incremental în `/var/www/tenebra`; HTTP 200, versiunea WASM confirmată, hash-urile JS/WASM live coincid cu build-ul local. Walletul creatorului a afișat `9,887,570.193013697 TNB` la height 20489.
- Noua ordonare a istoricului (intrări confirmate `Received`, apoi `Sent`, apoi trimiteri locale pending) este **locală, nepublicată**. Necesită doar redeploy-ul `web-wallet.html`; WASM-ul nu se schimbă. Nu s-au schimbat minerul/genesisul și nu s-a trimis nicio tranzacție de către asistent.

## Creare token: taxa de 10 TNB

- Fluxul este prezent local in `web-wallet.html` si este deja publicat pe `https://tenebra-network.com`.
- Pagina publica `tenebra-create-token.html` afiseaza taxa de 10 TNB si trimite utilizatorul spre wallet.
- Wallet-ul transfera 10,000,000,000 NOX catre Treasury, asteapta confirmarea transferului si abia apoi trimite tranzactia de creare token.
- Verificarea HTTP a confirmat markerii de taxa, destinatia Treasury si ordinea confirmare-inainte-de-creare pe paginile live. Nu este necesar un deploy suplimentar pentru acest flux, conform verificarii din 2026-09-29.

## Teste

- Rulat: `node --test tests/web-wallet.test.cjs` - 16 teste trecute, 0 esuate.
- Suita valideaza scriptul wallet, dar nu are un test dedicat fluxului de taxa pentru creare token.
- Validarea ramasa pentru acest feature: test de integrare/manual pe testnet cu wallet de test, confirmand plata catre Treasury si crearea tokenului doar dupa confirmare. Nu folosi un wallet cu fonduri reale pentru test.

## Regula de mentenanta

- Pentru fiecare modificare facuta si fiecare publicare/deploy, adauga aici data, fisierele afectate, rezumatul, testele rulate si starea publicarii.
- Nu marca drept publicat fara verificare HTTP a versiunii live.

## Fee policy upgrade - 2026-10-01 - LOCAL / DO NOT DEPLOY YET

### User-approved policy

- TNB transfer fee: 1% of the transfer amount, paid to the TENEBRA treasury.
- Scheduled block mining reward: separately split 90% miner / 10% TNB treasury.
- TSC-1 asset transfer: 1% network fee in TNB to the TNB treasury; optional issuer fee is 0-8% in TNB to the issuer's configured treasury.
- Asset creation from activation: 100 TNB per fungible token; 10 TNB per NFT. Legacy creation fee before activation remains 10 TNB.
- DEX swap: legacy 0.30% through height 21,999, then 1% from activation, with the full DEX fee sent to the configured TNB treasury address.
- User-approved consensus activation height: block 22,000 (live height at approval was 21,416).

### Critical release gate

- **Live deployment verified 2026-10-01 on primary VPS `89.39.7.191`:** publish script completed; public node online at height 21,416; wallet/token/DEX markers are live; public WASM SHA-256 matches local (`E65E7B3BF2CBFDC17935F232A9B6D38846F9711AE44A5DBDECA6FF93D35CA1D3`). Asset API reindex completed successfully (`indexed=true`, 21,416/21,416, 13 assets, no error). User states mining and transfers are paused. Confirm all other validators have this release before resuming mining.
- User approved output index 0 as the protocol's primary payment; a paired 8-bit confidential range proof binds public `fee_nox` to its hidden amount, rounded up to 1%. The signer adds it; mempool admission and both full-node/wallet block validation paths require it for mainnet transfers at/after 22,000. Proof construction, verification, malformed/underpaid rejection, serialization, and activation tests pass. The protocol convention is output 0=payment and later outputs=change.
- The release WASM package and consensus must be deployed together. Do not deploy only the HTML or only the node binary.

### Local implementation

- `src/tsc1_fee.rs`: activation is block 22,000; transaction fee routing is legacy 90/10 before activation and 100% treasury from activation in mainnet; mining reward has a separate 90/10 helper.
- `src/tsc1_chain_v2.rs`, `src/tsc1_chain_v3.rs`: reward split activation, treasury reward output, total issuance accounting, combined block payout validation; token creation fee is 100 TNB for fungible assets and 10 TNB for NFTs from 22,000; issuer fee cap 8% from 22,000.
- `src/tsc1_private_amounts.rs`, `src/tsc1_wallet_tx_v3.rs`, `src/tsc1_chain_v3.rs`, `src/candidate_node.rs`: paired confidential 1% proof helper, mainnet signer hook, mempool rejection and both block-validation paths. User approved output 0 as the protocol-defined primary payment and subsequent outputs as change.
- `src/tsc1_wallet_tx_v3.rs`, `wasm-wallet/src/lib.rs`: type/height-aware signed asset creation fee, while retaining the legacy fixed-fee helper for old tests/callers.
- `src/assets.rs`: issuer-fee maximum constant set to 8%; serialization remains able to decode older policies, but transfers/options over 8% are rejected from activation. Review legacy assets with existing issuer rates over 8% before enabling this rule.
- `src/dex.rs`: 0.30% historical quote through 21,999 and 1% quote from 22,000; full DEX fee share points to the configured treasury spend key. `tenebra-dex.html` shows the height-dependent rate.
- `web-wallet.html`: removes the separate token-creation transfer from the active flow, attaches one creation fee, passes NFT/fungible kind through WASM, updates issuer selector to 8%, passes the NFT/fungible asset kind, and bumps the WASM cache key.
- `tenebra-create-token.html`, `tenebra-dex.html`, `docs/fee-policy.md`, `docs/TENEBRA-whitepaper.html`: fee labels/policy updated for block 22,000. Legacy duplicate `resumeTokenCreate` declarations and the no-op `submitTokenCreationFee` stub remain to be cleaned up.

### Validation completed

- Passed focused mainnet tests for confidential fee proof serialization/construction/verification, valid/missing/underpaid fee enforcement, transaction fee activation and reward split, block payout separation, fungible/NFT creation-fee activation, issuer 8% cap (including legacy asset transfer), and DEX 1% treasury destination.
- `node --test tests/web-wallet.test.cjs`: 29 passed, 0 failed after the token-flow and issuer-selector changes.
- `cargo test --features mainnet-candidate --bin tsc1-fee-policy`: 4 passed.
- Latest focused tests: 7 activation tests passed, confidential-proof consensus and paired-proof serialization/math passed, legacy issuer-cap passed, DEX passed; wallet tests 29/29; public API tests 14/14. `cargo check --features mainnet-candidate --all-targets` passed with existing legacy dead-code warnings.
- `cargo check --features mainnet-candidate --all-targets` passed with existing dead-code warnings in standalone binaries. `cargo build --locked --release --features mainnet-candidate --bin tenebra-node` passed.
- Final WASM release build and wasm-bindgen generation succeeded; packaged and generated JS/WASM SHA-256 values matched (`E65E7B3BF2CBFDC17935F232A9B6D38846F9711AE44A5DBDECA6FF93D35CA1D3` for WASM and `CC85817E9E30F6BE367FCB48B812D0F406777F70BC81811EDDAB7EB03D4D5041` for JS).
- Last public height query returned 21,416, leaving 584 blocks before activation 22,000 at that time. Recheck immediately before release.
- The fee-policy release is deployed on the primary VPS only. Live status and page/WASM markers were verified. The asset API index is still rebuilding. No other validator host has been verified.

### Next steps for the next agent

1. Recheck live height 22,000 remains ahead. Keep all miners paused until every block-producing node has the release; output index 0 is the approved protocol fee base.
2. Clean obsolete duplicate `resumeTokenCreate` declarations and the no-op `submitTokenCreationFee` stub; add end-to-end signing/consensus tests for 100 TNB fungible and 10 TNB NFT creation fees.
3. Rerun all-target Rust tests, wallet tests, mainnet node build, WASM build/bindgen, ABI checks and artifact hashes after edits.
4. Verify every block-producing node's binary/version and the public asset index progress before resuming mining. If any validator missed the upgrade before block 22,000, halt and coordinate a later activation; do not let upgraded/old consensus nodes mine against each other.

### Manual deployment command (only after release gates)

From PowerShell at the project root, deploy the public site and candidate node to the confirmed primary VPS:

	.\deploy\publish-website.ps1 -HostName "89.39.7.191" -User "root"

This rebuilds/restarts the mainnet node on that server and publishes the static site/WASM/API. Repeat/coordinate equivalent release rollout for every block-producing node before resuming mining. Enter the SSH password directly in the terminal; it was previously exposed in chat and must be rotated before use.
