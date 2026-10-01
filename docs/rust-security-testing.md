# Rust security checks

This project uses Rust, not Solidity or Vyper; Slither does not analyze its
consensus code. Run checks on synthetic/local data only. Never upload a
wallet file, password, seed, or private key to an online analyzer.

## Dependency advisories

The local RustSec tool is installed at `.tools/bin/cargo-audit.exe`.

```powershell
& .\.tools\bin\cargo-audit.exe audit --file Cargo.lock
& .\.tools\bin\cargo-audit.exe audit --file fuzz\Cargo.lock
```

On 2026-09-20 both lockfiles had zero known vulnerabilities. RustSec warned
that `clear_on_drop 0.2.5`, pulled in by `bulletproofs 5.0.0`, is unmaintained
(RUSTSEC-2026-0283). This is not a reported exploit; replacing a proof-system
dependency requires separate cryptographic and compatibility review.

## Parser fuzzing

`cargo-fuzz` is installed at `.tools/bin/cargo-fuzz.exe`; Rust nightly is
installed but stable remains the default. In a PowerShell session:

```powershell
$env:PATH = "$(Resolve-Path .tools\bin);$env:PATH"
$env:PATH = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.44.35207\bin\Hostx64\x64;$env:PATH"
cargo +nightly fuzz run transaction_decode -- -max_total_time=30
cargo +nightly fuzz run block_decode -- -max_total_time=30
cargo +nightly fuzz run authorization_decode -- -max_total_time=30
```

The targets are in `fuzz/fuzz_targets/`. A short fuzz run only finds bugs in
executed paths; it is not evidence that all inputs or the proof design are
secure. Preserve and triage any crash artifact before changing code.
On this Windows machine, omit the AddressSanitizer DLL directory from PATH
and the fuzz executable fails to start with `STATUS_DLL_NOT_FOUND`.

## Signature cost

```powershell
cargo test --release --lib measure_ring_signature_cost -- --ignored --nocapture
```

Run this with no other compilation or heavy workload to estimate production
signature CPU cost. It measures one 16-member signature, not a full block.
On 2026-09-20, ten optimized samples on this machine gave 7.64 ms median
signing, 7.21 ms median verification, and 10.40 ms maximum verification.
V3e allowed 256 inputs/block (about 1.85 seconds of median verification
alone); v3f limits this to 32 inputs/block via two inputs/transaction and
16 transactions/block (about 0.23 seconds). These figures exclude range
proofs, storage, network load, and slower hardware. Public-node DoS
resistance is still unproven.
