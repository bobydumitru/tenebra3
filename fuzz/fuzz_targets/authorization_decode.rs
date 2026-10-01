#![no_main]

use libfuzzer_sys::fuzz_target;
use tenebra::tsc1_tx_v2::{AUTHORIZATION_BYTES, AuthorizationProof};

fuzz_target!(|data: &[u8]| {
    if let Ok(proof) = AuthorizationProof::decode(data) {
        assert_eq!(proof.encode(), data);
    }
    let mut fixed = [0u8; AUTHORIZATION_BYTES];
    for (destination, source) in fixed.iter_mut().zip(data) {
        *destination = *source;
    }
    if let Ok(proof) = AuthorizationProof::decode(&fixed) {
        assert_eq!(proof.encode(), fixed);
    }
});
