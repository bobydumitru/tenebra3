#![no_main]

use libfuzzer_sys::fuzz_target;
use tenebra::tsc1_tx_v2::Transaction;

fuzz_target!(|data: &[u8]| {
    if let Ok(tx) = Transaction::decode(data) {
        assert_eq!(tx.encode().unwrap(), data);
        let _ = tx.validate_public(1);
        assert!(tx.validate_for_consensus(1).is_err());
    }
    if data.len() >= 20 {
        let mut tagged = data.to_vec();
        tagged[..20].copy_from_slice(b"TSC-1:tx:unsigned:v1");
        if let Ok(tx) = Transaction::decode(&tagged) {
            assert_eq!(tx.encode().unwrap(), tagged);
            let _ = tx.validate_public(1);
            assert!(tx.validate_for_consensus(1).is_err());
        }
    }
});
