#![no_main]

use libfuzzer_sys::fuzz_target;
use tenebra::tsc1_chain_v3::BlockV3;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = BlockV3::decode(data) {
        assert_eq!(block.encode().unwrap(), data);
    }
    if data.len() >= 10 {
        let mut tagged = data.to_vec();
        tagged[..10].copy_from_slice(b"TSC1BLK3F1");
        if let Ok(block) = BlockV3::decode(&tagged) {
            assert_eq!(block.encode().unwrap(), tagged);
        }
    }
});
