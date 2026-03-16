#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pq_eth_precompiles::ntt_fw_precompile(data);
});
