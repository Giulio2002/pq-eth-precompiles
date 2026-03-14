#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = eth_ntt::ntt_vecaddmod_precompile(data);
});
