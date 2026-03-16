#![no_main]
use libfuzzer_sys::fuzz_target;
use pq_eth_precompiles::falcon;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }

    let make_valid = data[0] % 2 == 1;
    let seed = if data.len() > 1 { data[1] } else { 0 };

    // Generate deterministic test data from fuzz input
    let mut s2 = vec![0u64; 512];
    let mut h = vec![0u64; 512];
    for i in 0..512 {
        let byte_idx = 2 + (i % data.len().max(3).saturating_sub(2));
        let val = if byte_idx < data.len() { data[byte_idx] as u64 } else { 0 };
        // Small coefficients for s2 (signature is small)
        s2[i] = ((val as i64 * 3 % 5 - 2).rem_euclid(falcon::Q as i64)) as u64;
        // Random-ish h
        h[i] = (val.wrapping_mul(13).wrapping_add(i as u64 * 7 + seed as u64)) % falcon::Q;
    }

    // Compute NTT(h)
    let params = pq_eth_precompiles::FastNttParams::new(falcon::Q, falcon::N, falcon::PSI).unwrap();
    let ntth = pq_eth_precompiles::ntt_fw_fast(&h, &params);
    let ntth_c = falcon::pack(&ntth);

    // Build salt||msg
    let salt_msg_len = (seed as usize % 60) + 40;
    let salt_msg: Vec<u8> = (0..salt_msg_len).map(|i| data[i % data.len()]).collect();

    // Compute hashed
    let hashed_c = falcon::shake256_htp(&salt_msg);
    let hashed = falcon::unpack(&hashed_c).unwrap();

    // Compute s1 = INTT(NTT(s2) * NTT(h))
    let ntt_s2 = pq_eth_precompiles::ntt_fw_fast(&s2, &params);
    let product = pq_eth_precompiles::vec_mul_mod_fast(&ntt_s2, &ntth, falcon::Q);
    let s1 = pq_eth_precompiles::ntt_inv_fast(&product, &params);

    let s1_c = falcon::pack(&s1);
    let s2_c = falcon::pack(&s2);

    if make_valid {
        // Valid: norm check should pass (s2 is small, s1 = h*s2 matches)
        let result = falcon::falcon_norm(&s1_c, &s2_c, &hashed_c);
        // Also verify via full pipeline
        let result2 = falcon::falcon_norm_coeffs(&s1, &s2, &hashed);
        assert_eq!(result, result2, "compact vs coeffs norm mismatch");
    } else {
        // Invalid: corrupt s2 to make norm fail
        let mut bad_s2 = s2.clone();
        for i in 0..512 {
            bad_s2[i] = (bad_s2[i] + 3000) % falcon::Q;
        }
        let bad_s2_c = falcon::pack(&bad_s2);
        let result = falcon::falcon_norm(&s1_c, &bad_s2_c, &hashed_c);
        let result2 = falcon::falcon_norm_coeffs(&s1, &bad_s2, &hashed);
        assert_eq!(result, result2, "compact vs coeffs norm mismatch (invalid case)");
    }

    // Test pack/unpack roundtrip
    let rt = falcon::unpack(&falcon::pack(&s2)).unwrap();
    assert_eq!(s2, rt, "pack/unpack roundtrip failed");

    // Test NTT compact roundtrip
    let fwd = falcon::ntt_fw_compact(&s2_c).unwrap();
    let inv = falcon::ntt_inv_compact(&fwd).unwrap();
    let recovered = falcon::unpack(&inv).unwrap();
    assert_eq!(s2, recovered, "NTT compact roundtrip failed");
});
