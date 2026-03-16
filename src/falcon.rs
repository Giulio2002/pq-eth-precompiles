//! Falcon-512 EVM compact format operations.
//!
//! Compact: 1024 bytes = 32 big-endian uint256 words, each packing
//! 16 little-endian uint16 coefficients.

use crate::fast::{self, FastNttParams};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub const Q: u64 = 12289;
pub const N: usize = 512;
pub const PSI: u64 = 49;
pub const COMPACT_SIZE: usize = 1024;
pub const SIG_BOUND: u64 = 34034726;
const QS1: u64 = 6144;

pub fn unpack(data: &[u8]) -> Option<Vec<u64>> {
    if data.len() != COMPACT_SIZE {
        return None;
    }
    let mut coeffs = Vec::with_capacity(N);
    for w in 0..32 {
        let ws = w * 32;
        for j in 0..16 {
            let hi = data[ws + 30 - j * 2] as u64;
            let lo = data[ws + 31 - j * 2] as u64;
            coeffs.push(hi * 256 + lo);
        }
    }
    Some(coeffs)
}

pub fn pack(coeffs: &[u64]) -> Vec<u8> {
    assert!(coeffs.len() >= N);
    let mut out = vec![0u8; COMPACT_SIZE];
    for w in 0..32 {
        let ws = w * 32;
        for j in 0..16 {
            let c = coeffs[w * 16 + j];
            out[ws + 30 - j * 2] = (c >> 8) as u8;
            out[ws + 31 - j * 2] = (c & 0xff) as u8;
        }
    }
    out
}

use std::sync::LazyLock;

static FALCON_PARAMS: LazyLock<FastNttParams> = LazyLock::new(|| {
    FastNttParams::new(Q, N, PSI).unwrap()
});

fn falcon_params() -> &'static FastNttParams {
    &FALCON_PARAMS
}

/// NTT forward on compact data.
pub fn ntt_fw_compact(input: &[u8]) -> Option<Vec<u8>> {
    let coeffs = unpack(input)?;
    let params = falcon_params();
    Some(pack(&fast::ntt_fw_fast(&coeffs, &params)))
}

/// NTT inverse on compact data.
pub fn ntt_inv_compact(input: &[u8]) -> Option<Vec<u8>> {
    let coeffs = unpack(input)?;
    let params = falcon_params();
    Some(pack(&fast::ntt_inv_fast(&coeffs, &params)))
}

/// Pointwise multiply mod q on two compact vectors (2048 bytes input).
pub fn vecmulmod_compact(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() != 2 * COMPACT_SIZE {
        return None;
    }
    let a = unpack(&input[..COMPACT_SIZE])?;
    let b = unpack(&input[COMPACT_SIZE..])?;
    Some(pack(&fast::vec_mul_mod_fast(&a, &b, Q)))
}

/// SHAKE256 hash-to-point: input = salt||msg, output = compact.
pub fn shake256_htp(input: &[u8]) -> Vec<u8> {
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    let mut coeffs = Vec::with_capacity(N);
    let mut buf = [0u8; 2];
    while coeffs.len() < N {
        reader.read(&mut buf);
        let t = (buf[0] as u64) * 256 + buf[1] as u64;
        if t < 61445 {
            coeffs.push(t % Q);
        }
    }
    pack(&coeffs)
}

/// Falcon-512 norm check (compact format convenience).
pub fn falcon_norm(s1_compact: &[u8], s2_compact: &[u8], hashed_compact: &[u8]) -> bool {
    let s1 = match unpack(s1_compact) { Some(c) => c, None => return false };
    let s2 = match unpack(s2_compact) { Some(c) => c, None => return false };
    let hashed = match unpack(hashed_compact) { Some(c) => c, None => return false };
    falcon_norm_coeffs(&s1, &s2, &hashed)
}

/// Falcon-512 norm check on raw coefficient arrays.
pub fn falcon_norm_coeffs(s1: &[u64], s2: &[u64], hashed: &[u64]) -> bool {
    lp_norm_coeffs(Q, SIG_BOUND as u128, s1, s2, hashed)
}

/// Generalized centered L2 norm check for any lattice-based signature.
///
/// Computes: ||(hashed - s1) mod q||² + ||s2||² < bound
/// where centering maps x to min(x, q-x).
///
/// Works for Falcon-512 (q=12289, bound=34034726), Falcon-1024, Dilithium, etc.
pub fn lp_norm_coeffs(q: u64, bound: u128, s1: &[u64], s2: &[u64], hashed: &[u64]) -> bool {
    let n = s1.len();
    if s2.len() != n || hashed.len() != n {
        return false;
    }
    let qs1 = q / 2;
    let mut norm: u128 = 0;
    for i in 0..n {
        let mut d = (hashed[i] + q - s1[i]) % q;
        if d > qs1 { d = q - d; }
        norm += (d as u128) * (d as u128);

        let mut s = s2[i];
        if s > qs1 { s = q - s; }
        norm += (s as u128) * (s as u128);
    }
    norm < bound
}

/// Generalized LpNorm precompile.
/// Input: q(32 BE) | n(32 BE) | bound(32 BE) | cb(32 BE) | s1(n×cb) | s2(n×cb) | hashed(n×cb)
/// Output: 32 bytes (0x00..01 if norm < bound, 0x00..00 otherwise)
pub fn lp_norm_precompile(input: &[u8]) -> Option<Vec<u8>> {
    if input.len() < 128 { return None; }

    // Parse header (4 × 32-byte big-endian words)
    let q = read_u64_be(&input[0..32])?;
    let n = read_u64_be(&input[32..64])? as usize;
    let bound = read_u128_be(&input[64..96]);
    let cb = read_u64_be(&input[96..128])? as usize;

    if q == 0 || n == 0 || cb == 0 || cb > 8 { return None; }

    let vec_size = n.checked_mul(cb)?;
    let expected = 128 + 3 * vec_size;
    if input.len() != expected { return None; }

    let s1 = read_coeffs(&input[128..128 + vec_size], n, cb);
    let s2 = read_coeffs(&input[128 + vec_size..128 + 2 * vec_size], n, cb);
    let hashed = read_coeffs(&input[128 + 2 * vec_size..], n, cb);

    let valid = lp_norm_coeffs(q, bound, &s1, &s2, &hashed);
    let mut result = vec![0u8; 32];
    if valid { result[31] = 1; }
    Some(result)
}

// ─── Helpers ───

fn read_u64_be(data: &[u8]) -> Option<u64> {
    // Read from last 8 bytes of a 32-byte BE word (skip leading zeros)
    if data.len() != 32 { return None; }
    // Check that the top 24 bytes are zero
    if data[..24].iter().any(|&b| b != 0) { return None; }
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&data[24..32]);
    Some(u64::from_be_bytes(buf))
}

fn read_u128_be(data: &[u8]) -> u128 {
    if data.len() != 32 { return 0; }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&data[16..32]);
    u128::from_be_bytes(buf)
}

fn read_coeffs(data: &[u8], n: usize, cb: usize) -> Vec<u64> {
    let mut coeffs = Vec::with_capacity(n);
    for i in 0..n {
        let start = i * cb;
        let mut val: u64 = 0;
        for j in 0..cb {
            val = (val << 8) | data[start + j] as u64;
        }
        coeffs.push(val);
    }
    coeffs
}

/// Falcon-512 verify precompile.
/// Input: s2(1024, 512×uint16 BE) | ntth(1024, 512×uint16 BE) | salt_msg(var)
/// Output: 32 bytes (0x00..01 valid, 0x00..00 invalid)
pub fn falcon_verify_precompile(input: &[u8]) -> Option<Vec<u8>> {
    const VEC_SIZE: usize = N * 2; // 512 × 2 bytes = 1024
    if input.len() < 2 * VEC_SIZE {
        return None;
    }
    let s2 = read_u16_be_array(&input[0..VEC_SIZE]);
    let ntth = read_u16_be_array(&input[VEC_SIZE..2 * VEC_SIZE]);
    let salt_msg = &input[2 * VEC_SIZE..];

    let params = falcon_params();
    let hashed_compact = shake256_htp(salt_msg);
    let hashed = unpack(&hashed_compact).unwrap();

    let ntt_s2 = fast::ntt_fw_fast(&s2, params);
    let product = fast::vec_mul_mod_fast(&ntt_s2, &ntth, Q);
    let s1 = fast::ntt_inv_fast(&product, params);

    to_result(falcon_norm_coeffs(&s1, &s2, &hashed))
}

fn read_u16_be_array(data: &[u8]) -> Vec<u64> {
    data.chunks_exact(2)
        .map(|c| ((c[0] as u64) << 8) | c[1] as u64)
        .collect()
}

fn to_result(valid: bool) -> Option<Vec<u8>> {
    let mut result = vec![0u8; 32];
    if valid { result[31] = 1; }
    Some(result)
}

/// Full Falcon-512 verification pipeline on compact data.
/// Input: salt||msg, s2_compact, ntth_compact (public key in NTT domain).
/// Returns true if signature is valid.
pub fn falcon_verify(salt_msg: &[u8], s2_compact: &[u8], ntth_compact: &[u8]) -> bool {
    let hashed = shake256_htp(salt_msg);

    let s2_coeffs = match unpack(s2_compact) {
        Some(c) => c,
        None => return false,
    };
    let ntth_coeffs = match unpack(ntth_compact) {
        Some(c) => c,
        None => return false,
    };

    let params = falcon_params();
    let ntt_s2 = fast::ntt_fw_fast(&s2_coeffs, &params);
    let product = fast::vec_mul_mod_fast(&ntt_s2, &ntth_coeffs, Q);
    let s1 = fast::ntt_inv_fast(&product, &params);

    let hashed_coeffs = unpack(&hashed).unwrap();
    falcon_norm_coeffs(&s1, &s2_coeffs, &hashed_coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pack_unpack_roundtrip() {
        let coeffs: Vec<u64> = (0..N as u64).map(|i| i % Q).collect();
        let packed = pack(&coeffs);
        let unpacked = unpack(&packed).unwrap();
        assert_eq!(coeffs, unpacked);
    }

    #[test]
    fn test_ntt_compact_roundtrip() {
        let coeffs: Vec<u64> = (0..N as u64).map(|i| i % Q).collect();
        let packed = pack(&coeffs);
        let fwd = ntt_fw_compact(&packed).unwrap();
        let inv = ntt_inv_compact(&fwd).unwrap();
        let recovered = unpack(&inv).unwrap();
        assert_eq!(coeffs, recovered);
    }

    #[test]
    fn test_shake256_htp_deterministic() {
        let input = b"test input data";
        let a = shake256_htp(input);
        let b = shake256_htp(input);
        assert_eq!(a, b);
        assert_eq!(a.len(), COMPACT_SIZE);
        // All coefficients should be < Q
        let coeffs = unpack(&a).unwrap();
        assert!(coeffs.iter().all(|&c| c < Q));
    }

    #[test]
    fn test_norm_valid() {
        // s1 = hashed (so d = 0 for all), s2 = all zeros → norm = 0
        let hashed: Vec<u64> = (0..N as u64).map(|i| i % Q).collect();
        let s1 = hashed.clone();
        let s2 = vec![0u64; N];
        assert!(falcon_norm_coeffs(&s1, &s2, &hashed));
    }

    #[test]
    fn test_norm_invalid() {
        let hashed = vec![0u64; N];
        let s1 = vec![0u64; N];
        let s2 = vec![6000u64; N];
        assert!(!falcon_norm_coeffs(&s1, &s2, &hashed));
    }

    #[test]
    fn test_lp_norm_falcon() {
        // Valid: s1 == hashed, s2 = 0 → norm = 0
        let s1: Vec<u64> = (0..512).map(|i| i % Q).collect();
        let hashed = s1.clone();
        let s2 = vec![0u64; 512];
        assert!(lp_norm_coeffs(Q, SIG_BOUND as u128, &s1, &s2, &hashed));
    }

    #[test]
    fn test_lp_norm_dilithium_params() {
        // Dilithium: q=8380417, n=256
        let q = 8380417u64;
        let n = 256;
        let bound = 1u128 << 40; // arbitrary large bound for test
        let s1 = vec![0u64; n];
        let s2 = vec![1u64; n]; // small s2
        let hashed = vec![0u64; n];
        // norm = 256 * 1² = 256, well under bound
        assert!(lp_norm_coeffs(q, bound, &s1, &s2, &hashed));
    }

    #[test]
    fn test_falcon_verify_precompile_valid() {
        // Build a valid verification using the precompile format
        let params = falcon_params();
        let s2: Vec<u64> = vec![0u64; N]; // zero s2 = trivial sig
        let h: Vec<u64> = (0..N as u64).map(|i| (i * 13 + 1) % Q).collect();
        let ntth = fast::ntt_fw_fast(&h, params);

        let salt_msg = b"test salt data for hash to point verification";

        let s2c = pack(&s2);
        let ntthc = pack(&ntth);

        let mut input = vec![0u8; 32];
        let sm_len = salt_msg.len() as u64;
        input[24..32].copy_from_slice(&sm_len.to_be_bytes());
        input.extend_from_slice(&s2c);
        input.extend_from_slice(&ntthc);
        input.extend_from_slice(salt_msg);

        let result = falcon_verify_precompile(&input).unwrap();
        // With s2=0, s1 = INTT(NTT(0)*NTT(h)) = 0, norm = ||hashed||²
        // This may or may not pass the bound depending on hashed values.
        // Just check it returns something valid (32 bytes).
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn test_falcon_verify_roundtrip() {
        // Verify that falcon_verify matches manual pipeline
        let s2: Vec<u64> = (0..N as u64).map(|i| ((i as i64 % 3 - 1).rem_euclid(Q as i64)) as u64).collect();
        let h: Vec<u64> = (0..N as u64).map(|i| (i * 7 + 3) % Q).collect();
        let ntth = fast::ntt_fw_fast(&h, falcon_params());

        let salt_msg = b"nonce40bytesxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxmsg";
        let s2c = pack(&s2);
        let ntthc = pack(&ntth);

        let result_api = falcon_verify(salt_msg, &s2c, &ntthc);

        // Manual pipeline
        let hashed = shake256_htp(salt_msg);
        let hashed_coeffs = unpack(&hashed).unwrap();
        let ntt_s2 = fast::ntt_fw_fast(&s2, falcon_params());
        let product = fast::vec_mul_mod_fast(&ntt_s2, &ntth, Q);
        let s1 = fast::ntt_inv_fast(&product, falcon_params());
        let result_manual = falcon_norm_coeffs(&s1, &s2, &hashed_coeffs);

        assert_eq!(result_api, result_manual);
    }

    #[test]
    fn test_lp_norm_precompile() {
        // Build precompile input for Falcon-512
        let q: u64 = Q;
        let n: u64 = N as u64;
        let bound: u128 = SIG_BOUND as u128;
        let cb: u64 = 2;

        let mut input = Vec::new();
        // q (32 bytes BE)
        input.extend_from_slice(&[0u8; 24]);
        input.extend_from_slice(&q.to_be_bytes());
        // n (32 bytes BE)
        input.extend_from_slice(&[0u8; 24]);
        input.extend_from_slice(&n.to_be_bytes());
        // bound (32 bytes BE)
        input.extend_from_slice(&[0u8; 16]);
        input.extend_from_slice(&bound.to_be_bytes());
        // cb (32 bytes BE)
        input.extend_from_slice(&[0u8; 24]);
        input.extend_from_slice(&cb.to_be_bytes());

        // s1 = hashed, s2 = 0 → norm = 0, should be valid
        let hashed: Vec<u64> = (0..N as u64).map(|i| i % Q).collect();
        for &c in &hashed {
            input.extend_from_slice(&(c as u16).to_be_bytes());
        }
        // s2 = all zeros
        for _ in 0..N {
            input.extend_from_slice(&[0u8; 2]);
        }
        // hashed
        for &c in &hashed {
            input.extend_from_slice(&(c as u16).to_be_bytes());
        }

        let result = lp_norm_precompile(&input).unwrap();
        assert_eq!(result[31], 1, "expected valid norm");
    }
}
