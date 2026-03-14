use num_bigint::BigUint;
use num_traits::Zero;
use thiserror::Error;

use crate::fast::{self, FastNttParams};
use crate::field::FieldParams;
use crate::ntt;

pub const NTT_GAS: u64 = 600;

const WORD: usize = 32;

#[derive(Debug, Error)]
pub enum PrecompileError {
    #[error("input too short")]
    InputTooShort,
    #[error("invalid field parameters: {0}")]
    InvalidParams(&'static str),
    #[error("unexpected input length")]
    BadLength,
    #[error("parameter overflow: {0}")]
    Overflow(&'static str),
}

/// Compute gas for VECMULMOD: k * log2(n) / 8, where k = smallest power of 2 >= log2(q).
pub fn vecmulmod_gas(q: &BigUint, n: usize) -> u64 {
    let log_q = q.bits() as u64;
    let k = log_q.next_power_of_two();
    let log_n = (n as f64).log2() as u64;
    k * log_n / 8
}

/// Compute gas for VECADDMOD: k * log2(n) / 32.
pub fn vecaddmod_gas(q: &BigUint, n: usize) -> u64 {
    let log_q = q.bits() as u64;
    let k = log_q.next_power_of_two();
    let log_n = (n as f64).log2() as u64;
    k * log_n / 32
}

/// Read a 32-byte big-endian word as a BigUint and advance the offset.
fn read_word(data: &[u8], offset: &mut usize) -> Result<BigUint, PrecompileError> {
    if *offset + WORD > data.len() {
        return Err(PrecompileError::InputTooShort);
    }
    let val = BigUint::from_bytes_be(&data[*offset..*offset + WORD]);
    *offset += WORD;
    Ok(val)
}

/// Read a 32-byte big-endian word, returning it as usize.
/// Rejects values that exceed the input length (impossible to be valid).
fn read_word_usize(data: &[u8], offset: &mut usize) -> Result<usize, PrecompileError> {
    let val = read_word(data, offset)?;
    if val.bits() > 64 {
        return Err(PrecompileError::Overflow("value exceeds 64 bits"));
    }
    let bytes = val.to_bytes_be();
    let mut buf = [0u8; 8];
    let start = 8usize.saturating_sub(bytes.len());
    buf[start..start + bytes.len()].copy_from_slice(&bytes);
    let v = u64::from_be_bytes(buf) as usize;
    if v > data.len() {
        return Err(PrecompileError::Overflow("parameter exceeds input size"));
    }
    Ok(v)
}

/// Read `len` raw bytes and decode as big-endian BigUint.
fn read_biguint(data: &[u8], offset: &mut usize, len: usize) -> Result<BigUint, PrecompileError> {
    if len > data.len() || *offset > data.len() - len {
        return Err(PrecompileError::InputTooShort);
    }
    let val = BigUint::from_bytes_be(&data[*offset..*offset + len]);
    *offset += len;
    Ok(val)
}

/// Encode a BigUint as exactly `byte_len` bytes big-endian (zero-padded on the left).
fn encode_biguint(val: &BigUint, byte_len: usize) -> Vec<u8> {
    let bytes = val.to_bytes_be();
    let mut padded = vec![0u8; byte_len];
    let start = byte_len.saturating_sub(bytes.len());
    let copy_len = bytes.len().min(byte_len);
    padded[start..start + copy_len].copy_from_slice(&bytes[bytes.len() - copy_len..]);
    padded
}

/// Encode a usize as a 32-byte big-endian word.
fn encode_word(val: usize) -> [u8; WORD] {
    let mut buf = [0u8; WORD];
    buf[WORD - 8..].copy_from_slice(&(val as u64).to_be_bytes());
    buf
}

fn decode_vector(
    data: &[u8],
    offset: &mut usize,
    n: usize,
    coeff_bytes: usize,
) -> Result<Vec<BigUint>, PrecompileError> {
    let total = n.checked_mul(coeff_bytes)
        .ok_or(PrecompileError::Overflow("n * coeff_bytes overflow"))?;
    if total > data.len() || *offset > data.len() - total {
        return Err(PrecompileError::InputTooShort);
    }
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(read_biguint(data, offset, coeff_bytes)?);
    }
    Ok(v)
}

fn encode_vector(v: &[BigUint], coeff_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * coeff_bytes);
    for val in v {
        out.extend_from_slice(&encode_biguint(val, coeff_bytes));
    }
    out
}

/// Read `len` big-endian bytes as a u64. Caller must ensure len <= 8.
fn bytes_to_u64(data: &[u8]) -> u64 {
    debug_assert!(data.len() <= 8);
    let mut buf = [0u8; 8];
    buf[8 - data.len()..].copy_from_slice(data);
    u64::from_be_bytes(buf)
}

/// Encode u64 values as big-endian byte vectors.
fn encode_vector_u64(v: &[u64], coeff_bytes: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(v.len() * coeff_bytes);
    for &val in v {
        let be = val.to_be_bytes();
        out.extend_from_slice(&be[8 - coeff_bytes..]);
    }
    out
}

/// Gas for VECMULMOD from u64 q.
fn vecmulmod_gas_u64(q_bits: u32, n: usize) -> u64 {
    let k = (q_bits as u64).next_power_of_two();
    let log_n = (n as f64).log2() as u64;
    k * log_n / 8
}

/// Gas for VECADDMOD from u64 q.
fn vecaddmod_gas_u64(q_bits: u32, n: usize) -> u64 {
    let k = (q_bits as u64).next_power_of_two();
    let log_n = (n as f64).log2() as u64;
    k * log_n / 32
}

/// Try to decode NTT calldata using u64 fast path.
/// Returns `Ok(None)` if q >= 2^63 (fall back to BigUint).
fn try_decode_ntt_fast(
    input: &[u8],
) -> Result<Option<(FastNttParams, Vec<u64>)>, PrecompileError> {
    let mut offset = 0;
    let q_len = read_word_usize(input, &mut offset)?;
    let psi_len = read_word_usize(input, &mut offset)?;
    let n = read_word_usize(input, &mut offset)?;

    // Fast path: q and psi must fit in u64
    if q_len > 8 || psi_len > 8 {
        return Ok(None);
    }

    if offset + q_len > input.len() {
        return Err(PrecompileError::InputTooShort);
    }
    let q = bytes_to_u64(&input[offset..offset + q_len]);
    offset += q_len;

    if q >= (1u64 << 63) {
        return Ok(None);
    }

    if offset + psi_len > input.len() {
        return Err(PrecompileError::InputTooShort);
    }
    let psi = bytes_to_u64(&input[offset..offset + psi_len]);
    offset += psi_len;

    let fast = FastNttParams::new(q, n, psi).map_err(PrecompileError::InvalidParams)?;
    let cb = fast.coeff_bytes;

    let total = n.checked_mul(cb).ok_or(PrecompileError::Overflow("n * coeff_bytes overflow"))?;
    if total > input.len() || offset > input.len() - total {
        return Err(PrecompileError::InputTooShort);
    }
    if offset + total != input.len() {
        return Err(PrecompileError::BadLength);
    }

    let mut a = Vec::with_capacity(n);
    for _ in 0..n {
        a.push(bytes_to_u64(&input[offset..offset + cb]));
        offset += cb;
    }

    Ok(Some((fast, a)))
}

/// Try to decode vec-op calldata using u64 fast path.
fn try_decode_vec_fast(
    input: &[u8],
) -> Result<Option<(u64, usize, Vec<u64>, Vec<u64>)>, PrecompileError> {
    let mut offset = 0;
    let q_len = read_word_usize(input, &mut offset)?;
    let n = read_word_usize(input, &mut offset)?;

    if q_len > 8 {
        return Ok(None);
    }

    if q_len > input.len() || offset > input.len() - q_len {
        return Err(PrecompileError::InputTooShort);
    }
    let q = bytes_to_u64(&input[offset..offset + q_len]);
    offset += q_len;

    if q >= (1u64 << 63) || q == 0 {
        return Ok(None);
    }

    let q_bits = 64 - q.leading_zeros();
    let cb = (q_bits as usize + 7) / 8;
    let expected = n.checked_mul(cb).and_then(|v| v.checked_mul(2))
        .ok_or(PrecompileError::Overflow("n * coeff_bytes overflow"))?;

    if expected > input.len() || offset > input.len() - expected {
        return Err(PrecompileError::InputTooShort);
    }
    if offset + expected != input.len() {
        return Err(PrecompileError::BadLength);
    }

    let mut a = Vec::with_capacity(n);
    for _ in 0..n {
        a.push(bytes_to_u64(&input[offset..offset + cb]));
        offset += cb;
    }
    let mut b = Vec::with_capacity(n);
    for _ in 0..n {
        b.push(bytes_to_u64(&input[offset..offset + cb]));
        offset += cb;
    }

    Ok(Some((q, n, a, b)))
}

/// Decode calldata for NTT_FW / NTT_INV.
///
/// Layout: `q_len(32) | psi_len(32) | n(32) | q(q_len) | psi(psi_len) | coeffs(n * coeff_bytes)`
fn decode_ntt_input(input: &[u8]) -> Result<(FieldParams, Vec<BigUint>), PrecompileError> {
    let mut offset = 0;
    let q_len = read_word_usize(input, &mut offset)?;
    let psi_len = read_word_usize(input, &mut offset)?;
    let n = read_word_usize(input, &mut offset)?;

    let q = read_biguint(input, &mut offset, q_len)?;
    let psi = read_biguint(input, &mut offset, psi_len)?;

    let params = FieldParams::new(q, n, psi).map_err(PrecompileError::InvalidParams)?;
    let coeff_bytes = params.coeff_byte_len();
    let a = decode_vector(input, &mut offset, n, coeff_bytes)?;

    if offset != input.len() {
        return Err(PrecompileError::BadLength);
    }

    Ok((params, a))
}

/// Decode calldata for NTT_VECMULMOD / NTT_VECADDMOD.
///
/// Layout: `q_len(32) | n(32) | q(q_len) | a(n * cb) | b(n * cb)`
fn decode_vec_input(
    input: &[u8],
) -> Result<(BigUint, usize, Vec<BigUint>, Vec<BigUint>), PrecompileError> {
    let mut offset = 0;
    let q_len = read_word_usize(input, &mut offset)?;
    let n = read_word_usize(input, &mut offset)?;

    let q = read_biguint(input, &mut offset, q_len)?;
    if q.is_zero() {
        return Err(PrecompileError::InvalidParams("q must be nonzero"));
    }

    let coeff_bytes = (q.bits() as usize + 7) / 8;
    let a = decode_vector(input, &mut offset, n, coeff_bytes)?;
    let b = decode_vector(input, &mut offset, n, coeff_bytes)?;

    if offset != input.len() {
        return Err(PrecompileError::BadLength);
    }

    Ok((q, n, a, b))
}

// ─── Public precompile entry points ───

/// Execute `NTT_FW` precompile. Returns `(gas_used, output_bytes)`.
pub fn ntt_fw_precompile(input: &[u8]) -> Result<(u64, Vec<u8>), PrecompileError> {
    // Try u64 fast path (covers all practical moduli)
    if let Some((fast, a)) = try_decode_ntt_fast(input)? {
        let result = fast::ntt_fw_fast(&a, &fast);
        return Ok((NTT_GAS, encode_vector_u64(&result, fast.coeff_bytes)));
    }
    // BigUint fallback for q >= 2^63
    let (params, a) = decode_ntt_input(input)?;
    let coeff_bytes = params.coeff_byte_len();
    let result = ntt::ntt_fw(&a, &params);
    Ok((NTT_GAS, encode_vector(&result, coeff_bytes)))
}

/// Execute `NTT_INV` precompile. Returns `(gas_used, output_bytes)`.
pub fn ntt_inv_precompile(input: &[u8]) -> Result<(u64, Vec<u8>), PrecompileError> {
    if let Some((fast, a)) = try_decode_ntt_fast(input)? {
        let result = fast::ntt_inv_fast(&a, &fast);
        return Ok((NTT_GAS, encode_vector_u64(&result, fast.coeff_bytes)));
    }
    let (params, a) = decode_ntt_input(input)?;
    let coeff_bytes = params.coeff_byte_len();
    let result = ntt::ntt_inv(&a, &params);
    Ok((NTT_GAS, encode_vector(&result, coeff_bytes)))
}

/// Execute `NTT_VECMULMOD` precompile. Returns `(gas_used, output_bytes)`.
pub fn ntt_vecmulmod_precompile(input: &[u8]) -> Result<(u64, Vec<u8>), PrecompileError> {
    if let Some((q, n, a, b)) = try_decode_vec_fast(input)? {
        let q_bits = 64 - q.leading_zeros();
        let cb = (q_bits as usize + 7) / 8;
        let gas = vecmulmod_gas_u64(q_bits, n);
        let result = fast::vec_mul_mod_fast(&a, &b, q);
        return Ok((gas, encode_vector_u64(&result, cb)));
    }
    let (q, n, a, b) = decode_vec_input(input)?;
    let coeff_bytes = (q.bits() as usize + 7) / 8;
    let gas = vecmulmod_gas(&q, n);
    let result = ntt::vec_mul_mod(&a, &b, &q);
    Ok((gas, encode_vector(&result, coeff_bytes)))
}

/// Execute `NTT_VECADDMOD` precompile. Returns `(gas_used, output_bytes)`.
pub fn ntt_vecaddmod_precompile(input: &[u8]) -> Result<(u64, Vec<u8>), PrecompileError> {
    if let Some((q, n, a, b)) = try_decode_vec_fast(input)? {
        let q_bits = 64 - q.leading_zeros();
        let cb = (q_bits as usize + 7) / 8;
        let gas = vecaddmod_gas_u64(q_bits, n);
        let result = fast::vec_add_mod_fast(&a, &b, q);
        return Ok((gas, encode_vector_u64(&result, cb)));
    }
    let (q, n, a, b) = decode_vec_input(input)?;
    let coeff_bytes = (q.bits() as usize + 7) / 8;
    let gas = vecaddmod_gas(&q, n);
    let result = ntt::vec_add_mod(&a, &b, &q);
    Ok((gas, encode_vector(&result, coeff_bytes)))
}

// ─── Calldata encoders (for building inputs from Rust) ───

/// Encode calldata for NTT_FW / NTT_INV.
pub fn encode_ntt_input(params: &FieldParams, a: &[BigUint]) -> Vec<u8> {
    let q_bytes = params.q.to_bytes_be();
    let psi_bytes = params.psi.to_bytes_be();
    let coeff_bytes = params.coeff_byte_len();

    let mut out = Vec::new();
    out.extend_from_slice(&encode_word(q_bytes.len())); // q_len  (32 bytes)
    out.extend_from_slice(&encode_word(psi_bytes.len())); // psi_len (32 bytes)
    out.extend_from_slice(&encode_word(params.n)); // n       (32 bytes)
    out.extend_from_slice(&q_bytes); // q       (q_len bytes)
    out.extend_from_slice(&psi_bytes); // psi     (psi_len bytes)
    out.extend_from_slice(&encode_vector(a, coeff_bytes)); // coefficients
    out
}

/// Encode calldata for NTT_VECMULMOD / NTT_VECADDMOD.
pub fn encode_vec_input(q: &BigUint, n: usize, a: &[BigUint], b: &[BigUint]) -> Vec<u8> {
    let q_bytes = q.to_bytes_be();
    let coeff_bytes = (q.bits() as usize + 7) / 8;

    let mut out = Vec::new();
    out.extend_from_slice(&encode_word(q_bytes.len())); // q_len (32 bytes)
    out.extend_from_slice(&encode_word(n)); // n     (32 bytes)
    out.extend_from_slice(&q_bytes); // q     (q_len bytes)
    out.extend_from_slice(&encode_vector(a, coeff_bytes));
    out.extend_from_slice(&encode_vector(b, coeff_bytes));
    out
}

/// Helper: decode output vector from precompile return bytes.
pub fn decode_output(output: &[u8], n: usize, coeff_bytes: usize) -> Vec<BigUint> {
    assert_eq!(
        output.len(),
        n * coeff_bytes,
        "output length mismatch"
    );
    (0..n)
        .map(|i| {
            let start = i * coeff_bytes;
            BigUint::from_bytes_be(&output[start..start + coeff_bytes])
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::mod_pow;
    use num_traits::{One, Zero};

    fn small_params() -> FieldParams {
        let q = BigUint::from(17u64);
        let n: usize = 4;
        let psi = BigUint::from(9u64);
        FieldParams::new(q, n, psi).unwrap()
    }

    fn falcon_params() -> FieldParams {
        let q = BigUint::from(12289u64);
        let n: usize = 512;
        let g = BigUint::from(11u64);
        let exp = (&q - BigUint::one()) / BigUint::from(2u64 * n as u64);
        let psi = mod_pow(&g, &exp, &q);
        FieldParams::new(q, n, psi).unwrap()
    }

    #[test]
    fn test_encode_word_be() {
        let w = encode_word(512);
        assert_eq!(w.len(), 32);
        assert_eq!(&w[..24], &[0u8; 24]);
        assert_eq!(u64::from_be_bytes(w[24..32].try_into().unwrap()), 512);
    }

    #[test]
    fn test_encode_biguint_zero() {
        let z = encode_biguint(&BigUint::zero(), 4);
        assert_eq!(z, vec![0, 0, 0, 0]);
    }

    #[test]
    fn test_ntt_fw_precompile_roundtrip() {
        let params = small_params();
        let a: Vec<BigUint> = vec![1u64, 2, 3, 4]
            .into_iter()
            .map(BigUint::from)
            .collect();

        let input = encode_ntt_input(&params, &a);
        let (gas, output) = ntt_fw_precompile(&input).unwrap();
        assert_eq!(gas, NTT_GAS);

        let cb = params.coeff_byte_len();
        let ntt_a = decode_output(&output, params.n, cb);

        let inv_input = encode_ntt_input(&params, &ntt_a);
        let (_, inv_output) = ntt_inv_precompile(&inv_input).unwrap();
        let recovered = decode_output(&inv_output, params.n, cb);

        assert_eq!(a, recovered);
    }

    #[test]
    fn test_vecmulmod_precompile() {
        let q = BigUint::from(17u64);
        let n = 4;
        let a: Vec<BigUint> = vec![5u64, 10, 15, 3]
            .into_iter()
            .map(BigUint::from)
            .collect();
        let b: Vec<BigUint> = vec![4u64, 8, 3, 16]
            .into_iter()
            .map(BigUint::from)
            .collect();

        let input = encode_vec_input(&q, n, &a, &b);
        let (gas, output) = ntt_vecmulmod_precompile(&input).unwrap();
        assert!(gas > 0);

        let results = decode_output(&output, n, 1);
        assert_eq!(
            results,
            vec![
                BigUint::from(3u64),
                BigUint::from(12u64),
                BigUint::from(11u64),
                BigUint::from(14u64),
            ]
        );
    }

    #[test]
    fn test_vecaddmod_precompile() {
        let q = BigUint::from(17u64);
        let n = 4;
        let a: Vec<BigUint> = vec![5u64, 10, 15, 3]
            .into_iter()
            .map(BigUint::from)
            .collect();
        let b: Vec<BigUint> = vec![4u64, 8, 3, 16]
            .into_iter()
            .map(BigUint::from)
            .collect();

        let input = encode_vec_input(&q, n, &a, &b);
        let (gas, output) = ntt_vecaddmod_precompile(&input).unwrap();
        assert_eq!(gas, 0);

        let results = decode_output(&output, n, 1);
        assert_eq!(
            results,
            vec![
                BigUint::from(9u64),
                BigUint::from(1u64),
                BigUint::from(1u64),
                BigUint::from(2u64),
            ]
        );
    }

    #[test]
    fn test_full_polymul_via_precompiles_falcon() {
        let params = falcon_params();
        let n = params.n;
        let q = &params.q;
        let cb = params.coeff_byte_len();

        let f: Vec<BigUint> = (0..n).map(|i| BigUint::from(i as u64)).collect();
        let g: Vec<BigUint> = (0..n).map(|i| BigUint::from((n - i) as u64)).collect();

        let (_, fw_f_out) = ntt_fw_precompile(&encode_ntt_input(&params, &f)).unwrap();
        let (_, fw_g_out) = ntt_fw_precompile(&encode_ntt_input(&params, &g)).unwrap();
        let ntt_f = decode_output(&fw_f_out, n, cb);
        let ntt_g = decode_output(&fw_g_out, n, cb);

        let (_, mul_out) = ntt_vecmulmod_precompile(&encode_vec_input(q, n, &ntt_f, &ntt_g)).unwrap();
        let ntt_product = decode_output(&mul_out, n, cb);

        let (_, inv_out) = ntt_inv_precompile(&encode_ntt_input(&params, &ntt_product)).unwrap();
        let product = decode_output(&inv_out, n, cb);

        let mut expected = vec![BigUint::from(0u64); n];
        for i in 0..n {
            for j in 0..n {
                let c = (&f[i] * &g[j]) % q;
                if i + j < n {
                    expected[i + j] = (&expected[i + j] + &c) % q;
                } else {
                    let idx = i + j - n;
                    expected[idx] = (q + &expected[idx] - &c) % q;
                }
            }
        }

        assert_eq!(product, expected);
    }

    #[test]
    fn test_gas_computation() {
        let q = BigUint::from(12289u64);
        assert_eq!(vecmulmod_gas(&q, 512), 18);
        assert_eq!(vecaddmod_gas(&q, 512), 4);

        let q_dil = BigUint::from(8380417u64);
        assert_eq!(vecmulmod_gas(&q_dil, 256), 32);
    }

    #[test]
    fn test_calldata_is_all_big_endian() {
        let params = small_params();
        let a: Vec<BigUint> = vec![1u64, 2, 3, 4]
            .into_iter()
            .map(BigUint::from)
            .collect();

        let input = encode_ntt_input(&params, &a);

        assert_eq!(input[31], 1);
        assert_eq!(&input[..31], &[0u8; 31]);

        assert_eq!(input[63], 1);

        assert_eq!(input[95], 4);

        assert_eq!(input[96], 17);

        assert_eq!(input[97], 9);

        assert_eq!(&input[98..102], &[1, 2, 3, 4]);
    }
}
