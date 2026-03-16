use pq_eth_precompiles::{
    decode_output, encode_ntt_input, encode_vec_input, ntt_fw_precompile, ntt_inv_precompile,
    ntt_vecmulmod_precompile, FieldParams,
};
use num_bigint::BigUint;
use num_traits::Zero;
use pqcrypto_falcon::falcon512;
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as _};
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

const Q: u64 = 12289;
const N: usize = 512;
const NONCE_LEN: usize = 40;
const L2_BOUND: u64 = 34034726;

fn falcon512_params() -> FieldParams {
    let q = BigUint::from(Q);
    let psi = BigUint::from(49u64);
    FieldParams::new(q, N, psi).unwrap()
}

struct BitReader<'a> {
    data: &'a [u8],
    byte_pos: usize,
    bit_pos: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            byte_pos: 0,
            bit_pos: 0,
        }
    }

    fn read_bit(&mut self) -> Option<u8> {
        if self.byte_pos >= self.data.len() {
            return None;
        }
        let bit = (self.data[self.byte_pos] >> (7 - self.bit_pos)) & 1;
        self.bit_pos += 1;
        if self.bit_pos == 8 {
            self.bit_pos = 0;
            self.byte_pos += 1;
        }
        Some(bit)
    }

    fn read_bits(&mut self, n: u8) -> Option<u32> {
        let mut val = 0u32;
        for _ in 0..n {
            val = (val << 1) | self.read_bit()? as u32;
        }
        Some(val)
    }
}

fn decode_pubkey(pk_bytes: &[u8]) -> Vec<BigUint> {
    assert_eq!(pk_bytes.len(), 897, "FALCON-512 public key must be 897 bytes");
    assert_eq!(pk_bytes[0], 0x09);

    let mut reader = BitReader::new(&pk_bytes[1..]);
    let mut h = Vec::with_capacity(N);
    for _ in 0..N {
        let val = reader.read_bits(14).expect("truncated public key");
        h.push(BigUint::from(val));
    }
    h
}

fn decode_signature(sig_bytes: &[u8]) -> (Vec<u8>, Vec<BigUint>) {
    let nonce = sig_bytes[1..1 + NONCE_LEN].to_vec();
    let comp_data = &sig_bytes[1 + NONCE_LEN..];

    let mut reader = BitReader::new(comp_data);
    let mut s2 = Vec::with_capacity(N);

    for _ in 0..N {
        let sign = reader.read_bit().expect("truncated signature");
        let low = reader.read_bits(7).expect("truncated signature");

        let mut high = 0u32;
        loop {
            let bit = reader.read_bit().expect("truncated signature");
            if bit == 1 {
                break;
            }
            high += 1;
        }

        let magnitude = (high << 7) | low;
        if sign == 1 {
            s2.push(BigUint::from(Q - magnitude as u64));
        } else {
            s2.push(BigUint::from(magnitude as u64));
        }
    }

    (nonce, s2)
}

fn hash_to_point(nonce: &[u8], message: &[u8]) -> Vec<BigUint> {
    let mut hasher = Shake256::default();
    hasher.update(nonce);
    hasher.update(message);
    let mut reader = hasher.finalize_xof();

    let threshold: u16 = 61445;
    let mut c = Vec::with_capacity(N);
    while c.len() < N {
        let mut buf = [0u8; 2];
        reader.read(&mut buf);
        let t = ((buf[0] as u16) << 8) | (buf[1] as u16);
        if t < threshold {
            c.push(BigUint::from((t % Q as u16) as u64));
        }
    }
    c
}

fn squared_norm(poly: &[BigUint]) -> BigUint {
    let q = BigUint::from(Q);
    let half_q = BigUint::from(Q / 2);
    poly.iter()
        .map(|c| {
            let centered = if c > &half_q { &q - c } else { c.clone() };
            &centered * &centered
        })
        .fold(BigUint::zero(), |acc, x| acc + x)
}

/// Verify a FALCON-512 signature using only precompile functions.
fn verify_falcon512_via_precompiles(
    pk_bytes: &[u8],
    sig_bytes: &[u8],
    message: &[u8],
) -> Result<(), String> {
    let params = falcon512_params();
    let q = &params.q;
    let cb = params.coeff_byte_len();

    let h = decode_pubkey(pk_bytes);
    let (nonce, s2) = decode_signature(sig_bytes);
    let c = hash_to_point(&nonce, message);

    // NTT forward on s2 and h via precompile
    let fw_s2_out = ntt_fw_precompile(&encode_ntt_input(&params, &s2))
        .map_err(|e| e.to_string())?;
    let ntt_s2 = decode_output(&fw_s2_out, N, cb);

    let fw_h_out = ntt_fw_precompile(&encode_ntt_input(&params, &h))
        .map_err(|e| e.to_string())?;
    let ntt_h = decode_output(&fw_h_out, N, cb);

    // Pointwise multiply via precompile
    let mul_out = ntt_vecmulmod_precompile(&encode_vec_input(q, N, &ntt_s2, &ntt_h))
        .map_err(|e| e.to_string())?;
    let ntt_prod = decode_output(&mul_out, N, cb);

    // NTT inverse via precompile
    let inv_out = ntt_inv_precompile(&encode_ntt_input(&params, &ntt_prod))
        .map_err(|e| e.to_string())?;
    let t = decode_output(&inv_out, N, cb);

    // Recover s1 = c - t mod q
    let s1: Vec<BigUint> = c
        .iter()
        .zip(t.iter())
        .map(|(ci, ti)| {
            if ci >= ti {
                (ci - ti) % q
            } else {
                q - ((ti - ci) % q)
            }
        })
        .collect();

    // Norm check
    let total_norm = &squared_norm(&s1) + &squared_norm(&s2);
    let bound = BigUint::from(L2_BOUND);
    if total_norm > bound {
        return Err(format!(
            "norm check failed: ||(s1,s2)||² = {} > {} = β²",
            total_norm, bound
        ));
    }

    Ok(())
}

#[test]
fn falcon512_real_multiple_messages() {
    let (pk, sk) = falcon512::keypair();

    let messages: &[&[u8]] = &[
        b"",
        b"a",
        b"The quick brown fox jumps over the lazy dog",
        &[0u8; 1024],
        &(0..=255).collect::<Vec<u8>>(),
    ];

    for (i, msg) in messages.iter().enumerate() {
        let sig = falcon512::detached_sign(msg, &sk);

        falcon512::verify_detached_signature(&sig, msg, &pk)
            .unwrap_or_else(|_| panic!("library verify failed for message {}", i));

        verify_falcon512_via_precompiles(pk.as_bytes(), sig.as_bytes(), msg)
            .unwrap_or_else(|e| panic!("precompile verify failed for message {}: {}", i, e));
    }
}
