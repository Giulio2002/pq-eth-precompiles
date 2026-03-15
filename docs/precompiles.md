# Precompile API Reference

Six precompiles following existing Ethereum conventions.

| Address | Name | Pattern | Analogous to |
|---------|------|---------|--------------|
| `0x12` | NTT_FW | length-prefixed fields | modexp (`0x05`) |
| `0x13` | NTT_INV | length-prefixed fields | modexp (`0x05`) |
| `0x14` | VECMULMOD | length-prefixed fields | modexp (`0x05`) |
| `0x15` | VECADDMOD | length-prefixed fields | modexp (`0x05`) |
| `0x16` | SHAKE256 | output-length + data | SHA-256 (`0x02`) |
| `0x17` | FALCON_VERIFY | fixed arrays + bool | bn256Pairing (`0x08`) |

---

## `0x12` — NTT_FW

Forward Number Theoretic Transform over Z_q.

**Input** (like modexp — length-prefixed variable fields):
```
q_len    (32 bytes BE)   — byte length of modulus q
psi_len  (32 bytes BE)   — byte length of root of unity psi
n        (32 bytes BE)   — polynomial dimension (power of 2)
q        (q_len bytes)   — prime modulus, big-endian
psi      (psi_len bytes) — primitive 2n-th root of unity mod q, big-endian
coeffs   (n × cb bytes)  — input coefficients, big-endian (cb = ceil(bits(q) / 8))
```

**Output:** `n × cb` bytes — NTT-transformed coefficients, big-endian.

**Gas:** 600

---

## `0x13` — NTT_INV

Inverse NTT with n⁻¹ mod q scaling. Same input/output format as `0x12`.

**Gas:** 600

---

## `0x14` — VECMULMOD

Element-wise modular multiplication: `result[i] = a[i] × b[i] mod q`.

**Input** (like modexp — length-prefixed):
```
q_len  (32 bytes BE)
n      (32 bytes BE)
q      (q_len bytes)   — modulus, big-endian
a      (n × cb bytes)  — first vector, big-endian coefficients
b      (n × cb bytes)  — second vector, big-endian coefficients
```

**Output:** `n × cb` bytes — product vector, big-endian.

**Gas:** `k × log₂(n) / 8` where `k = next_power_of_two(bits(q))`

---

## `0x15` — VECADDMOD

Element-wise modular addition. Same format as `0x14`.

**Gas:** `k × log₂(n) / 32`

---

## `0x16` — SHAKE256

SHAKE256 extendable output function.

**Input** (like SHA-256 — hash with output length):
```
output_len  (32 bytes BE)  — desired output length in bytes
data        (var bytes)    — data to hash
```

**Output:** `output_len` bytes of SHAKE256(data).

**Gas:** `30 + 6 × ceil(len(data) / 32)` (same formula as KECCAK256)

---

## `0x17` — FALCON_VERIFY

Full Falcon-512 signature verification. Performs SHAKE256 hash-to-point, forward NTT, pointwise multiply, inverse NTT, and centered L2 norm check in a single call.

**Input** (like bn256Pairing — fixed-size arrays followed by variable data):
```
s2       (1024 bytes)  — signature polynomial, 512 × uint16 big-endian
ntth     (1024 bytes)  — public key in NTT domain, 512 × uint16 big-endian
salt_msg (var bytes)   — nonce (40 bytes) concatenated with message
```

Each coefficient is a 2-byte big-endian unsigned integer in [0, 12288].

**Output:** 32 bytes — `0x0000...0001` if valid, `0x0000...0000` if invalid. Same convention as bn256Pairing.

**Gas:** 2800

**Parameters** (hardcoded, Falcon-512):
- q = 12289
- n = 512
- ψ = 49
- L2 norm bound = 34034726

---

## Benchmarks (Apple M4)

| Precompile | Execution time | Gas |
|---|---|---|
| NTT_FW | 2.8 µs | 600 |
| NTT_INV | 2.8 µs | 600 |
| VECMULMOD | 590 ns | variable |
| VECADDMOD | 590 ns | variable |
| SHAKE256 | 1.8 µs | variable |
| **FALCON_VERIFY** | **8.1 µs** | **2800** |

Gas prices target 350 Mgas/s throughput.

---

## On-chain verification (FalconVerifierV5.yul)

The V5 contract is a minimal Yul wrapper around FALCON_VERIFY:

```yul
calldatacopy(0, 0, calldatasize())
if iszero(staticcall(gas(), 0x17, 0, calldatasize(), 0, 0x20)) { revert(0,0) }
return(0, 0x20)
```

**Calldata layout** = precompile input (zero rearrangement):
```
s2(1024, 512×uint16 BE) | ntth(1024, 512×uint16 BE) | salt(40) | msg(var)
```

| Metric | Value |
|---|---|
| Runtime bytecode | 25 bytes |
| Deploy gas | 58,586 |
| Verify gas (total tx) | ~97,000 |

### Gas breakdown

| Component | Gas | % |
|---|---|---|
| Base tx | 21,000 | 21.6% |
| Calldata (2.1 KB) | ~30,600 | 31.5% |
| Cold STATICCALL | 2,600 | 2.7% |
| FALCON_VERIFY precompile | 2,800 | 2.9% |
| EVM overhead | ~40,000 | 41.3% |

The actual cryptography (NTT + SHAKE256 + norm check) is **2.9%** of total gas. The rest is EVM fixed costs.
