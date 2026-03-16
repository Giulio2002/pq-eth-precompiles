# Precompile API Reference

Six precompiles following existing Ethereum conventions.

| Address | Name | Pattern | Analogous to |
|---------|------|---------|--------------|
| `0x12` | NTT_FW | 32-byte padded params + coefficients | ecrecover (`0x01`) |
| `0x13` | NTT_INV | 32-byte padded params + coefficients | ecrecover (`0x01`) |
| `0x14` | VECMULMOD | 32-byte padded params + two vectors | ecrecover (`0x01`) |
| `0x15` | VECADDMOD | 32-byte padded params + two vectors | ecrecover (`0x01`) |
| `0x16` | SHAKE256 | output-length + data | SHA-256 (`0x02`) |
| `0x17` | FALCON_VERIFY | fixed arrays + variable data → bool | bn256Pairing (`0x08`) |
| `0x18` | LP_NORM | 32-byte padded params + three vectors → bool | bn256Pairing (`0x08`) |

### Conventions

- All parameters are zero-padded to 32 bytes, big-endian (standard EVM word).
- Coefficient byte width `cb = ceil(bits(q) / 8)` is derived from `q` — not passed explicitly.
- Coefficients are flat big-endian arrays: coefficient `i` at bytes `[i×cb .. (i+1)×cb]`.
- Boolean outputs are 32-byte words: `0x00..01` (true) or `0x00..00` (false), same as `bn256Pairing`.
- Error on malformed input (returns empty / fails the call).

---

## `0x12` — NTT_FW

Forward Number Theoretic Transform over Z_q.

**Input:**
```
n      (32 bytes BE)   — polynomial dimension (must be power of 2)
q      (32 bytes BE)   — prime modulus
psi    (32 bytes BE)   — primitive 2n-th root of unity mod q
coeffs (n × cb bytes)  — input coefficients, big-endian
```

`cb = ceil(bits(q) / 8)` — derived from `q`, not passed.

**Output:** `n × cb` bytes — NTT-transformed coefficients, big-endian.

**Gas:** 600

---

## `0x13` — NTT_INV

Inverse NTT with n⁻¹ mod q scaling. Same input/output format as `0x12`.

**Gas:** 600

---

## `0x14` — VECMULMOD

Element-wise modular multiplication: `result[i] = a[i] × b[i] mod q`.

**Input:**
```
n  (32 bytes BE)   — vector dimension
q  (32 bytes BE)   — modulus
a  (n × cb bytes)  — first vector, big-endian coefficients
b  (n × cb bytes)  — second vector, big-endian coefficients
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

**Input:**
```
output_len  (32 bytes BE)  — desired output length in bytes
data        (var bytes)    — data to hash
```

**Output:** `output_len` bytes of SHAKE256(data).

**Gas:** `30 + 6 × ceil(len(data) / 32)` (same formula as KECCAK256)

---

## `0x17` — FALCON_VERIFY

Full Falcon-512 signature verification in a single call. Performs SHAKE256 hash-to-point, forward NTT, pointwise multiply, inverse NTT, and centered L2 norm check.

**Input:**
```
s2       (1024 bytes)  — signature polynomial, 512 × uint16 big-endian
ntth     (1024 bytes)  — public key in NTT domain, 512 × uint16 big-endian
salt_msg (var bytes)   — nonce (40 bytes) concatenated with message
```

Each coefficient is a 2-byte big-endian unsigned integer in [0, 12288].

**Output:** 32 bytes — `0x0000...0001` if valid, `0x0000...0000` if invalid.

**Gas:** 2800

**Parameters** (hardcoded, Falcon-512):
- q = 12289
- n = 512
- psi = 49
- L2 norm bound = 34034726

---

## `0x18` — LP_NORM

Generalized centered L2 norm check for any lattice-based signature scheme.

Computes `||(hashed - s1) mod q||^2 + ||s2||^2 < bound` with centering: each coefficient mapped to `min(x, q-x)`.

**Input:**
```
q      (32 bytes BE) — field modulus
n      (32 bytes BE) — dimension
bound  (32 bytes BE) — squared norm bound
cb     (32 bytes BE) — coefficient byte width (2 for Falcon, 4 for Dilithium)
s1     (n × cb bytes, BE) — first component
s2     (n × cb bytes, BE) — second component
hashed (n × cb bytes, BE) — hash-to-point result
```

**Output:** 32 bytes — `0x0000...0001` if norm is below bound, `0x0000...0000` otherwise.

**Gas:** 400

Works for Falcon-512 (q=12289, n=512, cb=2, bound=34034726), Falcon-1024, Dilithium, and any future lattice scheme.

---

## Benchmarks (Apple M4)

| Precompile | Execution time | Gas |
|---|---|---|
| NTT_FW | 2.8 us | 600 |
| NTT_INV | 2.8 us | 600 |
| VECMULMOD | 590 ns | variable |
| VECADDMOD | 590 ns | variable |
| SHAKE256 | 1.8 us | variable |
| **FALCON_VERIFY** | **8.1 us** | **2800** |
| LP_NORM | 1.0 us | 400 |

Gas prices target 350 Mgas/s throughput.

---

## On-chain contracts

Three Yul contracts with different trade-offs:

### FalconVerifierNTT

Uses generic NTT precompiles (0x12-0x14) + SHAKE256 (0x16) with an on-chain norm check loop.

| Metric | Value |
|---|---|
| Precompiles used | 0x12, 0x13, 0x14, 0x16 (4 calls) |
| Runtime bytecode | 266 bytes |
| Verify gas | ~180,000 |

### FalconVerifierNTTWithLpNorm

Same as NTT but replaces the on-chain norm loop with an LpNorm precompile call.

| Metric | Value |
|---|---|
| Precompiles used | 0x12, 0x13, 0x14, 0x16, LpNorm (5 calls) |
| Runtime bytecode | 116 bytes |
| Verify gas | ~98,000 |

### FalconVerifierDirectVerify

Single call to FALCON_VERIFY (0x17). Calldata = precompile input, zero rearrangement.

```yul
calldatacopy(0, 0, calldatasize())
if iszero(staticcall(gas(), 0x17, 0, calldatasize(), 0, 0x20)) { revert(0,0) }
return(0, 0x20)
```

**Calldata:** `s2(1024, 512 x uint16 BE) | ntth(1024, 512 x uint16 BE) | salt(40) | msg(var)`

| Metric | Value |
|---|---|
| Precompiles used | 0x17 (1 call) |
| Runtime bytecode | 25 bytes |
| Deploy gas | 58,586 |
| Verify gas | ~97,000 |

### Gas breakdown (FalconVerifierDirectVerify)

| Component | Gas | % |
|---|---|---|
| Base tx | 21,000 | 21.6% |
| Calldata (2.1 KB) | ~30,600 | 31.5% |
| Cold STATICCALL | 2,600 | 2.7% |
| FALCON_VERIFY precompile | 2,800 | 2.9% |
| EVM overhead | ~40,000 | 41.3% |

The actual cryptography is **2.9%** of total gas. The rest is EVM fixed costs.
