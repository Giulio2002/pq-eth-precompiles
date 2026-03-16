# eth-ntt

Post-quantum lattice precompiles for Ethereum: NTT, SHAKE, Falcon-512, Dilithium (ML-DSA-44) verification.

Seven EVM precompiles (addresses `0x12`–`0x18`) that bring efficient Ring-LWE cryptographic operations on-chain, enabling post-quantum signature verification at ~8 μs per Falcon-512 verify with only 2.9% of transaction gas spent on actual cryptography.

## Precompiles

| Address | Name | Description | Gas |
|---------|------|-------------|-----|
| `0x12` | NTT_FW | Forward Number Theoretic Transform | 600 |
| `0x13` | NTT_INV | Inverse NTT with n⁻¹ scaling | 600 |
| `0x14` | VECMULMOD | Element-wise modular multiplication | variable |
| `0x15` | VECADDMOD | Element-wise modular addition | variable |
| `0x16` | SHAKE | Generic SHAKE-N (128 or 256) XOF | variable |
| `0x17` | FALCON_VERIFY | Full Falcon-512 signature verification | 2800 |
| `0x18` | LP_NORM | Generalized centered L2 norm check | 400 |

The polynomial precompiles (`0x12`–`0x15`) are generic over ring parameters (q, n, ψ) and work for any lattice scheme — Falcon, Dilithium, Kyber, etc. LP_NORM accepts a configurable coefficient byte width (`cb`) to support different modulus sizes.

## On-chain contracts

Yul verifier contracts with different trade-offs:

| Contract | Scheme | Approach | Precompile calls |
|----------|--------|----------|-----------------|
| `FalconVerifierDirectVerify` | Falcon-512 | Single precompile call | 1 |
| `FalconVerifierNTTWithLpNorm` | Falcon-512 | Generic NTT + LP_NORM | 5 |
| `FalconVerifierNTT` | Falcon-512 | Generic NTT + on-chain norm | 4 |
| `DilithiumVerifierNTT` | ML-DSA-44 | Generic NTT + on-chain verify | ~45 |

## Performance

Measured on Apple M4. Montgomery multiplication is used automatically for q < 2³¹.

| Operation | Time | Speedup vs BigUint |
|-----------|------|--------------------|
| NTT forward (n=512, q=12289) | 2.43 μs | 1,226x |
| NTT inverse | 2.20 μs | 1,423x |
| Falcon-512 full verify | 8.1 μs | 1,150x+ |
| Polynomial multiply (3-call pipeline) | 7.9 μs | 1,262x |

Three arithmetic backends are selected automatically based on modulus size:

```
q < 2³¹       → Montgomery (u32, no division)
q ∈ [2³¹, 2⁶³) → u64 with u128 intermediate
q ≥ 2⁶³       → BigUint (arbitrary precision)
```

## Building

Rust library:

```bash
cargo build --release
cargo test
cargo bench
```

Cross-platform static libraries for Go CGO:

```bash
make precompiles                  # all targets
make precompile-linux-amd64       # single target
```

Supported targets: `darwin-{amd64,arm64}`, `linux-{amd64,arm64,riscv64}`, `windows-{amd64,arm64}`.

## Go bindings

```go
import "github.com/pq-eth/eth-ntt/go/ntt"

// Precompile API (same ABI as EVM calldata)
result, err := ntt.NttFwPrecompile(input)
valid, err := ntt.FalconVerify(input)

// Fast direct API
params, _ := ntt.NewFastParams(q, n, psi)
transformed := params.Forward(coeffs)
```

## Project structure

```
src/
  lib.rs          Public API
  field.rs        Modular arithmetic, roots of unity
  ntt.rs          Reference NTT (BigUint)
  fast.rs         Optimized NTT: Montgomery + u64 backends
  precompile.rs   EVM precompile ABI, encode/decode/dispatch
  falcon.rs       Falcon-512: SHAKE256 hash-to-point, L2 norm, verify
  ffi.rs          C FFI exports
include/
  eth_ntt.h       C header
go/ntt/
  ntt.go          Go CGO bindings
  ntt_test.go     Go tests
kurtosis/
  contracts/      Yul verifier contracts
  README.md       Devnet setup and fuzzing
docs/
  design.md       NTT algorithms and optimization tiers
  precompiles.md  Precompile API reference
  benchmarks.md   Gas cost analysis
fuzz/             libfuzzer targets (16,090 iterations, 0 failures)
benches/          Criterion benchmarks
tests/            Integration tests with real Falcon-512 signatures
```

## Fuzzing

```bash
cargo +nightly fuzz run fuzz_ntt_fw
cargo +nightly fuzz run fuzz_falcon_compact
```

Targets: `fuzz_ntt_fw`, `fuzz_ntt_inv`, `fuzz_vecmulmod`, `fuzz_vecaddmod`, `fuzz_falcon_compact`.

## Devnet

A Kurtosis-based devnet (Erigon + Lighthouse, Osaka fork) is included for end-to-end testing. See [`kurtosis/README.md`](kurtosis/README.md).

## License

[MIT](LICENSE) — Giulio Rebuffo
