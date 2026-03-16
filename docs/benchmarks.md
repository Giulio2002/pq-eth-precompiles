# Benchmarks

Measured on Kurtosis devnet (Erigon + Lighthouse, Osaka fork). 16,090 fuzz iterations, 0 failures.

## Transaction cost

| Contract | Total Gas | Fixed Overhead | Verification | Crypto | Crypto Time |
|---|---|---|---|---|---|
| FalconVerifierNTT | 210,441 | 52,100 | 158,341 | 1,266 | 8.1 us |
| FalconVerifierNTTWithLpNorm | 98,780 | 52,100 | 46,680 | 1,666 | 8.1 us |
| FalconVerifierDirectVerify | 98,780 | 52,100 | 46,680 | 2,800 | 8.1 us |

- **Total Gas**: charged to sender (includes everything)
- **Fixed Overhead**: base tx (21,000) + calldata intrinsic (~31,100) — same for all, unavoidable
- **Verification**: Total - Fixed Overhead — what the contract actually executes
- **Crypto**: gas spent inside precompiles doing actual math
- **Crypto Time**: wall-clock time for the actual Falcon-512 verification in Rust (same math for all three)

All three do the same cryptography in the same time. The difference is how much EVM overhead surrounds it.

## Where the verification gas goes

| | NTT | NTTWithLpNorm | DirectVerify |
|---|---|---|---|
| Cold STATICCALL(s) | 10,400 (4x) | 13,000 (5x) | 2,600 (1x) |
| On-chain norm loop | ~100,000 | 0 | 0 |
| Memory + calldatacopy | ~46,675 | ~32,014 | ~41,280 |
| Precompile compute | 1,266 | 1,666 | 2,800 |
| **Verification total** | **158,341** | **46,680** | **46,680** |

## Fixed overhead breakdown

| Cost | Gas | Why |
|---|---|---|
| Base transaction | 21,000 | EIP-2718, every tx pays this |
| Calldata (2,117 bytes) | ~31,100 | 16 gas/nonzero byte, 4 gas/zero byte |
| **Total** | **~52,100** | **Cannot be reduced** |

## Comparison with existing schemes

| Scheme | Precompile Gas | Total Tx Gas | Post-quantum |
|---|---|---|---|
| ECDSA (ecrecover) | 3,000 | ~28,000 | No |
| **Falcon-512 (DirectVerify)** | **2,800** | **98,780** | **Yes** |
| BLS12-381 pairing (1 pair) | 43,000 | ~65,000 | No |

Falcon-512 precompile execution is cheaper than ecrecover. The higher total tx gas is due to larger calldata (2 KB vs 128 bytes for ECDSA).
