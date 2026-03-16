# Benchmarks

Measured on Kurtosis devnet (Erigon + Lighthouse, Osaka fork). 16,090 fuzz iterations, 0 failures.

## Contracts

- **FalconVerifierNTT**: Calls 4 generic precompiles (NTT_FW, NTT_INV, VECMULMOD, SHAKE256) and runs the L2 norm check on-chain as a 512-iteration EVM loop.
- **FalconVerifierNTTWithLpNorm**: Same as NTT but replaces the on-chain norm loop with a 5th precompile call (LP_NORM). All math is in precompiles.
- **FalconVerifierDirectVerify**: Calls a single precompile (FALCON_VERIFY) that does everything — SHAKE256, NTT, multiply, inverse NTT, and norm check — in one shot.

All three verify the same Falcon-512 signature and do the same cryptography.

## Transaction cost

| Contract | Total Gas | Overhead | Falcon Verification |
|---|---|---|---|
| NTT | 210,441 | 109,175 | 101,266 |
| NTTWithLpNorm | 98,800 | 97,134 | 1,666 |
| DirectVerify | 98,360 | 95,560 | 2,800 |

- **Total Gas**: charged to sender
- **Overhead**: base tx + calldata + cold STATICCALLs + EVM code (calldatacopy, memory, norm loop)
- **Verification**: gas spent doing actual Falcon-512 math inside precompiles

> **Note on verification gas**: NTTWithLpNorm shows lower verification gas (1,666) than DirectVerify (2,800) because the individual precompile gas prices (NTT_FW=600, SHAKE256=48, VECMULMOD=18, etc.) are stale — set before a caching optimization that made them 5-6x faster. At the 350 Mgas/s target, the sum of parts should be ~3,150 gas. The total transaction gas is nearly identical because the real difference between the two contracts is just the number of cold STATICCALL accesses: NTTWithLpNorm makes 5 calls (5 x 2,600 = 13,000 gas) while DirectVerify makes 1 call (2,600 gas), and this 10,400 gas difference offsets the lower wrongful precompile pricing (but this is just a detail anyways).

