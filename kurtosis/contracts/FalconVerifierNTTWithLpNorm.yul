/// @title FalconVerifierNTTWithLpNorm — Falcon-512 verifier using NTT + LpNorm precompiles
/// Uses 0x12 (NTT_FW), 0x13 (NTT_INV), 0x14 (VECMULMOD), 0x16 (SHAKE256), 0x18 (LP_NORM)
/// No on-chain norm loop — delegated to LP_NORM precompile.
/// Calldata: s2(1024, 512×uint16 BE) | ntth(1024, 512×uint16 BE) | salt_msg(var)

object "FalconVerifierNTTWithLpNorm" {
    code {
        datacopy(0, dataoffset("runtime"), datasize("runtime"))
        return(0, datasize("runtime"))
    }
    object "runtime" {
        code {
            let cd := calldatasize()
            let smLen := sub(cd, 0x800)

            // Step 1: SHAKE256(salt_msg) → 1024 bytes hashed at mem[0xc00]
            // (placed at 0xc00 so we can build the norm input contiguously later)
            mstore(0, 1024)
            calldatacopy(0x20, 0x800, smLen)
            if iszero(staticcall(gas(), 0x16, 0, add(0x20, smLen), 0xc00, 0x400)) { revert(0,0) }

            // Step 2: NTT_FW(s2) — header: n(32)|q(32)|psi(32) + coeffs(1024)
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mstore(0x40, 49)
            calldatacopy(0x60, 0, 0x400)
            if iszero(staticcall(gas(), 0x12, 0, 0x460, 0, 0x400)) { revert(0,0) }

            // Step 3: VECMULMOD(NTT(s2), ntth) — header: n(32)|q(32) + a(1024) + b(1024)
            mcopy(0x40, 0, 0x400)       // a = NTT(s2) at mem[0x40]
            mstore(0x00, 512)
            mstore(0x20, 12289)
            calldatacopy(0x440, 0x400, 0x400)  // b = ntth
            if iszero(staticcall(gas(), 0x14, 0, 0x840, 0, 0x400)) { revert(0,0) }

            // Step 4: NTT_INV(product)
            mcopy(0x60, 0, 0x400)       // product at mem[0x60]
            mstore(0x00, 512)
            mstore(0x20, 12289)
            mstore(0x40, 49)
            if iszero(staticcall(gas(), 0x13, 0, 0x460, 0, 0x400)) { revert(0,0) }
            // s1 at mem[0x00..0x3ff]

            // Step 5: Build LP_NORM input contiguously
            // LP_NORM format: q(32) | n(32) | bound(32) | cb(32) | s1(n×cb) | s2(n×cb) | hashed(n×cb)
            // We have: s1 at mem[0x00], hashed at mem[0xc00]
            // Build at mem[0x1000]:
            //   header at 0x1000..0x107f (128 bytes)
            //   s1 at 0x1080..0x147f (1024 bytes)
            //   s2 at 0x1480..0x187f (1024 bytes)
            //   hashed at 0x1880..0x1c7f (1024 bytes)

            mstore(0x1000, 12289)       // q
            mstore(0x1020, 512)         // n
            mstore(0x1040, 34034726)    // bound
            mstore(0x1060, 2)           // cb = 2 bytes per coefficient

            mcopy(0x1080, 0, 0x400)             // s1
            calldatacopy(0x1480, 0, 0x400)      // s2 from calldata
            mcopy(0x1880, 0xc00, 0x400)         // hashed

            // Total: 128 + 3 × 1024 = 3200 bytes
            if iszero(staticcall(gas(), 0x18, 0x1000, 0xc80, 0, 0x20)) { revert(0,0) }

            return(0, 0x20)
        }
    }
}
