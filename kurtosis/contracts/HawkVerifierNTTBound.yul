/// @title HawkVerifierNTTBound — Hawk-512 verifier using NTT precompiles
/// Uses a 63-bit NTT prime (4611686018427448321) so mod q never triggers —
/// effectively exact integer polynomial arithmetic via existing precompiles.
///
/// Constructor: q00_ntt(4096) | q01_ntt(4096) | q00_inv_ntt(4096) | q11_ntt(4096) | hpub(16) = 16400 bytes
///   All NTT data precomputed off-chain under q_large with psi_large.
///
/// Verify calldata: s1(1024, 512×int16 LE) | salt(24) | msg(var)
///   s1 pre-decoded from Golomb-Rice by caller.
///
/// 12 precompile calls:
///   2 × SHAKE256, 2 × NTT_FW, 4 × NTT_INV, 4 × VECMULMOD
///
/// UNTESTED — no Hawk signing library available for generating test vectors.

object "HawkVerifierNTTBound" {
    code {
        let rtSize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rtSize)
        // Append: q00_ntt(4096) + q01_ntt(4096) + q00_inv_ntt(4096) + q11_ntt(4096) + hpub(16) = 16400
        calldatacopy(rtSize, 0, 16400)
        return(0, add(rtSize, 16400))
    }
    object "runtime" {
        code {
            // ── Constants ──
            // q_large = 4611686018427448321 (63-bit NTT prime, q ≡ 1 mod 1024)
            // psi_large = 1888723220603080298 (primitive 1024th root of unity)
            // cb = 8 (bytes per coefficient under q_large)
            // For Hawk-512: n=512, sigma_verify=1.425
            // Bound: 4 * sigma_verify^2 * 2n = 4 * 2.030625 * 1024 ≈ 8317
            let N           := 512
            let CB          := 8
            let POLYSZ      := 4096    // N * CB
            let SALT_BYTES  := 24
            let HPUB_BYTES  := 16
            let APPENDED    := 16400   // 4*POLYSZ + HPUB
            let Q_LO        := 0x3ffffffffffffc01  // low 64 bits of q_large
            // q_large as 32-byte word: 0x00..003ffffffffffffc01
            // psi_large as 32-byte word: 0x00..001a36e2eb1c432c8a

            // Calldata offsets
            let cdS1     := 0              // 512 × 2 bytes = 1024
            let cdSalt   := 1024           // 24 bytes
            let cdMsg    := 1048           // variable

            // Bytecode offsets for precomputed data
            let codeOff  := sub(codesize(), APPENDED)
            let cQ00ntt  := codeOff                        // 4096
            let cQ01ntt  := add(codeOff, POLYSZ)           // 4096
            let cQ00inv  := add(codeOff, mul(2, POLYSZ))   // 4096
            let cQ11ntt  := add(codeOff, mul(3, POLYSZ))   // 4096
            let cHpub    := add(codeOff, mul(4, POLYSZ))   // 16

            // Memory layout (all polynomials are 4096 bytes under q_large)
            // 0x0000 : precompile I/O scratch (up to ~16KB)
            // 0x8000 : w1 standard domain (4096)
            // 0x9000 : w1_ntt (4096)
            // 0xA000 : w0 standard domain (4096)
            // 0xB000 : w0_ntt (4096)
            // 0xC000 : temp polynomial (4096)
            // 0xD000 : mu hash (64 bytes)
            let mW1     := 0x8000
            let mW1ntt  := 0x9000
            let mW0     := 0xA000
            let mW0ntt  := 0xB000
            let mTemp   := 0xC000
            let mMu     := 0xD000

            // Helper: write q_large as 32-byte BE word at memory offset
            function storeQ(offset) {
                mstore(offset, 0)
                mstore(add(offset, 24), 0x3ffffffffffffc01)
            }
            // Helper: write psi_large as 32-byte BE word
            function storePsi(offset) {
                mstore(offset, 0)
                mstore(add(offset, 24), 0x1a36e2eb1c432c8a)
            }

            // ── Step 1: Hash M = SHAKE256(msg || hpub) ──
            let msgLen := sub(calldatasize(), cdMsg)
            mstore(0, 64)  // output_len
            calldatacopy(0x20, cdMsg, msgLen)
            codecopy(add(0x20, msgLen), cHpub, HPUB_BYTES)
            if iszero(staticcall(gas(), 0x16, 0, add(add(0x20, msgLen), HPUB_BYTES), mMu, 0x40)) { revert(0,0) }

            // ── Step 2: h = SHAKE256(M || salt) → 1024 bits = 128 bytes ──
            mstore(0, 128)  // output_len = 128 bytes = 1024 bits
            mcopy(0x20, mMu, 64)
            calldatacopy(0x60, cdSalt, SALT_BYTES)
            if iszero(staticcall(gas(), 0x16, 0, add(0x60, SALT_BYTES), 0x7000, 0x80)) { revert(0,0) }
            // h bits at mem[0x7000..0x707f]
            // h0 = first 512 bits, h1 = next 512 bits

            // ── Step 3: Compute w1[i] = h1[i] - 2*s1[i] ──
            // h1 is binary (0 or 1 from SHAKE output bits 512..1023)
            // s1 is signed 16-bit LE from calldata
            // w1 stored as 8-byte BE coefficients (for NTT with q_large)
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                // Extract h1[i] bit
                let bitIdx := add(N, i)  // bits 512..1023
                let byteOff := div(bitIdx, 8)
                let bitOff := mod(bitIdx, 8)
                let h1i := and(shr(bitOff, byte(0, mload(add(0x7000, byteOff)))), 1)

                // Read s1[i] as signed 16-bit LE from calldata
                let cdOff := add(cdS1, mul(i, 2))
                let lo := byte(0, calldataload(cdOff))
                let hi := byte(0, calldataload(add(cdOff, 1)))
                let s1i := or(lo, shl(8, hi))
                // Sign extend 16-bit
                if and(s1i, 0x8000) { s1i := or(s1i, not(0xffff)) }

                // w1[i] = h1[i] - 2*s1[i]
                let w1i := sub(h1i, mul(2, s1i))

                // Store as 8-byte BE (centered mod q_large for NTT)
                // Since w1[i] is small (~12 bits), just handle sign
                let w1mod := w1i
                if slt(w1i, 0) {
                    w1mod := add(Q_LO, w1i)
                }
                mstore(add(mW1, mul(i, CB)), w1mod)
            }

            // ── Step 4: NTT_FW(w1) → w1_ntt ──
            mstore(0, N)
            storeQ(0x20)
            storePsi(0x40)
            mcopy(0x60, mW1, POLYSZ)
            // Input: 96 + 4096 = 4192 = 0x1060
            if iszero(staticcall(gas(), 0x12, 0, 0x1060, mW1ntt, POLYSZ)) { revert(0,0) }

            // ── Step 5: ratio = q01*w1/q00 via NTT pointwise ──
            // 5a: VECMULMOD(q01_ntt, w1_ntt) → temp_ntt
            mstore(0, N)
            storeQ(0x20)
            codecopy(0x40, cQ01ntt, POLYSZ)            // q01_ntt from code
            mcopy(add(0x40, POLYSZ), mW1ntt, POLYSZ)   // w1_ntt from memory
            // Input: 64 + 4096 + 4096 = 8256 = 0x2040
            if iszero(staticcall(gas(), 0x14, 0, 0x2040, mTemp, POLYSZ)) { revert(0,0) }

            // 5b: VECMULMOD(temp_ntt, q00_inv_ntt) → ratio_ntt
            mstore(0, N)
            storeQ(0x20)
            mcopy(0x40, mTemp, POLYSZ)
            codecopy(add(0x40, POLYSZ), cQ00inv, POLYSZ)
            if iszero(staticcall(gas(), 0x14, 0, 0x2040, mTemp, POLYSZ)) { revert(0,0) }

            // 5c: NTT_INV(ratio_ntt) → ratio in standard domain
            mstore(0, N)
            storeQ(0x20)
            storePsi(0x40)
            mcopy(0x60, mTemp, POLYSZ)
            if iszero(staticcall(gas(), 0x13, 0, 0x1060, mTemp, POLYSZ)) { revert(0,0) }
            // ratio at mTemp, coefficients mod q_large (centered: if > q/2, it's negative)

            // ── Step 6: s0[i] = round((h0[i] + ratio[i]) / 2), w0[i] = h0[i] - 2*s0[i] ──
            let halfQ := shr(1, Q_LO)
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                // h0[i] bit
                let byteOff := div(i, 8)
                let bitOff := mod(i, 8)
                let h0i := and(shr(bitOff, byte(0, mload(add(0x7000, byteOff)))), 1)

                // ratio[i] centered
                let ri := mload(add(mTemp, mul(i, CB)))
                let ri_signed := ri
                if gt(ri, halfQ) { ri_signed := sub(ri, Q_LO) }

                // s0 = floor((h0 + ratio) / 2)
                let num := add(h0i, ri_signed)
                let s0i := sdiv(num, 2)
                // For negative: floor division
                if and(slt(num, 0), mod(num, 2)) { s0i := sub(s0i, 1) }

                // w0[i] = h0[i] - 2*s0[i]
                let w0i := sub(h0i, mul(2, s0i))
                let w0mod := w0i
                if slt(w0i, 0) { w0mod := add(Q_LO, w0i) }
                mstore(add(mW0, mul(i, CB)), w0mod)
            }

            // ── Step 7: NTT_FW(w0) ──
            mstore(0, N)
            storeQ(0x20)
            storePsi(0x40)
            mcopy(0x60, mW0, POLYSZ)
            if iszero(staticcall(gas(), 0x12, 0, 0x1060, mW0ntt, POLYSZ)) { revert(0,0) }

            // ── Step 8: Q-norm computation ──
            // term1 = <w0, q00*w0>: VECMULMOD(q00_ntt, w0_ntt) → NTT_INV → dot with w0
            mstore(0, N)
            storeQ(0x20)
            codecopy(0x40, cQ00ntt, POLYSZ)
            mcopy(add(0x40, POLYSZ), mW0ntt, POLYSZ)
            if iszero(staticcall(gas(), 0x14, 0, 0x2040, mTemp, POLYSZ)) { revert(0,0) }
            mstore(0, N)
            storeQ(0x20)
            storePsi(0x40)
            mcopy(0x60, mTemp, POLYSZ)
            if iszero(staticcall(gas(), 0x13, 0, 0x1060, mTemp, POLYSZ)) { revert(0,0) }
            // q00*w0 at mTemp. Dot product with w0:
            let term1 := 0
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let a := mload(add(mW0, mul(i, CB)))
                let b := mload(add(mTemp, mul(i, CB)))
                if gt(a, halfQ) { a := sub(a, Q_LO) }
                if gt(b, halfQ) { b := sub(b, Q_LO) }
                term1 := add(term1, mul(a, b))
            }

            // term2 = 2 * <w0, q01*w1>: already have q01*w1 from step 5a... no, that was in NTT domain.
            // Redo: VECMULMOD(q01_ntt, w1_ntt) → NTT_INV → dot with w0
            mstore(0, N)
            storeQ(0x20)
            codecopy(0x40, cQ01ntt, POLYSZ)
            mcopy(add(0x40, POLYSZ), mW1ntt, POLYSZ)
            if iszero(staticcall(gas(), 0x14, 0, 0x2040, mTemp, POLYSZ)) { revert(0,0) }
            mstore(0, N)
            storeQ(0x20)
            storePsi(0x40)
            mcopy(0x60, mTemp, POLYSZ)
            if iszero(staticcall(gas(), 0x13, 0, 0x1060, mTemp, POLYSZ)) { revert(0,0) }
            let term2 := 0
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let a := mload(add(mW0, mul(i, CB)))
                let b := mload(add(mTemp, mul(i, CB)))
                if gt(a, halfQ) { a := sub(a, Q_LO) }
                if gt(b, halfQ) { b := sub(b, Q_LO) }
                term2 := add(term2, mul(a, b))
            }
            term2 := mul(2, term2)

            // term3 = <w1, q11*w1>: VECMULMOD(q11_ntt, w1_ntt) → NTT_INV → dot with w1
            mstore(0, N)
            storeQ(0x20)
            codecopy(0x40, cQ11ntt, POLYSZ)
            mcopy(add(0x40, POLYSZ), mW1ntt, POLYSZ)
            if iszero(staticcall(gas(), 0x14, 0, 0x2040, mTemp, POLYSZ)) { revert(0,0) }
            mstore(0, N)
            storeQ(0x20)
            storePsi(0x40)
            mcopy(0x60, mTemp, POLYSZ)
            if iszero(staticcall(gas(), 0x13, 0, 0x1060, mTemp, POLYSZ)) { revert(0,0) }
            let term3 := 0
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let a := mload(add(mW1, mul(i, CB)))
                let b := mload(add(mTemp, mul(i, CB)))
                if gt(a, halfQ) { a := sub(a, Q_LO) }
                if gt(b, halfQ) { b := sub(b, Q_LO) }
                term3 := add(term3, mul(a, b))
            }

            // ||w||²_Q * n = term1 + term2 + term3
            let qnorm_times_n := add(add(term1, term2), term3)

            // Check: ||w||²_Q ≤ 4 * sigma_verify² * 2n
            // i.e. qnorm_times_n ≤ 4 * 1.425² * 2 * 512 * 512
            // = 4 * 2.030625 * 524288 = 4,257,218 (approx)
            // Use generous bound: 4260000
            let bound := 4260000

            // sym-break: first nonzero of w1 should be positive
            let symOk := 0
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let v := mload(add(mW1, mul(i, CB)))
                if gt(v, halfQ) { v := sub(v, Q_LO) }
                if iszero(iszero(v)) {
                    symOk := sgt(v, 0)
                    i := N  // break
                }
            }

            if and(symOk, and(sgt(qnorm_times_n, 0), iszero(gt(qnorm_times_n, bound)))) {
                mstore(0, 1)
                return(0, 32)
            }

            mstore(0, 0)
            return(0, 32)
        }
    }
}
