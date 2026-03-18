/// @title HawkVerifierNTTBound — Hawk-512 verifier
/// Uses REBUILD_S0 (0x1e) for s0 recovery, QNORM (0x1d) for norm check.
///
/// Constructor: q00_half(512) | q01(1024) | hpub(16) = 1552 bytes
/// Verify calldata: s1(1024, 512×i16 LE) | salt(24) | msg(var)
///
/// 4 precompile calls: 2×SHAKE256, 1×REBUILD_S0, 1×QNORM

object "HawkVerifierNTTBound" {
    code {
        let rtSize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rtSize)
        calldatacopy(rtSize, 0, 1552)
        return(0, add(rtSize, 1552))
    }
    object "runtime" {
        code {
            let N        := 512
            let LOGN     := 9
            let SALT_LEN := 24
            let HPUB_LEN := 16
            let APPENDED := 1552
            let HN_BYTES := 512   // n/2 × 2
            let N_BYTES  := 1024  // n × 2
            let H_BYTES  := 64    // n/8

            let cdS1   := 0       // 1024
            let cdSalt := 1024    // 24
            let cdMsg  := 1048    // var

            let codeOff := sub(codesize(), APPENDED)
            let cQ00    := codeOff            // 512
            let cQ01    := add(codeOff, 512)  // 1024
            let cHpub   := add(codeOff, 1536) // 16

            // ── Step 1: M = SHAKE256(msg || hpub) ──
            let msgLen := sub(calldatasize(), cdMsg)
            mstore(0, 64)
            calldatacopy(0x20, cdMsg, msgLen)
            codecopy(add(0x20, msgLen), cHpub, HPUB_LEN)
            if iszero(staticcall(gas(), 0x16, 0, add(add(0x20, msgLen), HPUB_LEN), 0xE000, 0x40)) { revert(0,0) }

            // ── Step 2: h = SHAKE256(M || salt) → 128 bytes = 1024 bits ──
            mstore(0, 128)
            mcopy(0x20, 0xE000, 64)
            calldatacopy(0x60, cdSalt, SALT_LEN)
            if iszero(staticcall(gas(), 0x16, 0, add(0x60, SALT_LEN), 0xF000, 0x80)) { revert(0,0) }
            // h0 = bits 0..511 at 0xF000, h1 = bits 512..1023 at 0xF040

            // ── Step 3: w1[i] = h1[i] - 2*s1[i] as i16 LE at 0x8000 ──
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let bitIdx := add(N, i)
                let h1i := and(shr(mod(bitIdx, 8), byte(0, mload(add(0xF000, div(bitIdx, 8))))), 1)
                let cdOff := add(cdS1, mul(i, 2))
                let lo := byte(0, calldataload(cdOff))
                let hi := byte(0, calldataload(add(cdOff, 1)))
                let s1i := or(lo, shl(8, hi))
                if and(s1i, 0x8000) { s1i := or(s1i, not(0xffff)) }
                let w1i := sub(h1i, mul(2, s1i))
                let off := add(0x8000, mul(i, 2))
                mstore8(off, and(w1i, 0xff))
                mstore8(add(off, 1), and(shr(8, w1i), 0xff))
            }

            // ── Step 4: REBUILD_S0(logn, q00, q01, h0, w1) → s0 at 0x9000 ──
            // Input: logn(32) | q00_half(512) | q01(1024) | h0(64) | w1(1024) = 2656
            mstore(0, LOGN)
            codecopy(0x20, cQ00, HN_BYTES)              // q00_half
            codecopy(add(0x20, HN_BYTES), cQ01, N_BYTES) // q01
            mcopy(add(0x20, add(HN_BYTES, N_BYTES)), 0xF000, H_BYTES) // h0 bits
            mcopy(add(0x20, add(add(HN_BYTES, N_BYTES), H_BYTES)), 0x8000, N_BYTES) // w1
            // Total: 32 + 512 + 1024 + 64 + 1024 = 2656 = 0xA60
            if iszero(staticcall(gas(), 0x1e, 0, 0xA60, 0x9000, N_BYTES)) { revert(0,0) }
            // s0 at 0x9000 (512 × i16 LE)

            // ── Step 5: t0 = h0 - 2*s0 as i16 LE at 0xA000 ──
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let h0i := and(shr(mod(i, 8), byte(0, mload(add(0xF000, div(i, 8))))), 1)
                let s0Off := add(0x9000, mul(i, 2))
                let s0lo := byte(0, mload(s0Off))
                let s0hi := byte(0, mload(add(s0Off, 1)))
                let s0i := or(s0lo, shl(8, s0hi))
                if and(s0i, 0x8000) { s0i := or(s0i, not(0xffff)) }
                let t0i := sub(h0i, mul(2, s0i))
                let off := add(0xA000, mul(i, 2))
                mstore8(off, and(t0i, 0xff))
                mstore8(add(off, 1), and(shr(8, t0i), 0xff))
            }

            // ── Step 6: sym-break check on w1 ──
            // First nonzero of t1 (= w1) must be positive
            let symOk := 0
            for { let i := 0 } lt(i, N) { i := add(i, 1) } {
                let off := add(0x8000, mul(i, 2))
                let lo := byte(0, mload(off))
                let hi := byte(0, mload(add(off, 1)))
                let v := or(lo, shl(8, hi))
                if and(v, 0x8000) { v := or(v, not(0xffff)) }
                if iszero(iszero(v)) {
                    symOk := sgt(v, 0)
                    i := N
                }
            }
            if iszero(symOk) {
                mstore(0, 0)
                return(0, 32)
            }

            // ── Step 7: QNORM(logn, bound, q00, q01, t0, t1) ──
            // Input: logn(32) | bound(32) | q00_half(512) | q01(1024) | t0(1024) | t1(1024) = 3648
            mstore(0, LOGN)
            mstore(0x20, 8317)  // max_tnorm for Hawk-512
            codecopy(0x40, cQ00, HN_BYTES)
            codecopy(add(0x40, HN_BYTES), cQ01, N_BYTES)
            mcopy(add(0x40, add(HN_BYTES, N_BYTES)), 0xA000, N_BYTES)  // t0
            mcopy(add(0x40, add(add(HN_BYTES, N_BYTES), N_BYTES)), 0x8000, N_BYTES)  // t1 = w1
            // Total: 64 + 512 + 1024 + 1024 + 1024 = 3648 = 0xE40
            if iszero(staticcall(gas(), 0x1d, 0, 0xE40, 0, 0x20)) { revert(0,0) }

            return(0, 0x20)
        }
    }
}
