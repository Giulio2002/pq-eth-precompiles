/// @title HawkVerifierDirectBound — Hawk-512 verifier with pk bound at deploy
/// Constructor: pk(1024) as calldata, stored in bytecode.
/// Verify calldata: sig(555) | msg(var)
/// Single STATICCALL to HAWK_VERIFY (0x1d) with pk from code.

object "HawkVerifierDirectBound" {
    code {
        let rtSize := datasize("runtime")
        datacopy(0, dataoffset("runtime"), rtSize)
        calldatacopy(rtSize, 0, 1024)
        return(0, add(rtSize, 1024))
    }
    object "runtime" {
        code {
            let PK_SIZE := 1024
            let cd := calldatasize()

            // Build HAWK_VERIFY input: pk(1024) | sig(555) | msg(var)
            codecopy(0, sub(codesize(), PK_SIZE), PK_SIZE)
            calldatacopy(PK_SIZE, 0, cd)

            let totalLen := add(PK_SIZE, cd)
            if iszero(staticcall(gas(), 0x1d, 0, totalLen, 0, 0x20)) { revert(0,0) }
            return(0, 0x20)
        }
    }
}
