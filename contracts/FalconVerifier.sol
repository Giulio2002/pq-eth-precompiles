// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "./Shake256.sol";

/// @title Falcon-512 signature verifier using NTT precompiles
contract FalconVerifier {
    uint64 constant Q = 12289;
    uint256 constant N = 512;
    uint64 constant PSI = 49;
    uint256 constant COEFF_BYTES = 2;
    uint256 constant NONCE_LEN = 40;
    uint256 constant L2_BOUND = 34034726;
    uint16 constant HASH_THRESHOLD = 61445;

    // Precompile addresses (Osaka/Fusaka)
    address constant NTT_FW_ADDR = address(0x12);
    address constant NTT_INV_ADDR = address(0x13);
    address constant VECMULMOD_ADDR = address(0x14);

    // NTT(h) stored as packed uint16[512] = 32 storage slots
    uint256[32] private nttH;

    constructor(bytes memory pubkey) {
        require(pubkey.length == 897, "bad pubkey length");
        require(uint8(pubkey[0]) == 0x09, "bad pubkey header");

        // Decode 512 x 14-bit coefficients from pubkey (skip header byte)
        bytes memory pkBits = new bytes(pubkey.length - 1);
        for (uint256 i = 0; i < pkBits.length; i++) {
            pkBits[i] = pubkey[i + 1];
        }
        uint16[512] memory h = decodePubkey(pkBits);

        // Compute NTT_FW(h) via precompile
        bytes memory nttInput = encodeNttInput(h);
        (bool ok, bytes memory nttOut) = NTT_FW_ADDR.staticcall(nttInput);
        require(ok && nttOut.length == N * COEFF_BYTES, "NTT_FW failed");

        // Store NTT(h) packed into storage
        uint16[512] memory nttHCoeffs = decodeCoeffs(nttOut);
        for (uint256 slot = 0; slot < 32; slot++) {
            uint256 packed = 0;
            for (uint256 j = 0; j < 16; j++) {
                packed |= uint256(nttHCoeffs[slot * 16 + j]) << (j * 16);
            }
            nttH[slot] = packed;
        }
    }

    /// @notice Verify a Falcon-512 signature
    /// @param message The signed message
    /// @param signature The Falcon-512 compressed signature
    /// @return True if the signature is valid
    function verify(bytes calldata message, bytes calldata signature) external view returns (bool) {
        // Step 1: Decode signature -> (nonce, s2)
        require(signature.length >= 42, "sig too short");
        uint8 header = uint8(signature[0]);
        require(header & 0x0F == 9, "bad sig logn");

        bytes calldata nonce = signature[1:41];
        uint16[512] memory s2 = decodeCompressedSig(signature[41:]);

        // Step 2: hash_to_point(nonce || message) -> c
        uint16[512] memory c = hashToPoint(nonce, message);

        // Step 3: NTT_FW(s2)
        bytes memory nttS2Input = encodeNttInput(s2);
        (bool ok1, bytes memory nttS2Out) = NTT_FW_ADDR.staticcall(nttS2Input);
        require(ok1 && nttS2Out.length == N * COEFF_BYTES, "NTT_FW(s2) failed");

        // Step 4: Load NTT(h) from storage
        bytes memory nttHBytes = loadNttH();

        // Step 5: VECMULMOD(NTT(s2), NTT(h))
        bytes memory mulInput = encodeVecInput(nttS2Out, nttHBytes);
        (bool ok2, bytes memory mulOut) = VECMULMOD_ADDR.staticcall(mulInput);
        require(ok2 && mulOut.length == N * COEFF_BYTES, "VECMULMOD failed");

        // Step 6: NTT_INV(product) -> t
        bytes memory invInput = encodeNttInputRaw(mulOut);
        (bool ok3, bytes memory invOut) = NTT_INV_ADDR.staticcall(invInput);
        require(ok3 && invOut.length == N * COEFF_BYTES, "NTT_INV failed");

        uint16[512] memory t = decodeCoeffs(invOut);

        // Step 7: s1 = c - t mod Q, then check norm
        uint256 normSq = 0;
        for (uint256 i = 0; i < N; i++) {
            // s1[i] = (c[i] - t[i]) mod Q
            uint64 s1i;
            if (c[i] >= t[i]) {
                s1i = uint64(c[i]) - uint64(t[i]);
            } else {
                s1i = Q - (uint64(t[i]) - uint64(c[i]));
            }

            // Center s1[i] for norm: if > Q/2, use Q - s1i
            uint64 centered1 = s1i > Q / 2 ? Q - s1i : s1i;
            normSq += uint256(centered1) * uint256(centered1);

            // Center s2[i] for norm
            uint64 centered2 = uint64(s2[i]) > Q / 2 ? Q - uint64(s2[i]) : uint64(s2[i]);
            normSq += uint256(centered2) * uint256(centered2);
        }

        return normSq <= L2_BOUND;
    }

    // ─── Internal helpers ───

    /// @dev Encode coefficients as NTT precompile calldata
    /// Layout: q_len(32) | psi_len(32) | n(32) | q(q_len) | psi(psi_len) | coeffs(n*cb)
    function encodeNttInput(uint16[512] memory coeffs) private pure returns (bytes memory) {
        bytes memory out = new bytes(96 + 2 + 1 + N * COEFF_BYTES);
        // q_len = 2
        out[31] = 0x02;
        // psi_len = 1
        out[63] = 0x01;
        // n = 512
        out[94] = 0x02;
        out[95] = 0x00;
        // q = 12289 (big-endian, 2 bytes)
        out[96] = 0x30;
        out[97] = 0x01;
        // psi = 49 (1 byte)
        out[98] = 0x31;
        // coefficients (2 bytes each, big-endian)
        for (uint256 i = 0; i < N; i++) {
            out[99 + i * 2] = bytes1(uint8(coeffs[i] >> 8));
            out[99 + i * 2 + 1] = bytes1(uint8(coeffs[i]));
        }
        return out;
    }

    /// @dev Encode raw coefficient bytes as NTT input (for NTT_INV)
    function encodeNttInputRaw(bytes memory coeffBytes) private pure returns (bytes memory) {
        bytes memory out = new bytes(99 + N * COEFF_BYTES);
        out[31] = 0x02;
        out[63] = 0x01;
        out[94] = 0x02;
        out[95] = 0x00;
        out[96] = 0x30;
        out[97] = 0x01;
        out[98] = 0x31;
        for (uint256 i = 0; i < N * COEFF_BYTES; i++) {
            out[99 + i] = coeffBytes[i];
        }
        return out;
    }

    /// @dev Encode two coefficient vectors as VECMULMOD calldata
    /// Layout: q_len(32) | n(32) | q(q_len) | a(n*cb) | b(n*cb)
    function encodeVecInput(bytes memory a, bytes memory b) private pure returns (bytes memory) {
        bytes memory out = new bytes(66 + 2 * N * COEFF_BYTES);
        // q_len = 2
        out[31] = 0x02;
        // n = 512
        out[62] = 0x02;
        out[63] = 0x00;
        // q = 12289
        out[64] = 0x30;
        out[65] = 0x01;
        // vector a
        for (uint256 i = 0; i < N * COEFF_BYTES; i++) {
            out[66 + i] = a[i];
        }
        // vector b
        for (uint256 i = 0; i < N * COEFF_BYTES; i++) {
            out[66 + N * COEFF_BYTES + i] = b[i];
        }
        return out;
    }

    /// @dev Load NTT(h) from storage as raw bytes
    function loadNttH() private view returns (bytes memory out) {
        out = new bytes(N * COEFF_BYTES);
        for (uint256 slot = 0; slot < 32; slot++) {
            uint256 packed = nttH[slot];
            for (uint256 j = 0; j < 16; j++) {
                uint16 val = uint16(packed >> (j * 16));
                uint256 idx = (slot * 16 + j) * 2;
                out[idx] = bytes1(uint8(val >> 8));
                out[idx + 1] = bytes1(uint8(val));
            }
        }
    }

    /// @dev Decode 2-byte big-endian coefficients from precompile output
    function decodeCoeffs(bytes memory data) private pure returns (uint16[512] memory coeffs) {
        for (uint256 i = 0; i < N; i++) {
            coeffs[i] = (uint16(uint8(data[i * 2])) << 8) | uint16(uint8(data[i * 2 + 1]));
        }
    }

    /// @dev Decode 512 x 14-bit coefficients from Falcon public key (MSB-first bitstream)
    function decodePubkey(bytes memory bits) private pure returns (uint16[512] memory h) {
        uint256 bytePos = 0;
        uint256 bitPos = 0;

        for (uint256 i = 0; i < N; i++) {
            uint16 val = 0;
            for (uint256 b = 0; b < 14; b++) {
                val = (val << 1) | uint16((uint8(bits[bytePos]) >> (7 - bitPos)) & 1);
                bitPos++;
                if (bitPos == 8) {
                    bitPos = 0;
                    bytePos++;
                }
            }
            h[i] = val;
        }
    }

    /// @dev Decode compressed Falcon signature to s2 coefficients
    function decodeCompressedSig(bytes calldata comp) private pure returns (uint16[512] memory s2) {
        uint256 bytePos = 0;
        uint256 bitPos = 0;

        for (uint256 i = 0; i < N; i++) {
            // Sign bit
            uint8 sign = (uint8(comp[bytePos]) >> (7 - bitPos)) & 1;
            bitPos++;
            if (bitPos == 8) { bitPos = 0; bytePos++; }

            // Low 7 bits
            uint16 low = 0;
            for (uint256 b = 0; b < 7; b++) {
                low = (low << 1) | uint16((uint8(comp[bytePos]) >> (7 - bitPos)) & 1);
                bitPos++;
                if (bitPos == 8) { bitPos = 0; bytePos++; }
            }

            // Unary high bits (count zeros until 1)
            uint16 high = 0;
            while (true) {
                uint8 bit = (uint8(comp[bytePos]) >> (7 - bitPos)) & 1;
                bitPos++;
                if (bitPos == 8) { bitPos = 0; bytePos++; }
                if (bit == 1) break;
                high++;
            }

            uint16 magnitude = (high << 7) | low;
            if (sign == 1) {
                s2[i] = uint16(Q) - magnitude;
            } else {
                s2[i] = magnitude;
            }
        }
    }

    /// @dev SHAKE256 hash-to-point: H(nonce || message) -> 512 coefficients mod Q
    function hashToPoint(bytes calldata nonce, bytes calldata message) private pure returns (uint16[512] memory c) {
        // Concatenate nonce || message
        bytes memory input = new bytes(nonce.length + message.length);
        for (uint256 i = 0; i < nonce.length; i++) {
            input[i] = nonce[i];
        }
        for (uint256 i = 0; i < message.length; i++) {
            input[nonce.length + i] = message[i];
        }

        // We need ~1092 bytes of SHAKE256 output (rejection sampling)
        // Worst case: ~1100 bytes should be enough for 512 accepted samples
        bytes memory shakeOut = Shake256.hash(input, 1536);

        uint256 count = 0;
        uint256 offset = 0;
        while (count < N) {
            uint16 t = (uint16(uint8(shakeOut[offset])) << 8) | uint16(uint8(shakeOut[offset + 1]));
            offset += 2;
            if (t < HASH_THRESHOLD) {
                c[count] = t % uint16(Q);
                count++;
            }
        }
    }
}
