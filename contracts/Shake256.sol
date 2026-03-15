// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/// @title SHAKE256 sponge construction with Keccak-f[1600] permutation
/// @dev Rate = 136 bytes (1088 bits), capacity = 64 bytes (512 bits)
library Shake256 {
    uint256 private constant RATE = 136;

    /// @notice Absorb `data` and squeeze `outLen` bytes using SHAKE256
    function hash(bytes memory data, uint256 outLen) internal pure returns (bytes memory out) {
        // State: 25 uint64 words (200 bytes)
        uint64[25] memory state;

        // Absorb phase: XOR data into state in RATE-sized blocks
        uint256 offset = 0;
        while (offset + RATE <= data.length) {
            xorBlock(state, data, offset, RATE);
            keccakF(state);
            offset += RATE;
        }

        // Final partial block + SHAKE256 padding
        uint256 remaining = data.length - offset;
        bytes memory padded = new bytes(RATE);
        for (uint256 i = 0; i < remaining; i++) {
            padded[i] = data[offset + i];
        }
        // SHAKE256 domain separator: 0x1F
        padded[remaining] = 0x1f;
        // Final bit of multi-rate padding
        padded[RATE - 1] |= 0x80;

        xorBlock(state, padded, 0, RATE);
        keccakF(state);

        // Squeeze phase
        out = new bytes(outLen);
        uint256 squeezed = 0;
        while (squeezed < outLen) {
            uint256 chunk = outLen - squeezed;
            if (chunk > RATE) chunk = RATE;
            extractBytes(state, out, squeezed, chunk);
            squeezed += chunk;
            if (squeezed < outLen) {
                keccakF(state);
            }
        }
    }

    /// @dev XOR `len` bytes from `data[offset..]` into the state
    function xorBlock(uint64[25] memory state, bytes memory data, uint256 offset, uint256 len) private pure {
        for (uint256 i = 0; i < len; i += 8) {
            uint256 laneIdx = i / 8;
            if (laneIdx >= 25) break;
            uint64 lane = 0;
            uint256 end = i + 8;
            if (end > len) end = len;
            for (uint256 j = i; j < end; j++) {
                lane |= uint64(uint8(data[offset + j])) << uint64((j - i) * 8);
            }
            state[laneIdx] ^= lane;
        }
    }

    /// @dev Extract bytes from state into output
    function extractBytes(uint64[25] memory state, bytes memory out, uint256 outOffset, uint256 len) private pure {
        for (uint256 i = 0; i < len; i++) {
            uint256 laneIdx = i / 8;
            uint256 byteIdx = i % 8;
            out[outOffset + i] = bytes1(uint8(uint64(state[laneIdx] >> (byteIdx * 8))));
        }
    }

    /// @dev Keccak-f[1600] permutation — 24 rounds
    function keccakF(uint64[25] memory state) private pure {
        // Round constants
        uint64[24] memory RC;
        RC[0]  = 0x0000000000000001; RC[1]  = 0x0000000000008082;
        RC[2]  = 0x800000000000808a; RC[3]  = 0x8000000080008000;
        RC[4]  = 0x000000000000808b; RC[5]  = 0x0000000080000001;
        RC[6]  = 0x8000000080008081; RC[7]  = 0x8000000000008009;
        RC[8]  = 0x000000000000008a; RC[9]  = 0x0000000000000088;
        RC[10] = 0x0000000080008009; RC[11] = 0x000000008000000a;
        RC[12] = 0x000000008000808b; RC[13] = 0x800000000000008b;
        RC[14] = 0x8000000000008089; RC[15] = 0x8000000000008003;
        RC[16] = 0x8000000000008002; RC[17] = 0x8000000000000080;
        RC[18] = 0x000000000000800a; RC[19] = 0x800000008000000a;
        RC[20] = 0x8000000080008081; RC[21] = 0x8000000000008080;
        RC[22] = 0x0000000080000001; RC[23] = 0x8000000080008008;

        for (uint256 round = 0; round < 24; round++) {
            // θ (theta)
            uint64[5] memory C;
            uint64[5] memory D;
            for (uint256 x = 0; x < 5; x++) {
                C[x] = state[x] ^ state[x+5] ^ state[x+10] ^ state[x+15] ^ state[x+20];
            }
            for (uint256 x = 0; x < 5; x++) {
                D[x] = C[(x+4)%5] ^ rot64(C[(x+1)%5], 1);
                for (uint256 y = 0; y < 5; y++) {
                    state[x + 5*y] ^= D[x];
                }
            }

            // ρ (rho) and π (pi)
            uint64[25] memory B;
            B[0]  = state[0];
            B[1]  = rot64(state[6],  44);
            B[2]  = rot64(state[12], 43);
            B[3]  = rot64(state[18], 21);
            B[4]  = rot64(state[24], 14);
            B[5]  = rot64(state[3],  28);
            B[6]  = rot64(state[9],  20);
            B[7]  = rot64(state[10], 3);
            B[8]  = rot64(state[16], 45);
            B[9]  = rot64(state[22], 61);
            B[10] = rot64(state[1],  1);
            B[11] = rot64(state[7],  6);
            B[12] = rot64(state[13], 25);
            B[13] = rot64(state[19], 8);
            B[14] = rot64(state[20], 18);
            B[15] = rot64(state[4],  27);
            B[16] = rot64(state[5],  36);
            B[17] = rot64(state[11], 10);
            B[18] = rot64(state[17], 15);
            B[19] = rot64(state[23], 56);
            B[20] = rot64(state[2],  62);
            B[21] = rot64(state[8],  55);
            B[22] = rot64(state[14], 39);
            B[23] = rot64(state[15], 41);
            B[24] = rot64(state[21], 2);

            // χ (chi)
            for (uint256 y = 0; y < 5; y++) {
                uint256 base = 5 * y;
                for (uint256 x = 0; x < 5; x++) {
                    state[base + x] = B[base + x] ^ ((~B[base + (x+1)%5]) & B[base + (x+2)%5]);
                }
            }

            // ι (iota)
            state[0] ^= RC[round];
        }
    }

    /// @dev 64-bit left rotation
    function rot64(uint64 x, uint64 n) private pure returns (uint64) {
        return (x << n) | (x >> (64 - n));
    }
}
