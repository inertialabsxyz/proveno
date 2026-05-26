// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Public inputs produced by the luai Noir circuit, in declaration order.
/// @dev Field ordering MUST match the `pub` declarations in `noir/src/main.nr`
///      exactly. The `pack` helper relies on this ordering to produce the
///      `bytes32[]` that the generated `HonkVerifier.verify` consumes.
struct PublicInputs {
    uint32  numSteps;
    bytes32 programHash;
    int64   returnValue;
    bytes32 toolResponsesHash;
    bytes32 inputHash;
    bytes32 outputHash;
    bytes32 tlsAttestationHash;
    bytes32 policyHash;
}

// Total wire-format public-input count produced by `bb prove -t evm` for the
// luai Noir circuit. Two scalars (`numSteps`, `returnValue`) plus six 32-byte
// hashes byte-expanded to 32 wire elements each: 1 + 32 + 1 + 6 * 32 = 194.
uint256 constant LUAI_PUBLIC_INPUTS_LENGTH = 194;

/// @notice Pack a `PublicInputs` struct into the wire-format `bytes32[]` that
/// the generated `HonkVerifier.verify(bytes,bytes32[])` consumes.
///
/// @dev Layout (must match the `pub` declaration order in `noir/src/main.nr`):
///        [0]            numSteps           (uint32 widened to bytes32)
///        [1 .. 33)      programHash        bytes (one byte per bytes32)
///        [33]           returnValue        (int64, two's-complement cast to uint64 -> bytes32)
///        [34 .. 66)     toolResponsesHash  bytes
///        [66 .. 98)     inputHash          bytes
///        [98 .. 130)    outputHash         bytes
///        [130 .. 162)   tlsAttestationHash bytes
///        [162 .. 194)   policyHash         bytes
///
/// Reordering or merging fields breaks verification — each [u8; 32] in the Noir
/// circuit is wire-expanded byte-by-byte, so the 32 entries of each hash must
/// appear in big-endian order.
library PublicInputsLib {
    function pack(PublicInputs memory pi)
        internal
        pure
        returns (bytes32[] memory packed)
    {
        packed = new bytes32[](LUAI_PUBLIC_INPUTS_LENGTH);
        uint256 i;

        packed[0] = bytes32(uint256(pi.numSteps));
        i = 1;
        _writeBytes32AsBytes(packed, i, pi.programHash);
        i += 32;
        // int64 -> uint64 wraps via two's complement, matching Noir's `(x as u64) as Field`.
        packed[i] = bytes32(uint256(uint64(pi.returnValue)));
        i += 1;
        _writeBytes32AsBytes(packed, i, pi.toolResponsesHash);
        i += 32;
        _writeBytes32AsBytes(packed, i, pi.inputHash);
        i += 32;
        _writeBytes32AsBytes(packed, i, pi.outputHash);
        i += 32;
        _writeBytes32AsBytes(packed, i, pi.tlsAttestationHash);
        i += 32;
        _writeBytes32AsBytes(packed, i, pi.policyHash);
    }

    /// @dev Expand a 32-byte hash into 32 single-byte `bytes32` entries
    /// starting at `offset`. Big-endian: `hash[0]` lands at `packed[offset]`.
    function _writeBytes32AsBytes(
        bytes32[] memory packed,
        uint256 offset,
        bytes32 hash
    ) private pure {
        for (uint256 j = 0; j < 32; j++) {
            packed[offset + j] = bytes32(uint256(uint8(hash[j])));
        }
    }
}
